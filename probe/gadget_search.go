package probe

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	rawhttp "github.com/projectdiscovery/rawhttp/client"
	"github.com/skyrimdlyalohov-droid/omnislash"
)

// DefaultGadgetHeaders is the built-in candidate set for group testing. These
// are ordinary proxy/cache headers, not scanner signatures: their values are
// fresh cryptographic canaries generated for each run.
var DefaultGadgetHeaders = []string{
	"X-Forwarded-Host",
	"X-Forwarded-Proto",
	"X-Forwarded-Server",
	"X-Forwarded-For",
	"X-Forwarded-Port",
	"X-Forwarded-Path",
	"X-Real-IP",
	"X-Client-IP",
	"X-Original-URL",
	"X-Rewrite-URL",
	"X-Host",
	"Forwarded",
	"Via",
	"Referer",
	"Origin",
	"Accept-Language",
}

const (
	defaultGadgetBatchSize   = 16
	defaultGadgetMaxRequests = 64
	defaultGadgetMaxAttempts = 2
	defaultGadgetThreshold   = 0.15
)

// canaryReader is a field on GadgetProbe (gadgets.go); tests replace it with a
// deterministic reader. Production always uses crypto/rand.
func (p *GadgetProbe) canary() (string, error) {
	reader := p.canaryReader
	if reader == nil {
		reader = rand.Reader
	}
	var raw [12]byte
	if _, err := io.ReadFull(reader, raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func (p *GadgetProbe) batchMode() bool { return len(p.Headers) > 0 }

func (p *GadgetProbe) batchSize() int {
	if p.BatchSize <= 0 {
		return defaultGadgetBatchSize
	}
	if p.BatchSize > 32 {
		return 32
	}
	return p.BatchSize
}

func (p *GadgetProbe) requestBudget() int {
	if p.MaxRequests <= 0 {
		return defaultGadgetMaxRequests
	}
	return p.MaxRequests
}

func (p *GadgetProbe) attempts() int {
	if p.MaxAttempts <= 0 {
		return defaultGadgetMaxAttempts
	}
	return p.MaxAttempts
}

func (p *GadgetProbe) structuralThreshold() float64 {
	if p.StructuralThreshold > 0 {
		return p.StructuralThreshold
	}
	return defaultGadgetThreshold
}

func (p *GadgetProbe) headerCandidates() ([]string, error) {
	source := p.Headers
	if len(source) == 0 {
		source = DefaultGadgetHeaders
	}
	seen := make(map[string]struct{}, len(source))
	out := make([]string, 0, len(source))
	for _, header := range source {
		header = strings.TrimSpace(header)
		if header == "" || strings.ContainsAny(header, " \t\r\n:") {
			return nil, fmt.Errorf("probe: invalid gadget header %q", header)
		}
		key := strings.ToLower(header)
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, header)
	}
	return out, nil
}

// fixedConnSource lets Execute (one already dialed conn) use the same search
// implementation as ExecuteMulti. The probe never closes that conn: Runner
// owns it.
type fixedConnSource struct{ conn net.Conn }

func (s *fixedConnSource) Dial(context.Context) (net.Conn, error) {
	if s == nil || s.conn == nil {
		return nil, errors.New("probe: fixed connection source has no conn")
	}
	return s.conn, nil
}

// ExecuteMulti runs divide-and-conquer group testing. Every socket comes from
// the ConnSource, so one experiment still maps to one pinned exit IP.
func (p *GadgetProbe) ExecuteMulti(ctx context.Context, target Target, source ConnSource) (*Result, error) {
	if source == nil {
		return nil, errors.New("probe: nil conn source")
	}
	if p.batchMode() {
		return p.search(ctx, target, source, true)
	}
	conn, err := source.Dial(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return p.executeSingle(ctx, target, conn)
}

// search is the group-testing core. A batch that changes the response is
// bisected until one header remains; negative batches are discarded. The
// Result keeps every wire write in Exchanges and every parsed response in
// Responses, so a finding can be exported verbatim through /api/caido/push.
func (p *GadgetProbe) search(ctx context.Context, target Target, source ConnSource, ownsConns bool) (*Result, error) {
	candidates, err := p.headerCandidates()
	if err != nil {
		return nil, err
	}
	conn0, err := source.Dial(ctx)
	if err != nil {
		return nil, err
	}
	e := newExec(ctx, p.Name(), target, conn0, p.Timeout, p.MaxHeader, p.MaxBody)
	if ownsConns {
		_ = conn0.Close() // attribution only; the real exchanges get fresh conns
	}

	used := 0
	baseline, err := p.exchange(ctx, target, source, e, ownsConns, p.baseHeaders(target, !ownsConns))
	used++
	if err != nil && baseline == nil {
		return e.finish(), err
	}
	if baseline == nil {
		return e.finish(), errors.New("probe: gadget search got no baseline response")
	}
	blocks := &gadgetBlockState{}
	if reason := blocks.observe(baseline); reason != "" {
		e.addFinding(Finding{Kind: "gadget_stop", Confidence: ConfidenceHigh, Detail: reason, Response: baseline.Seq})
		return e.finish(), nil
	}

	stack := [][]string{candidates}
	found := false
	for len(stack) > 0 && ctx.Err() == nil && used < p.requestBudget() {
		group := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if len(group) == 0 {
			continue
		}
		if len(group) > p.batchSize() {
			left, right := splitHeaderGroup(group)
			stack = append(stack, right, left)
			continue
		}

		resp, changed, detail, sendErr := p.testGroup(ctx, target, source, e, ownsConns, baseline, group)
		used++
		if sendErr != nil {
			e.addFinding(Finding{Kind: "gadget_request_error", Confidence: ConfidenceLow, Detail: sendErr.Error()})
			continue
		}
		if resp == nil {
			continue
		}
		if reason := blocks.observe(resp); reason != "" {
			e.addFinding(Finding{Kind: "gadget_stop", Confidence: ConfidenceHigh, Detail: reason, Response: resp.Seq})
			return e.finish(), nil
		}
		if !changed {
			continue
		}
		if len(group) == 1 {
			e.addFinding(Finding{
				Kind:       "unkeyed_header",
				Confidence: ConfidenceHigh,
				Detail:     fmt.Sprintf("header %s changed the response: %s", group[0], detail),
				Response:   resp.Seq,
			})
			found = true
			break
		}
		left, right := splitHeaderGroup(group)
		stack = append(stack, right, left)
	}

	if !found && used >= p.requestBudget() {
		e.addFinding(Finding{Kind: "gadget_batch_unresolved", Confidence: ConfidenceLow,
			Detail: fmt.Sprintf("request budget %d exhausted before one header remained", p.requestBudget())})
	}
	if len(e.res.Findings) == 0 {
		e.addFinding(Finding{Kind: "gadget_no_signal", Confidence: ConfidenceLow, Detail: "no candidate header changed the response"})
	}
	return e.finish(), nil
}

// baseHeaders contains no scanner-specific User-Agent: only the Host and the
// connection policy needed to frame one response per request.
func (p *GadgetProbe) baseHeaders(target Target, reuse bool) []rawhttp.Header {
	connection := "close"
	if reuse {
		// Execute got one conn from the caller and must reuse it for every
		// group; ExecuteMulti owns fresh conns and keeps the one-shot framing.
		connection = "keep-alive"
	}
	return []rawhttp.Header{
		{Key: "Host", Value: target.HostHeader()},
		{Key: "Connection", Value: connection},
	}
}

func (p *GadgetProbe) requestHeaders(target Target, names []string, reuse bool) ([]rawhttp.Header, []string, error) {
	headers := p.baseHeaders(target, reuse)
	canaries := make([]string, 0, len(names))
	for _, name := range names {
		canary, err := p.canary()
		if err != nil {
			return nil, nil, fmt.Errorf("probe: canary: %w", err)
		}
		headers = append(headers, rawhttp.Header{Key: name, Value: canary})
		canaries = append(canaries, canary)
	}
	return headers, canaries, nil
}

func (p *GadgetProbe) testGroup(ctx context.Context, target Target, source ConnSource, e *exec, ownsConns bool, baseline *Response, names []string) (*Response, bool, string, error) {
	var lastErr error
	for attempt := 0; attempt < p.attempts(); attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, false, "", err
		}
		headers, canaries, err := p.requestHeaders(target, names, !ownsConns)
		if err != nil {
			return nil, false, "", err
		}
		resp, err := p.exchange(ctx, target, source, e, ownsConns, headers)
		if err != nil && resp == nil {
			lastErr = err
			continue
		}
		if resp == nil {
			continue
		}
		changed, detail := p.responseChanged(baseline, resp, canaries)
		return resp, changed, detail, nil
	}
	return nil, false, "", lastErr
}

func (p *GadgetProbe) exchange(ctx context.Context, target Target, source ConnSource, e *exec, ownsConns bool, headers []rawhttp.Header) (*Response, error) {
	conn, err := source.Dial(ctx)
	if err != nil {
		return nil, err
	}
	if ownsConns {
		defer conn.Close()
	}
	e.attach(conn)
	payload, err := render(requestSpec{Method: "GET", Path: target.RequestPath(), Headers: headers})
	if err != nil {
		return nil, fmt.Errorf("probe: render gadget batch: %w", err)
	}
	if err := e.write(payload); err != nil {
		return nil, err
	}
	resp, err := e.read()
	if err != nil && resp == nil {
		return nil, err
	}
	return resp, nil
}

// responseChanged looks for an unkeyed-header effect: status, Location,
// canary reflection, or a real structural shift. Dynamic values alone are
// filtered by the local skeleton comparator.
func (p *GadgetProbe) responseChanged(baseline, resp *Response, canaries []string) (bool, string) {
	if baseline == nil || resp == nil {
		return false, ""
	}
	if resp.Status != baseline.Status {
		return true, fmt.Sprintf("status %d -> %d", baseline.Status, resp.Status)
	}
	baseLocation := baseline.headerValues("Location")
	currentLocation := resp.headerValues("Location")
	if len(baseLocation) != len(currentLocation) {
		return true, fmt.Sprintf("Location headers %d -> %d", len(baseLocation), len(currentLocation))
	}
	for i := range baseLocation {
		if baseLocation[i] != currentLocation[i] {
			return true, fmt.Sprintf("Location %q -> %q", baseLocation[i], currentLocation[i])
		}
	}
	for _, header := range resp.Headers {
		for _, canary := range canaries {
			if strings.Contains(header.Key, canary) || strings.Contains(header.Value, canary) {
				return true, "canary reflected in response headers"
			}
		}
	}
	body := resp.Body + resp.Raw
	for _, canary := range canaries {
		if strings.Contains(body, canary) {
			return true, "canary reflected in response body"
		}
	}
	contentType := ""
	if values := resp.headerValues("Content-Type"); len(values) > 0 {
		contentType = values[0]
	}
	distance := omnislash.StructuralShift([]byte(baseline.Body), []byte(resp.Body), contentType)
	if distance > p.structuralThreshold() {
		return true, fmt.Sprintf("structural shift %.3f", distance)
	}
	return false, ""
}

// gadgetBlockState enforces the session STOP rules. A single 429/503 stops
// immediately; 403 needs a repeat to distinguish a block from a policy echo.
type gadgetBlockState struct{ forbidden int }

func (s *gadgetBlockState) observe(resp *Response) string {
	if resp == nil {
		return ""
	}
	switch resp.Status {
	case 429:
		return "STOP: rate limited (429)"
	case 503:
		return "STOP: service unavailable (503)"
	case 403:
		s.forbidden++
		if s.forbidden >= 2 {
			return "STOP: repeated 403"
		}
	default:
		s.forbidden = 0
	}
	return ""
}

func splitHeaderGroup(group []string) ([]string, []string) {
	half := len(group) / 2
	left := append([]string(nil), group[:half]...)
	right := append([]string(nil), group[half:]...)
	return left, right
}

var _ MultiConnProbe = (*GadgetProbe)(nil)
