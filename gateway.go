package omnislash

import (
	"bufio"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Gateway is a local HTTP forward proxy. Plain HTTP requests are forwarded
// request-by-request so the gateway can feed target status codes into the
// safety breaker; HTTPS and raw TCP use CONNECT, which stays byte-transparent.
// Every new upstream connection is selected by the pool, so tools that cannot
// be rebuilt in Go can still use proxy rotation.
type Gateway struct {
	listener net.Listener
	dialer   *Dialer
	token    string
	log      *slog.Logger

	wg    sync.WaitGroup
	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

// NewGateway starts listening on addr ("127.0.0.1:0" picks a free port).
func NewGateway(addr string, dialer *Dialer, token string, logger *slog.Logger) (*Gateway, error) {
	if logger == nil {
		logger = dialer.log
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &Gateway{
		listener: ln,
		dialer:   dialer,
		token:    token,
		log:      logger,
		conns:    make(map[net.Conn]struct{}),
	}, nil
}

// Addr returns the actual listening address.
func (g *Gateway) Addr() net.Addr { return g.listener.Addr() }

// Serve accepts connections until ctx is canceled or the listener fails.
func (g *Gateway) Serve(ctx context.Context) error {
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = g.listener.Close()
			g.closeAll()
		case <-done:
		}
	}()
	for {
		conn, err := g.listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				break
			}
			g.closeAll()
			g.wg.Wait()
			return err
		}
		g.track(conn)
		g.wg.Add(1)
		go func() {
			defer g.wg.Done()
			defer g.untrack(conn)
			g.handle(ctx, conn)
		}()
	}
	g.wg.Wait()
	return nil
}

// Close stops the listener and all active tunnels.
func (g *Gateway) Close() error {
	err := g.listener.Close()
	g.closeAll()
	return err
}

func (g *Gateway) track(conn net.Conn) {
	g.mu.Lock()
	g.conns[conn] = struct{}{}
	g.mu.Unlock()
}

func (g *Gateway) untrack(conn net.Conn) {
	g.mu.Lock()
	delete(g.conns, conn)
	g.mu.Unlock()
	_ = conn.Close()
}

func (g *Gateway) closeAll() {
	g.mu.Lock()
	conns := make([]net.Conn, 0, len(g.conns))
	for conn := range g.conns {
		conns = append(conns, conn)
	}
	g.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

func (g *Gateway) handle(ctx context.Context, conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		writeHTTPError(conn, http.StatusBadRequest, "Bad Request", "malformed proxy request")
		return
	}
	if !g.authorized(req.Header.Get("Proxy-Authorization")) {
		writeProxyAuthRequired(conn)
		return
	}
	if req.Method == http.MethodConnect {
		g.handleConnect(ctx, conn, br, req)
		return
	}
	g.handleHTTP(ctx, conn, req)
}

// handleConnect establishes a byte-transparent tunnel. The gateway cannot see
// HTTP status codes inside TLS, so the breaker only reacts to CONNECT failures
// on this path. Use the plain-HTTP path when status-level safety is required.
func (g *Gateway) handleConnect(ctx context.Context, conn net.Conn, br *bufio.Reader, req *http.Request) {
	target := req.Host
	if target == "" {
		target = req.URL.Host
	}
	if target == "" {
		target = req.RequestURI
	}
	if target == "" {
		writeHTTPError(conn, http.StatusBadRequest, "Bad Request", "CONNECT target is missing")
		return
	}
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(strings.Trim(target, "[]"), "443")
	}

	if df := g.dialer.pool.Deception(); df != nil && df.Enabled() {
		host, _, _ := net.SplitHostPort(target)
		if _, block := df.ShouldBlock(host, "/"); block {
			g.audit(AuditEvent{Kind: "connect", Target: target, Reason: "deception_target_banned"})
			writeHTTPError(conn, http.StatusForbidden, "Forbidden", "target banned by deception filter")
			return
		}
	}

	// Reject out-of-scope targets with a distinct status. Otherwise a policy
	// violation and a dead proxy both surface as 502 and are impossible to tell
	// apart from the client side. The dialer checks again; this is not a
	// substitute for that check.
	if _, err := g.dialer.pool.scope.CheckTarget(ctx, target); err != nil {
		g.log.Debug("gateway target rejected by scope", "target", target, "error", err)
		g.audit(AuditEvent{Kind: "connect", Target: target, Reason: "scope_rejected"})
		writeHTTPError(conn, http.StatusForbidden, "Forbidden", "target is outside the configured scope")
		return
	}

	ctx, waitErr := g.dialer.pool.WaitGlobal(ctx)
	if waitErr != nil {
		g.audit(AuditEvent{Kind: "connect", Target: target, Reason: "rate_limited"})
		writeHTTPError(conn, http.StatusTooManyRequests, "Too Many Requests", "global rate limit exceeded")
		return
	}
	if err := g.dialer.pool.Allow(); err != nil {
		g.log.Warn("gateway refused by safety circuit", "target", target, "error", err)
		g.audit(AuditEvent{Kind: "connect", Target: target, Reason: "circuit_open"})
		writeHTTPError(conn, http.StatusServiceUnavailable, "Service Unavailable", "safety circuit is open")
		return
	}

	var (
		upstream net.Conn
		err      error
	)
	pinHeader := strings.TrimSpace(g.dialer.pool.cfg.Gateway.ProxyPinHeader)
	if pinHeader != "" {
		if label := strings.TrimSpace(req.Header.Get(pinHeader)); label != "" {
			if pr, ok := g.dialer.pool.ProxyByLabel(label); ok {
				upstream, err = g.dialer.dialProxy(ctx, pr, target)
			} else {
				err = fmt.Errorf("pinned proxy %q not found", label)
			}
		}
	}
	if upstream == nil && err == nil {
		upstream, err = g.dialer.DialContext(ctx, "tcp", target)
	}
	if err != nil {
		g.log.Debug("gateway dial failed", "target", target, "error", err)
		g.audit(AuditEvent{Kind: "connect", Target: target, Reason: "dial_error"})
		writeHTTPError(conn, http.StatusBadGateway, "Bad Gateway", "upstream connection failed")
		return
	}
	defer upstream.Close()

	if pr, ok := ProxyOf(upstream); ok {
		g.audit(AuditEvent{Kind: "connect", Target: target, Status: http.StatusOK, Proxy: pr.Label()})
	} else {
		g.audit(AuditEvent{Kind: "connect", Target: target, Status: http.StatusOK, Reason: "direct"})
	}

	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	clientConn := &bufferedConn{Conn: conn, r: br}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstream, clientConn)
		closeWrite(upstream)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(clientConn, upstream)
		closeWrite(clientConn)
	}()
	wg.Wait()
}

// handleHTTP forwards one absolute-form HTTP request. Unlike CONNECT, the
// response status is visible here, so block statuses are recorded by the
// safety breaker and the next request is refused with 503.
func (g *Gateway) handleHTTP(ctx context.Context, conn net.Conn, req *http.Request) {
	if req.URL == nil || !req.URL.IsAbs() || !strings.EqualFold(req.URL.Scheme, "http") {
		writeHTTPError(conn, http.StatusBadRequest, "Bad Request", "absolute http:// URL required; use CONNECT for HTTPS")
		return
	}
	// Public exits never receive session credentials. This is checked before
	// scope, rate limiting or any dial so nothing downstream can leak them.
	if err := rejectSensitiveHeaders(g.dialer.pool.cfg, req.Header); err != nil {
		g.audit(AuditEvent{Kind: "http", Method: req.Method, Target: auditTarget(req.URL), Reason: "sensitive_header_blocked"})
		writeHTTPError(conn, http.StatusForbidden, "Forbidden", err.Error())
		return
	}
	target := req.URL.Host
	if target == "" {
		writeHTTPError(conn, http.StatusBadRequest, "Bad Request", "request target is missing")
		return
	}
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(strings.Trim(target, "[]"), "80")
	}

	if df := g.dialer.pool.Deception(); df != nil && df.Enabled() {
		if _, block := df.ShouldBlock(req.URL.Hostname(), req.URL.Path); block {
			g.audit(AuditEvent{Kind: "http", Method: req.Method, Target: auditTarget(req.URL), Reason: "deception_target_banned"})
			writeHTTPError(conn, http.StatusForbidden, "Forbidden", "target banned by deception filter")
			return
		}
	}

	if _, err := g.dialer.pool.scope.CheckTarget(ctx, target); err != nil {
		g.log.Debug("gateway target rejected by scope", "target", target, "error", err)
		g.audit(AuditEvent{Kind: "http", Method: req.Method, Target: auditTarget(req.URL), Reason: "scope_rejected"})
		writeHTTPError(conn, http.StatusForbidden, "Forbidden", "target is outside the configured scope")
		return
	}

	// Calibrate against nonexistent paths before the first real request. The
	// control requests use the same scope-checked pool path but bypass this
	// handler so they cannot recurse into EnsureBaseline.
	if df := g.dialer.pool.Deception(); df != nil && df.Enabled() {
		if _, err := df.EnsureBaseline(ctx, "http://"+req.URL.Host, pathPrefix(req.URL.Path), g.baselineDoRequest); err != nil {
			g.audit(AuditEvent{Kind: "http", Method: req.Method, Target: auditTarget(req.URL), Reason: "deception_baseline_failed"})
			writeHTTPError(conn, http.StatusServiceUnavailable, "Service Unavailable", "deception baseline unavailable")
			return
		}
	}

	ctx, waitErr := g.dialer.pool.WaitGlobal(ctx)
	if waitErr != nil {
		g.audit(AuditEvent{Kind: "http", Method: req.Method, Target: auditTarget(req.URL), Reason: "rate_limited"})
		writeHTTPError(conn, http.StatusTooManyRequests, "Too Many Requests", "global rate limit exceeded")
		return
	}
	if err := g.dialer.pool.Allow(); err != nil {
		g.log.Warn("gateway refused by safety circuit", "target", target, "error", err)
		g.audit(AuditEvent{Kind: "http", Method: req.Method, Target: auditTarget(req.URL), Reason: "circuit_open"})
		writeHTTPError(conn, http.StatusServiceUnavailable, "Service Unavailable", "safety circuit is open")
		return
	}

	var (
		upstream net.Conn
		err      error
	)
	pinHeader := strings.TrimSpace(g.dialer.pool.cfg.Gateway.ProxyPinHeader)
	if pinHeader != "" {
		if label := strings.TrimSpace(req.Header.Get(pinHeader)); label != "" {
			if pr, ok := g.dialer.pool.ProxyByLabel(label); ok {
				upstream, err = g.dialer.dialProxy(ctx, pr, target)
			} else {
				err = fmt.Errorf("pinned proxy %q not found", label)
			}
		}
	}
	if upstream == nil && err == nil {
		upstream, err = g.dialer.DialContext(ctx, "tcp", target)
	}
	if err != nil {
		g.log.Debug("gateway dial failed", "target", target, "error", err)
		g.audit(AuditEvent{Kind: "http", Method: req.Method, Target: auditTarget(req.URL), Reason: "dial_error"})
		writeHTTPError(conn, http.StatusBadGateway, "Bad Gateway", "upstream connection failed")
		return
	}
	defer upstream.Close()

	// Strip proxy-only headers before the request reaches the origin. One
	// request per connection keeps the forwarding path small and predictable.
	req.RequestURI = ""
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Expect")
	req.Close = true
	if err := req.Write(upstream); err != nil {
		g.audit(AuditEvent{Kind: "http", Method: req.Method, Target: auditTarget(req.URL), Reason: "request_write_error"})
		writeHTTPError(conn, http.StatusBadGateway, "Bad Gateway", "failed to forward request")
		return
	}

	start := time.Now()
	resp, err := http.ReadResponse(bufio.NewReader(upstream), req)
	if err != nil {
		g.audit(AuditEvent{Kind: "http", Method: req.Method, Target: auditTarget(req.URL), Reason: "response_read_error"})
		writeHTTPError(conn, http.StatusBadGateway, "Bad Gateway", "invalid upstream response")
		return
	}
	defer resp.Body.Close()
	latency := time.Since(start)

	pr, hasProxy := ProxyOf(upstream)
	var pptr *Proxy
	if hasProxy {
		pptr = pr
	}
	g.dialer.pool.RecordTargetStatus(req.URL.Hostname(), pptr, resp.StatusCode)
	if df := g.dialer.pool.Deception(); df != nil && df.Enabled() {
		// Ensure request URL is absolute for inspection.
		if resp.Request == nil {
			resp.Request = req
		}
		d, dErr := df.InspectHTTPResponse(resp, latency)
		if dErr != nil {
			ev := AuditEvent{Kind: "http", Method: req.Method, Target: auditTarget(req.URL), Status: resp.StatusCode, Reason: "deception_inspection_failed"}
			if hasProxy {
				ev.Proxy = pr.Label()
			}
			if errors.Is(dErr, ErrDeceptionUncertain) {
				ev.Reason = "deception_uncertain"
				ev.DeceptionUncertain = true
			}
			g.audit(ev)
			writeHTTPError(conn, http.StatusBadGateway, "Bad Gateway", "deception analysis failed")
			return
		}
		if d.Flagged {
			g.dialer.pool.HandleDeception(pptr, d)
			proxyLabel := ""
			if hasProxy {
				proxyLabel = pr.Label()
			}
			g.audit(AuditEvent{Kind: "http", Method: req.Method, Target: auditTarget(req.URL), Status: resp.StatusCode, Proxy: proxyLabel, Reason: "deception_" + string(d.Kind)})
			if _, block := df.ShouldBlock(req.URL.Hostname(), req.URL.Path); block {
				writeHTTPError(conn, http.StatusBadGateway, "Bad Gateway", "deception/tarpit response blocked")
				return
			}
		}
	}

	ev := AuditEvent{Kind: "http", Method: req.Method, Target: auditTarget(req.URL), Status: resp.StatusCode}
	if hasProxy {
		ev.Proxy = pr.Label()
	} else {
		ev.Reason = "direct"
	}
	g.audit(ev)

	resp.Close = true
	if err := resp.Write(conn); err != nil {
		g.log.Debug("gateway response write failed", "target", target, "error", err)
	}
}

// baselineDoRequest is the gateway's non-recursive control path for deception
// calibration. It reuses the pool's scope checks, rate limit and circuit, but
// never re-enters handleHTTP or InspectHTTPResponse.
func (g *Gateway) baselineDoRequest(ctx context.Context, rawURL string) (*http.Response, time.Duration, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, 0, err
	}
	target := u.Host
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(strings.Trim(target, "[]"), "80")
	}
	if _, err := g.dialer.pool.scope.CheckTarget(ctx, target); err != nil {
		return nil, 0, err
	}
	if _, err := g.dialer.pool.WaitGlobal(ctx); err != nil {
		return nil, 0, err
	}
	if err := g.dialer.pool.Allow(); err != nil {
		return nil, 0, err
	}
	pr, pickErr := g.dialer.pool.pick(nil, target)
	var upstream net.Conn
	if pickErr == nil {
		upstream, err = g.dialer.dialProxy(ctx, pr, target)
	} else if g.dialer.pool.cfg.AllowDirect {
		upstream, err = g.dialer.directDialContext(ctx, "tcp", target)
	} else {
		return nil, 0, pickErr
	}
	if err != nil {
		return nil, 0, err
	}
	defer upstream.Close()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, 0, err
	}
	req.RequestURI = ""
	req.Close = true
	start := time.Now()
	if err := req.Write(upstream); err != nil {
		return nil, time.Since(start), err
	}
	resp, err := http.ReadResponse(bufio.NewReader(upstream), req)
	return resp, time.Since(start), err
}

func (g *Gateway) authorized(header string) bool {
	if g.token == "" {
		return true
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	got := []byte(strings.TrimSpace(strings.TrimPrefix(header, prefix)))
	return subtle.ConstantTimeCompare(got, []byte(g.token)) == 1
}

func (g *Gateway) audit(ev AuditEvent) {
	if g == nil || g.dialer == nil || g.dialer.pool == nil {
		return
	}
	g.dialer.pool.Audit().Log(ev)
}

func closeWrite(conn net.Conn) {
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

func writeHTTPError(conn net.Conn, code int, reason, msg string) {
	body := msg + "\n"
	_, _ = fmt.Fprintf(conn,
		"HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, reason, len(body), body)
}

func writeProxyAuthRequired(conn net.Conn) {
	_, _ = io.WriteString(conn,
		"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Bearer\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
}
