package omnislash

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// sensitiveHeaders are never sent through a public exit in the strict trust
// tier. They are verbatim names: a client can send "cookie" or "COOKIE", and a
// header map lookup in net/http is canonical but not guaranteed for raw writes.
var sensitiveHeaders = [...]string{"Cookie", "Authorization", "X-Api-Key"}

// rejectSensitiveHeaders fails closed before any dial. In strict tier the
// operator has declared the pool public/untrusted, so credentials must not be
// handed to it. Trusted pools keep the historical behaviour; manual Caido
// sessions are outside this transport entirely.
func hasSensitiveHeader(h http.Header) string {
	for _, name := range sensitiveHeaders {
		if h.Get(name) != "" {
			return name
		}
	}
	return ""
}

func rejectSensitiveHeaders(cfg Config, h http.Header) error {
	if !strings.EqualFold(strings.TrimSpace(cfg.TrustTier), TrustTierStrict) {
		return nil
	}
	if name := hasSensitiveHeader(h); name != "" {
		return fmt.Errorf("%w: %s", ErrSensitiveHeaderBlocked, name)
	}
	return nil
}

// isIdempotentMethod restricts speculative dials to methods that are safe to
// repeat. POST/PATCH are excluded even when they carry no credentials.
func isIdempotentMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodPut, http.MethodDelete, http.MethodTrace:
		return true
	default:
		return false
	}
}

// RotatingTransport is an http.RoundTripper that assigns every request to a
// proxy and therefore rotates the source IP. Each proxy gets its own
// http.Transport, so keep-alive connections are reused per proxy while
// different requests can leave through different IPs.
type RotatingTransport struct {
	pool   *Pool
	dialer *Dialer
	cfg    HTTPConfig
	log    *slog.Logger

	mu       sync.Mutex
	perProxy map[*Proxy]*http.Transport
	direct   *http.Transport
	closed   atomic.Bool
	ban      map[int]struct{}
	gen      uint64

	// maxResponseBytes is probe.max_response_bytes from the transport config.
	// Exceeding it is an error, never a truncated body: NCD and framing
	// analysis must never see a response that was silently cut in half.
	maxResponseBytes int64
	// ttfbTimeout is the top-level first-byte budget. It is kept separately
	// from HTTPConfig because TLS handshake and TTFB are distinct stages.
	ttfbTimeout time.Duration
}

// NewRotatingTransport creates a transport for pool.
func NewRotatingTransport(pool *Pool, dialer *Dialer, cfg HTTPConfig, logger *slog.Logger) *RotatingTransport {
	if logger == nil {
		logger = pool.log
	}
	normalized := pool.cfg
	normalized.HTTP = cfg
	normalized.normalize()
	ban := make(map[int]struct{}, len(normalized.HTTP.BanStatuses))
	for _, code := range normalized.HTTP.BanStatuses {
		ban[code] = struct{}{}
	}
	return &RotatingTransport{
		pool:             pool,
		dialer:           dialer,
		cfg:              normalized.HTTP,
		log:              logger,
		perProxy:         make(map[*Proxy]*http.Transport),
		ban:              ban,
		gen:              pool.Generation(),
		maxResponseBytes: normalized.Probe.MaxResponseBytes,
		ttfbTimeout:      normalized.TTFBTimeout.Std(),
	}
}

// RoundTrip implements http.RoundTripper.
func (t *RotatingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.closed.Load() {
		return nil, ErrPoolClosed
	}
	if req.URL == nil {
		return nil, errors.New("omnislash: nil request URL")
	}
	if err := rejectSensitiveHeaders(t.pool.cfg, req.Header); err != nil {
		t.audit(AuditEvent{Kind: "http", Method: req.Method, Target: auditTarget(req.URL), Reason: "sensitive_header_blocked"})
		return nil, err
	}
	if df := t.pool.Deception(); df != nil && df.Enabled() {
		if d, block := df.ShouldBlock(req.URL.Hostname(), req.URL.Path); block {
			t.audit(AuditEvent{Kind: "http", Method: req.Method, Target: auditTarget(req.URL), Reason: "deception_target_banned"})
			return nil, fmt.Errorf("%w: %s", ErrDeceptionDetected, d.Reason)
		}
	}
	ctx, err := t.pool.WaitGlobal(req.Context())
	if err != nil {
		return nil, err
	}
	if err := t.pool.Allow(); err != nil {
		t.audit(AuditEvent{Kind: "http", Method: req.Method, Target: auditTarget(req.URL), Reason: "circuit_open"})
		return nil, err
	}
	t.prune()
	factory, canRetry, err := prepareBody(req, t.cfg.MaxBodyBuffer)
	if err != nil {
		return nil, err
	}
	attempts := t.cfg.MaxRetries + 1
	if attempts < 1 {
		attempts = 1
	}
	if !canRetry {
		attempts = 1
	}

	excluded := make(map[*Proxy]struct{}, attempts)
	var lastErr error
	makeRequest := func() (*http.Request, error) {
		r := req.Clone(ctx)
		if factory != nil {
			body, bErr := factory()
			if bErr != nil {
				return nil, bErr
			}
			r.Body = body
			r.GetBody = factory
		}
		return r, nil
	}

	// Deception control traffic goes through the same scope-checked pool path
	// as the real probe, but never re-enters RoundTrip. Without this, an agent
	// could stumble into a tarpit before the filter knows the target's baseline.
	if df := t.pool.Deception(); df != nil && df.Enabled() {
		baseURL := req.URL.Scheme + "://" + req.URL.Host
		if _, err := df.EnsureBaseline(ctx, baseURL, pathPrefix(req.URL.Path), t.baselineDoRequest); err != nil {
			if errors.Is(err, ErrDeceptionUncertain) {
				t.audit(AuditEvent{Kind: "http", Method: req.Method, Target: auditTarget(req.URL), Reason: "deception_uncertain", DeceptionUncertain: true})
				return nil, err
			}
			t.audit(AuditEvent{Kind: "http", Method: req.Method, Target: auditTarget(req.URL), Reason: "deception_baseline_failed"})
			return nil, fmt.Errorf("%w: %v", ErrDeceptionBaseline, err)
		}
	}

	for attempt := 0; attempt < attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := t.pool.Allow(); err != nil {
			t.audit(AuditEvent{Kind: "http", Method: req.Method, Target: auditTarget(req.URL), Reason: "circuit_open"})
			return nil, err
		}
		pr, pickErr := t.pool.pick(excluded, req.URL.Host)
		if pickErr != nil {
			if t.pool.cfg.AllowDirect && attempt == 0 {
				t.log.Warn("no usable proxy, falling back to direct request", "url", req.URL.Redacted(), "error", pickErr)
				directReq, rErr := makeRequest()
				if rErr != nil {
					return nil, rErr
				}
				start := t.pool.now()
				resp, rErr := t.directTransport().RoundTrip(directReq)
				latency := t.pool.now().Sub(start)
				if rErr == nil && resp != nil {
					t.limitResponseBody(resp)
					t.pool.RecordTargetStatus(req.URL.Hostname(), nil, resp.StatusCode)
					if df := t.pool.Deception(); df != nil && df.Enabled() {
						d, dErr := df.InspectHTTPResponse(resp, latency)
						if dErr != nil {
							t.auditInspectionError(req, nil, dErr)
							drainAndClose(resp.Body)
							return nil, dErr
						}
						if d.Flagged {
							t.pool.HandleDeception(nil, d)
							t.audit(AuditEvent{Kind: "http", Method: req.Method, Target: auditTarget(req.URL), Status: resp.StatusCode, Reason: "deception_" + string(d.Kind)})
							if _, block := df.ShouldBlock(req.URL.Hostname(), req.URL.Path); block {
								drainAndClose(resp.Body)
								return nil, fmt.Errorf("%w: %s", ErrDeceptionDetected, d.Reason)
							}
						}
					}
					t.audit(AuditEvent{Kind: "http", Method: req.Method, Target: auditTarget(req.URL), Status: resp.StatusCode, Reason: "direct"})
				}
				return resp, rErr
			}
			break
		}
		excluded[pr] = struct{}{}

		attemptReq, rErr := makeRequest()
		if rErr != nil {
			return nil, rErr
		}
		start := t.pool.now()
		var (
			resp  *http.Response
			rtErr error
		)
		// Speculation is restricted to idempotent, unauthenticated HTTPS through
		// an Infantry exit. Sniper, credentials and plain HTTP stay on the
		// deterministic per-proxy transport.
		if t.dialer != nil && req.URL.Scheme == "https" &&
			isIdempotentMethod(req.Method) && hasSensitiveHeader(req.Header) == "" &&
			pr.Tier() == TierInfantry {
			resp, rtErr = t.hedgedRoundTrip(ctx, attemptReq, pr, requestDialAddr(req.URL))
		} else {
			resp, rtErr = t.transportFor(pr).RoundTrip(attemptReq)
		}
		latency := t.pool.now().Sub(start)
		if rtErr != nil {
			lastErr = fmt.Errorf("%s: %w", pr.Label(), rtErr)
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			t.log.Debug("request via proxy failed", "proxy", pr.Label(), "url", req.URL.Redacted(), "error", rtErr)
			t.audit(AuditEvent{Kind: "http", Method: req.Method, Target: auditTarget(req.URL), Proxy: pr.Label(), Reason: "proxy_error"})
			continue
		}
		t.limitResponseBody(resp)
		t.pool.RecordTargetStatus(req.URL.Hostname(), pr, resp.StatusCode)
		if df := t.pool.Deception(); df != nil && df.Enabled() {
			d, dErr := df.InspectHTTPResponse(resp, latency)
			if dErr != nil {
				t.auditInspectionError(req, pr, dErr)
				drainAndClose(resp.Body)
				return nil, dErr
			}
			if d.Flagged {
				t.pool.HandleDeception(pr, d)
				t.audit(AuditEvent{Kind: "http", Method: req.Method, Target: auditTarget(req.URL), Status: resp.StatusCode, Proxy: pr.Label(), Reason: "deception_" + string(d.Kind)})
				if _, block := df.ShouldBlock(req.URL.Hostname(), req.URL.Path); block {
					drainAndClose(resp.Body)
					return nil, fmt.Errorf("%w: %s", ErrDeceptionDetected, d.Reason)
				}
			}
		}
		if _, banned := t.ban[resp.StatusCode]; banned {
			pr.markBan(t.pool.now(), fmt.Sprintf("HTTP %d", resp.StatusCode), t.cfg.BanCooldown.Std())
			t.audit(AuditEvent{Kind: "http", Method: req.Method, Target: auditTarget(req.URL), Status: resp.StatusCode, Proxy: pr.Label(), Reason: "proxy_ban"})
			if attempt < attempts-1 {
				drainAndClose(resp.Body)
				lastErr = fmt.Errorf("%s: banned with HTTP %d", pr.Label(), resp.StatusCode)
				continue
			}
			return resp, nil
		}
		t.audit(AuditEvent{Kind: "http", Method: req.Method, Target: auditTarget(req.URL), Status: resp.StatusCode, Proxy: pr.Label()})
		return resp, nil
	}

	if lastErr != nil {
		return nil, fmt.Errorf("omnislash: all attempts failed: %w", lastErr)
	}
	return nil, ErrNoProxyAvailable
}

// Close closes idle connections for every proxy transport.
func (t *RotatingTransport) Close() error {
	t.closed.Store(true)
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, tr := range t.perProxy {
		tr.CloseIdleConnections()
	}
	if t.direct != nil {
		t.direct.CloseIdleConnections()
	}
	return nil
}

// prune drops transports for proxies removed by a pool hot-swap. Without it a
// long-running scanner would retain one idle transport per proxy per refresh.
func (t *RotatingTransport) prune() {
	gen := t.pool.Generation()
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.gen == gen {
		return
	}
	current := make(map[*Proxy]struct{}, t.pool.Len())
	for _, pr := range t.pool.Proxies() {
		current[pr] = struct{}{}
	}
	for pr, tr := range t.perProxy {
		if _, ok := current[pr]; !ok {
			tr.CloseIdleConnections()
			delete(t.perProxy, pr)
		}
	}
	t.gen = gen
}

func (t *RotatingTransport) transportFor(pr *Proxy) *http.Transport {
	t.mu.Lock()
	defer t.mu.Unlock()
	if tr, ok := t.perProxy[pr]; ok {
		return tr
	}
	tlsCfg := &tls.Config{InsecureSkipVerify: t.cfg.TLSSkipVerify, MinVersion: tls.VersionTLS12}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return t.dialer.DialProxy(ctx, pr, addr)
		},
		ForceAttemptHTTP2:     false,
		TLSClientConfig:       tlsCfg,
		TLSHandshakeTimeout:   t.cfg.TLSHandshakeTimeout.Std(),
		ResponseHeaderTimeout: t.ttfbTimeout,
		MaxIdleConns:          t.cfg.MaxIdleConns,
		MaxIdleConnsPerHost:   t.cfg.MaxIdleConnsPerHost,
		IdleConnTimeout:       t.cfg.IdleConnTimeout.Std(),
		ExpectContinueTimeout: time.Second,
	}
	t.perProxy[pr] = tr
	return tr
}

func (t *RotatingTransport) directTransport() *http.Transport {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.direct != nil {
		return t.direct
	}
	t.direct = &http.Transport{
		DialContext:         t.dialer.directDialContext,
		ForceAttemptHTTP2:   false,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: t.cfg.TLSSkipVerify, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: t.cfg.TLSHandshakeTimeout.Std(),
		MaxIdleConns:        t.cfg.MaxIdleConns,
		MaxIdleConnsPerHost: t.cfg.MaxIdleConnsPerHost,
		IdleConnTimeout:     t.cfg.IdleConnTimeout.Std(),
	}
	return t.direct
}

// requestDialAddr returns the explicit host:port handed to a proxy. Relying on
// net/http's implicit port would make scope checks and hedged dials see a
// different address than the TLS SNI.
func requestDialAddr(u *url.URL) string {
	port := u.Port()
	if port == "" {
		if strings.EqualFold(u.Scheme, "https") {
			port = "443"
		} else {
			port = "80"
		}
	}
	return net.JoinHostPort(u.Hostname(), port)
}

// hedgedRoundTrip runs one request over a pre-dialed, race-winning TLS
// connection. The single-use http.Transport never reuses the socket, so a
// speculative win cannot pollute the per-proxy keep-alive cache or report a
// proxy that did not carry the request.
func (t *RotatingTransport) hedgedRoundTrip(ctx context.Context, req *http.Request, pr *Proxy, addr string) (*http.Response, error) {
	tlsCfg := &tls.Config{
		ServerName:         req.URL.Hostname(),
		InsecureSkipVerify: t.cfg.TLSSkipVerify,
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"http/1.1"},
	}
	conn, err := t.dialer.HedgedDialContext(ctx, pr, "tcp", addr, tlsCfg)
	if err != nil {
		return nil, err
	}
	var once sync.Once
	tr := &http.Transport{
		// DialTLSContext returns the already handshaken socket. DisableKeepAlives
		// keeps attribution exact: this connection belongs to this one request.
		DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
			var c net.Conn
			once.Do(func() { c = conn })
			if c == nil {
				return nil, errors.New("omnislash: hedged connection was already handed out")
			}
			return c, nil
		},
		DisableKeepAlives:     true,
		ForceAttemptHTTP2:     false,
		TLSClientConfig:       tlsCfg,
		TLSHandshakeTimeout:   t.cfg.TLSHandshakeTimeout.Std(),
		ResponseHeaderTimeout: t.ttfbTimeout,
		MaxIdleConns:          1,
		MaxIdleConnsPerHost:   1,
	}
	defer tr.CloseIdleConnections()
	resp, roundErr := tr.RoundTrip(req)
	if roundErr != nil {
		_ = conn.Close()
	}
	return resp, roundErr
}

// baselineDoRequest issues one control request for deception calibration. It
// deliberately bypasses RoundTrip: the response is inspected by
// CalibrateBaseline, not by the normal deception decision path, and recursion
// would otherwise calibrate the calibration.
func (t *RotatingTransport) baselineDoRequest(ctx context.Context, rawURL string) (*http.Response, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, 0, err
	}
	if _, _, err := net.SplitHostPort(req.URL.Host); err != nil {
		port := "80"
		if req.URL.Scheme == "https" {
			port = "443"
		}
		req.URL.Host = net.JoinHostPort(req.URL.Hostname(), port)
		req.Host = req.URL.Host
	}
	if _, err := t.pool.WaitGlobal(ctx); err != nil {
		return nil, 0, err
	}
	if err := t.pool.Allow(); err != nil {
		return nil, 0, err
	}
	pr, err := t.pool.pick(nil, req.URL.Host)
	var tr *http.Transport
	switch {
	case err == nil:
		tr = t.transportFor(pr)
	case t.pool.cfg.AllowDirect:
		tr = t.directTransport()
	default:
		return nil, 0, err
	}
	start := t.pool.now()
	resp, err := tr.RoundTrip(req)
	latency := t.pool.now().Sub(start)
	if err != nil {
		return nil, latency, err
	}
	return resp, latency, nil
}

// prepareBody makes the request body replayable when it is small enough.
// It returns a fresh-body factory and whether retries are allowed.
func prepareBody(req *http.Request, limit int64) (func() (io.ReadCloser, error), bool, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return nil, true, nil
	}
	if limit <= 0 {
		limit = 4 << 20
	}
	if req.GetBody != nil {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		req.Body = http.NoBody
		return req.GetBody, true, nil
	}
	data, err := io.ReadAll(io.LimitReader(req.Body, limit+1))
	if err != nil {
		_ = req.Body.Close()
		return nil, false, fmt.Errorf("buffer request body: %w", err)
	}
	_ = req.Body.Close()
	if int64(len(data)) > limit {
		req.Body = io.NopCloser(bytes.NewReader(data))
		return nil, false, nil
	}
	req.Body = http.NoBody
	return func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	}, true, nil
}

// transportBufferPool keeps the drain path allocation-free. Every byte is
// cleared before Put: a pooled buffer must never carry bytes from a previous
// response into the next request (payload bleeding).
var transportBufferPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 32<<10)
		return &buf
	},
}

func drainAndClose(body io.ReadCloser) {
	if body == nil {
		return
	}
	bufp := transportBufferPool.Get().(*[]byte)
	buf := (*bufp)[:32<<10]
	_, _ = io.CopyBuffer(io.Discard, io.LimitReader(body, 32<<10), buf)
	clear(buf)
	transportBufferPool.Put(bufp)
	_ = body.Close()
}

// limitResponseBody installs the configured response bound. The wrapper returns
// ErrResponseTooLarge when the peer sends one byte past the bound; it never
// silently truncates the body handed to NCD or framing analysis.
func (t *RotatingTransport) limitResponseBody(resp *http.Response) {
	if t == nil || resp == nil || resp.Body == nil || t.maxResponseBytes <= 0 {
		return
	}
	resp.Body = &limitedResponseBody{ReadCloser: resp.Body, remaining: t.maxResponseBytes}
}

type limitedResponseBody struct {
	io.ReadCloser
	remaining int64
	overflow  error
}

func (b *limitedResponseBody) Read(p []byte) (int, error) {
	if b.overflow != nil {
		return 0, b.overflow
	}
	if len(p) == 0 {
		return 0, nil
	}
	if b.remaining <= 0 {
		var one [1]byte
		n, err := b.ReadCloser.Read(one[:])
		if n > 0 {
			b.overflow = ErrResponseTooLarge
			return 0, b.overflow
		}
		return 0, err
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.ReadCloser.Read(p)
	b.remaining -= int64(n)
	return n, err
}

func (t *RotatingTransport) auditInspectionError(req *http.Request, pr *Proxy, err error) {
	ev := AuditEvent{Kind: "http", Method: req.Method, Target: auditTarget(req.URL), Reason: "deception_inspection_failed"}
	if errors.Is(err, ErrDeceptionUncertain) {
		ev.Reason = "deception_uncertain"
		ev.DeceptionUncertain = true
	}
	if pr != nil {
		ev.Proxy = pr.Label()
	}
	t.audit(ev)
}

func (t *RotatingTransport) audit(ev AuditEvent) {
	if t == nil || t.pool == nil {
		return
	}
	t.pool.Audit().Log(ev)
}
