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
	"sync"
	"sync/atomic"
	"time"
)

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
		pool:     pool,
		dialer:   dialer,
		cfg:      normalized.HTTP,
		log:      logger,
		perProxy: make(map[*Proxy]*http.Transport),
		ban:      ban,
		gen:      pool.Generation(),
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
	t.prune()
	ctx := req.Context()
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

	for attempt := 0; attempt < attempts; attempt++ {
		if err := ctx.Err(); err != nil {
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
				return t.directTransport().RoundTrip(directReq)
			}
			break
		}
		excluded[pr] = struct{}{}

		attemptReq, rErr := makeRequest()
		if rErr != nil {
			return nil, rErr
		}
		resp, rtErr := t.transportFor(pr).RoundTrip(attemptReq)
		if rtErr != nil {
			lastErr = fmt.Errorf("%s: %w", pr.Label(), rtErr)
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			t.log.Debug("request via proxy failed", "proxy", pr.Label(), "url", req.URL.Redacted(), "error", rtErr)
			continue
		}
		if _, banned := t.ban[resp.StatusCode]; banned {
			pr.markBan(t.pool.now(), fmt.Sprintf("HTTP %d", resp.StatusCode), t.cfg.BanCooldown.Std())
			if attempt < attempts-1 {
				drainAndClose(resp.Body)
				lastErr = fmt.Errorf("%s: banned with HTTP %d", pr.Label(), resp.StatusCode)
				continue
			}
			return resp, nil
		}
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

func drainAndClose(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(body, 32<<10))
	_ = body.Close()
}
