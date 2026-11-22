package omnislash

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// Dialer opens TCP connections through the pool. Every new connection is
// assigned to a proxy according to the pool strategy; connections that fail
// during the proxy handshake are retired with a cooldown and the dial is
// retried through a different proxy.
type Dialer struct {
	pool *Pool
	log  *slog.Logger
	base *net.Dialer
}

// NewDialer creates a dialer for pool.
func NewDialer(pool *Pool, logger *slog.Logger) *Dialer {
	if logger == nil {
		logger = pool.log
	}
	return &Dialer{
		pool: pool,
		log:  logger,
		base: &net.Dialer{
			Timeout:   pool.cfg.DialTimeout.Std(),
			KeepAlive: 30 * time.Second,
		},
	}
}

// DialContext implements the function signature expected by http.Transport.
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("omnislash: unsupported network %q", network)
	}
	if d.pool.closed.Load() {
		return nil, ErrPoolClosed
	}
	var err error
	ctx, err = d.pool.WaitGlobal(ctx)
	if err != nil {
		return nil, err
	}
	if err := d.pool.Allow(); err != nil {
		return nil, err
	}

	target, err := d.pool.scope.CheckTarget(ctx, addr)
	if err != nil {
		return nil, err
	}

	attempts := d.pool.cfg.MaxDialAttempts
	if attempts < 1 {
		attempts = 1
	}
	excluded := make(map[*Proxy]struct{}, attempts)
	var lastErr error

	for i := 0; i < attempts; i++ {
		pr, err := d.pool.pick(excluded, addr)
		if err != nil {
			if errors.Is(err, ErrPoolClosed) {
				return nil, err
			}
			break
		}
		excluded[pr] = struct{}{}
		conn, err := d.dialProxy(ctx, pr, target)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}

	if d.pool.cfg.AllowDirect {
		d.log.Warn("no usable proxy, falling back to direct connection",
			"target", addr, "error", lastErr)
		return d.base.DialContext(ctx, network, target)
	}
	if lastErr != nil {
		return nil, fmt.Errorf("omnislash: dial %s failed: %w", addr, lastErr)
	}
	return nil, ErrNoProxyAvailable
}

// DialProxy dials target through one specific proxy, records success or
// failure and returns a connection that releases the in-flight gauge on Close.
// The target is checked against the pool scope before any proxy is contacted.
func (d *Dialer) DialProxy(ctx context.Context, pr *Proxy, target string) (net.Conn, error) {
	var err error
	ctx, err = d.pool.WaitGlobal(ctx)
	if err != nil {
		return nil, err
	}
	if err := d.pool.Allow(); err != nil {
		return nil, err
	}
	checked, err := d.pool.scope.CheckTarget(ctx, target)
	if err != nil {
		return nil, err
	}
	return d.dialProxy(ctx, pr, checked)
}

// dialProxy is the internal, already-scope-checked dial path. Keeping it
// separate avoids validating a locally pinned IP literal as if it were a
// hostname, which would fail the allow_hosts rule that approved the original
// name.
func (d *Dialer) dialProxy(ctx context.Context, pr *Proxy, target string) (net.Conn, error) {
	start := time.Now()
	conn, err := d.dialProxyRaw(ctx, pr, target)
	if err != nil {
		if ctx.Err() == nil {
			pr.markFailure(d.pool.now(), err, d.pool.cfg.Cooldown)
		}
		return nil, fmt.Errorf("%s: %w", pr.Label(), err)
	}
	pr.markSuccess(d.pool.now(), time.Since(start))
	return conn, nil
}

// dialProxyRaw acquires a rate-limit slot and opens the tunnel but does not
// update health counters. It is used by the health checker, which scores the
// full HTTP probe rather than just the TCP handshake.
func (d *Dialer) dialProxyRaw(ctx context.Context, pr *Proxy, target string) (net.Conn, error) {
	if err := pr.acquire(ctx); err != nil {
		return nil, err
	}
	conn, err := dialThroughProxy(
		ctx,
		d.base,
		pr,
		target,
		d.pool.cfg.HandshakeTimeout.Std(),
		d.pool.cfg.ProxyTLSSkipVerify,
	)
	if err != nil {
		pr.release()
		return nil, err
	}
	return &trackedConn{Conn: conn, release: pr.release, proxy: pr}, nil
}

// DialTLSContext dials target through the pool and performs a TLS handshake.
// TLS errors are reported to the caller but do not penalize the proxy: the
// certificate may simply not match the scanner's expectations.
func (d *Dialer) DialTLSContext(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
	raw, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		cfg = &tls.Config{}
	} else {
		cfg = cfg.Clone()
	}
	if cfg.ServerName == "" {
		if host, _, splitErr := net.SplitHostPort(addr); splitErr == nil {
			cfg.ServerName = host
		}
	}
	tc := tls.Client(raw, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("tls handshake with %s: %w", addr, err)
	}
	return tc, nil
}

func (d *Dialer) directDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	target, err := d.pool.scope.CheckTarget(ctx, addr)
	if err != nil {
		return nil, err
	}
	return d.base.DialContext(ctx, network, target)
}

type trackedConn struct {
	net.Conn
	release func()
	proxy   *Proxy
	once    sync.Once
}

func (c *trackedConn) Proxy() *Proxy { return c.proxy }

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

func (c *trackedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (c *trackedConn) CloseRead() error {
	if cr, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
}

// ProxyOf returns the proxy that owns conn. It works for connections returned
// by Dialer.DialContext and the raw connections used by DialTLSContext. If you
// need the proxy handle for an application-level ban after a TLS handshake,
// dial raw first, keep the raw connection for ProxyOf, then wrap it in tls.Client
// yourself.
func ProxyOf(conn net.Conn) (*Proxy, bool) {
	type proxied interface{ Proxy() *Proxy }
	if pc, ok := conn.(proxied); ok {
		return pc.Proxy(), true
	}
	// A TLS wrapper hides the tracked connection. Unwrap it so a probe running
	// over Session.DialTLSContext still knows which proxy carried the bytes.
	if tc, ok := conn.(interface{ NetConn() net.Conn }); ok {
		return ProxyOf(tc.NetConn())
	}
	if bc, ok := conn.(*bufferedConn); ok {
		return ProxyOf(bc.Conn)
	}
	return nil, false
}
