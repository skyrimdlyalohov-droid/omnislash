package omnislash

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"
)

// Dialer opens TCP connections through the pool. Every new connection is
// assigned to a proxy according to the pool strategy; connections that fail
// during the proxy handshake are retired with a cooldown and the dial is
// retried through a different proxy.
type Dialer struct {
	pool *Pool
	log  *slog.Logger
	base *net.Dialer

	// fingerprints are rotated one per Session, never per dial inside a
	// session. fpSeq is atomic because a pool can create sessions concurrently.
	fingerprints []utls.ClientHelloID
	fpSeq        atomic.Uint64
}

// WaitForProxy blocks until the pool has a usable proxy. The daemon uses it to
// enter a health-check wait instead of failing the whole run when every exit is
// cooling down or the scraper has not populated the pool yet.
func (d *Dialer) WaitForProxy(ctx context.Context) error {
	if d == nil || d.pool == nil {
		return nil
	}
	return d.pool.WaitForProxy(ctx)
}

// TargetCooling reports whether host is paused after a target-wide block burst.
func (d *Dialer) TargetCooling(host string) (time.Time, bool) {
	if d == nil || d.pool == nil {
		return time.Time{}, false
	}
	return d.pool.TargetCooling(host)
}

// NewDialer creates a dialer for pool.
func NewDialer(pool *Pool, logger *slog.Logger) *Dialer {
	if logger == nil {
		logger = pool.log
	}
	d := &Dialer{
		pool: pool,
		log:  logger,
		base: &net.Dialer{
			Timeout:   pool.cfg.DialTimeout.Std(),
			KeepAlive: 30 * time.Second,
			Control:   tuneDialSocket,
		},
	}
	for _, name := range pool.cfg.TLSFingerprints {
		id, err := ParseFingerprint(name)
		if err != nil {
			// Config.Validate normally rejects this; never guess a profile.
			logger.Warn("ignoring invalid TLS fingerprint", "name", name, "error", err)
			continue
		}
		d.fingerprints = append(d.fingerprints, id)
	}
	return d
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
		return nil, markProxyTransport(fmt.Errorf("%s: %w", pr.Label(), err))
	}
	pr.markSuccess(d.pool.now(), time.Since(start))
	return conn, nil
}

// dialProxyRaw acquires a rate-limit slot and opens the tunnel but does not
// update health counters. It is used by the health checker, which scores the
// full HTTP probe rather than just the TCP handshake.
func (d *Dialer) dialProxyRaw(ctx context.Context, pr *Proxy, target string) (net.Conn, error) {
	host, _, splitErr := net.SplitHostPort(target)
	if splitErr != nil || host == "" {
		host = target
	}
	// Charge the per-host interval to the original name even when the proxy
	// CONNECT was pinned to a literal IP; otherwise rotating resolved IPs
	// would bypass the spacing rule.
	if original := d.pool.scope.OriginalHost(target); original != "" {
		host = original
	}
	if err := d.pool.WaitHost(ctx, host); err != nil {
		return nil, err
	}
	if err := pr.acquire(ctx); err != nil {
		return nil, err
	}
	handshake := d.pool.cfg.HandshakeTimeout.Std()
	if pr.Tier() == TierInfantry && pr.P90Latency() > 0 {
		if cut := pr.AdaptiveTimeout(); cut > 0 && cut < handshake {
			handshake = cut
		}
	}
	connect := d.pool.cfg.ProxyConnectTimeout.Std()
	if connect <= 0 || connect > handshake {
		connect = handshake
	}
	conn, err := dialThroughProxy(
		ctx,
		d.base,
		pr,
		target,
		connect,
		handshake,
		d.pool.cfg.ProxyTLSSkipVerify,
	)
	if err != nil {
		pr.release()
		return nil, err
	}
	return &trackedConn{Conn: conn, release: pr.release, proxy: pr}, nil
}

// DialSniperContext dials a target through a SniperTier proxy only. It is the
// transport entry point for final synchronized series and cross-proxy
// verification, and it never silently falls back to Infantry.
func (d *Dialer) DialSniperContext(ctx context.Context, network, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("omnislash: unsupported network %q", network)
	}
	target, err := d.pool.scope.CheckTarget(ctx, addr)
	if err != nil {
		return nil, err
	}
	pr, err := d.pool.AcquireSniper(ctx)
	if err != nil {
		return nil, err
	}
	return d.dialProxy(ctx, pr, target)
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
		cfg.ServerName = d.sniFor(addr)
	}
	if hs := d.pool.cfg.UTLSHandshakeTimeout.Std(); hs > 0 {
		deadline := time.Now().Add(hs)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		_ = raw.SetDeadline(deadline)
	}
	tc := tls.Client(raw, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, markProxyTransport(fmt.Errorf("tls handshake with %s: %w", addr, err))
	}
	_ = raw.SetDeadline(time.Time{})
	return newTTFBConn(tc, d.pool.cfg.TTFBTimeout.Std()), nil
}

// sniFor resolves the TLS identity of addr. A scope-pinned IP maps back to the
// hostname that was approved in allow_hosts; using the IP here would produce
// "certificate is valid for <host>, not <IP>" (IP SANs) errors and leak the
// resolved address as SNI.
func (d *Dialer) sniFor(addr string) string {
	if d == nil || d.pool == nil {
		return addr
	}
	if original := d.pool.scope.OriginalHost(addr); original != "" {
		return original
	}
	if host, _, err := net.SplitHostPort(addr); err == nil && host != "" {
		return host
	}
	return addr
}

// hedgedTLSConfig derives the TLS settings for a speculative dial. The SNI is
// the original hostname even when CONNECT is pinned to a literal IP, and a
// public pool never accepts an unverified certificate chain: callers cannot
// disable verification for a proxy-backed request in the strict trust tier.
func (d *Dialer) hedgedTLSConfig(sni string, cfg *tls.Config) *tls.Config {
	out := &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
	if cfg != nil {
		out = cfg.Clone()
	}
	if out.ServerName == "" {
		out.ServerName = sni
	}
	if out.MinVersion < tls.VersionTLS12 {
		out.MinVersion = tls.VersionTLS12
	}
	if len(out.NextProtos) == 0 {
		out.NextProtos = []string{"http/1.1"}
	}
	if d != nil && d.pool != nil && strings.EqualFold(strings.TrimSpace(d.pool.cfg.TrustTier), TrustTierStrict) {
		out.InsecureSkipVerify = false
	}
	return out
}

// dialHedgedTLS opens one proxy tunnel and completes a verified TLS handshake.
// It is used for both the primary and the backup attempt; every connection here
// is a distinct physical socket and has already been charged a global token.
func (d *Dialer) dialHedgedTLS(ctx context.Context, pr *Proxy, target, sni string, cfg *tls.Config) (net.Conn, error) {
	raw, err := d.dialProxy(ctx, pr, target)
	if err != nil {
		return nil, err
	}
	tlsCfg := d.hedgedTLSConfig(sni, cfg)
	hs := d.pool.cfg.UTLSHandshakeTimeout.Std()
	var tc net.Conn
	if len(d.fingerprints) > 0 {
		// Speculative and warmed tunnels present the same browser/mobile
		// ClientHello as a pinned session. The socket is already dialled
		// through pr, so uTLS cannot change the exit path.
		id := d.fingerprints[(d.fpSeq.Add(1)-1)%uint64(len(d.fingerprints))]
		tc, err = openTLSWithFingerprint(ctx, raw, sni, tlsCfg, id, hs)
	} else {
		if hs > 0 {
			deadline := time.Now().Add(hs)
			if d0, ok := ctx.Deadline(); ok && d0.Before(deadline) {
				deadline = d0
			}
			_ = raw.SetDeadline(deadline)
		}
		stdlib := tls.Client(raw, tlsCfg)
		if err = stdlib.HandshakeContext(ctx); err == nil {
			tc = stdlib
		}
	}
	if err != nil {
		_ = raw.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, markProxyTransport(fmt.Errorf("hedged tls handshake with %s: %w", sni, err))
	}
	if !tlsCfg.InsecureSkipVerify && connVerifiedChains(tc) == 0 {
		_ = raw.Close()
		return nil, markProxyTransport(fmt.Errorf("hedged tls with %s: target certificate chain was not verified", sni))
	}
	_ = raw.SetDeadline(time.Time{})
	return newTTFBConn(tc, d.pool.cfg.TTFBTimeout.Std()), nil
}

type hedgeAttempt struct {
	conn  net.Conn
	proxy *Proxy
	err   error
}

// HedgedDialContext races a second Infantry exit against a slow primary. The
// primary has already been selected by the pool (Thompson Sampling when that
// strategy is configured); the backup is selected here with the primary
// excluded. A backup is launched only after P75(primary) elapses, clamped to
// 150..600ms, and only when the global limiter has a token to spend. No token
// means no hedge, never a queue jump.
//
// The first *verified* TLS handshake wins. The losing goroutine closes its own
// net.Conn as soon as it observes that another attempt won; it is never handed
// to a caller. Both sockets are accounted for by the shared limiter and by
// per-host spacing. Sniper sessions and authenticated requests never hedge.
func (d *Dialer) HedgedDialContext(ctx context.Context, primary *Proxy, network, addr string, cfg *tls.Config) (net.Conn, error) {
	if d == nil || d.pool == nil {
		return nil, errors.New("omnislash: hedged dial requires a dialer and pool")
	}
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("omnislash: unsupported network %q", network)
	}
	if d.pool.closed.Load() {
		return nil, ErrPoolClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	// Check the scope first: the caller may pass a locally pinned IP. The
	// original hostname is kept separately for SNI and certificate checks.
	target, err := d.pool.scope.CheckTarget(ctx, addr)
	if err != nil {
		return nil, err
	}
	sni := ""
	if cfg != nil {
		sni = cfg.ServerName
	}
	if sni == "" {
		sni = d.sniFor(addr)
	}
	if primary == nil {
		primary, err = d.pool.pick(nil, addr)
		if err != nil {
			return nil, err
		}
	}
	// The primary consumes the application's normal token. WaitGlobal's marker
	// prevents a second charge when the HTTP transport already waited.
	ctx, err = d.pool.WaitGlobal(ctx)
	if err != nil {
		return nil, err
	}
	if err := d.pool.Allow(); err != nil {
		return nil, err
	}
	if primary.Tier() != TierInfantry {
		return d.dialHedgedTLS(ctx, primary, target, sni, cfg)
	}

	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan hedgeAttempt, 2)
	var raceMu sync.Mutex
	var winner net.Conn
	claim := func(a hedgeAttempt) bool {
		raceMu.Lock()
		defer raceMu.Unlock()
		if a.err == nil && winner == nil {
			winner = a.conn
			return true
		}
		return false
	}
	launch := func(pr *Proxy) {
		go func() {
			conn, dialErr := d.dialHedgedTLS(raceCtx, pr, target, sni, cfg)
			won := false
			defer func() {
				// Loser: close immediately, never expose this socket upstream.
				// The winner is handed to the caller and closed by them.
				if conn != nil && !won {
					_ = conn.Close()
				}
			}()
			if dialErr == nil {
				won = claim(hedgeAttempt{conn: conn, proxy: pr})
			}
			results <- hedgeAttempt{conn: conn, proxy: pr, err: dialErr}
		}()
	}
	launch(primary)

	delay := primary.P75Latency()
	if delay < 150*time.Millisecond {
		delay = 150 * time.Millisecond
	}
	if delay > 600*time.Millisecond {
		delay = 600 * time.Millisecond
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	timerC := timer.C
	backup := false
	for {
		select {
		case res := <-results:
			if res.err == nil {
				return res.conn, nil
			}
			if backup {
				return nil, res.err
			}
			// The primary died before the hedge window: no reason to spend a
			// second token on a backup for a failure that was already final.
			return nil, res.err
		case <-timerC:
			if backup {
				continue
			}
			if !d.pool.TryGlobalToken() {
				// Rate limit is tight: speculation is disabled for this race.
				timerC = nil
				continue
			}
			alt, pickErr := d.pool.pick(map[*Proxy]struct{}{primary: {}}, addr)
			if pickErr != nil {
				timerC = nil
				continue
			}
			backup = true
			launch(alt)
		case <-raceCtx.Done():
			return nil, raceCtx.Err()
		}
	}
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
