package omnislash

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

// Session pins one proxy, and therefore one exit IP, for the lifetime of one
// experiment. Unlike the sticky pool strategy, which is keyed by target and can
// silently expire, a session has an explicit deadline and never rotates on a
// failed dial. Use it when several requests or connections must be attributed
// to the same egress address (for example a multi-step smuggling experiment).
//
// A Session is safe for concurrent use. It does not own the proxy or the pool;
// Close only prevents further dials through this session.
type Session struct {
	dialer  *Dialer
	proxy   *Proxy
	expires time.Time
	now     func() time.Time

	// fingerprint is chosen once at session creation, so every connection in
	// one experiment presents the same ClientHello profile. Empty means plain
	// crypto/tls (explicit tls_fingerprints: [] configuration).
	fingerprint     utls.ClientHelloID
	fingerprintName string

	mu      sync.Mutex
	isClose bool
}

// NewSession selects one proxy now and pins it for ttl. A non-positive ttl is
// an error rather than an implicit default: the experiment lifetime must be
// explicit. The pool strategy is applied once, at session creation.
//
// With an empty pool in a trusted config that sets allow_direct, the session
// pins direct egress instead. That is still one egress for the whole session:
// the direct path is never a mid-session fallback after a proxy failure.
func (d *Dialer) NewSession(ttl time.Duration) (*Session, error) {
	if d == nil || d.pool == nil {
		return nil, fmt.Errorf("omnislash: nil dialer or pool")
	}
	if ttl <= 0 {
		return nil, fmt.Errorf("omnislash: session ttl must be > 0")
	}
	if d.pool.closed.Load() {
		return nil, ErrPoolClosed
	}
	pr, err := d.pool.pick(nil, "")
	if err != nil {
		if !d.pool.cfg.AllowDirect {
			return nil, fmt.Errorf("omnislash: create session: %w", err)
		}
		pr = nil
	}
	now := d.pool.now()
	s := &Session{
		dialer:  d,
		proxy:   pr,
		expires: now.Add(ttl),
		now:     d.pool.now,
	}
	if len(d.fingerprints) > 0 {
		seq := d.fpSeq.Add(1) - 1
		id := d.fingerprints[int(seq%uint64(len(d.fingerprints)))]
		s.fingerprint = id
		s.fingerprintName = fingerprintName(id)
	}
	return s, nil
}

// Proxy returns the pinned proxy, or nil for a direct-egress session. Its
// Label is safe to log.
func (s *Session) Proxy() *Proxy { return s.proxy }

// Fingerprint returns the ClientHello profile pinned for this session, or ""
// when the session uses crypto/tls. It is safe to log.
func (s *Session) Fingerprint() string {
	if s == nil {
		return ""
	}
	return s.fingerprintName
}

// ExpiresAt returns the explicit session deadline.
func (s *Session) ExpiresAt() time.Time { return s.expires }

// Close stops the session. Existing connections remain open.
func (s *Session) Close() {
	s.mu.Lock()
	s.isClose = true
	s.mu.Unlock()
}

func (s *Session) check() error {
	s.mu.Lock()
	closed := s.isClose
	s.mu.Unlock()
	if closed {
		return ErrSessionClosed
	}
	if !s.now().Before(s.expires) {
		return ErrSessionExpired
	}
	return nil
}

// DialContext dials addr through the pinned proxy. A failure is returned to the
// caller and never retried through another proxy or a direct connection: both
// would break the one-experiment/one-exit-IP invariant.
func (s *Session) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if err := s.check(); err != nil {
		return nil, err
	}
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("omnislash: unsupported network %q", network)
	}
	if s.dialer.pool.closed.Load() {
		return nil, ErrPoolClosed
	}
	target, err := s.dialer.pool.scope.CheckTarget(ctx, addr)
	if err != nil {
		return nil, err
	}
	// Every physical socket must consume one global token. The marker from
	// WaitGlobal prevents a second charge when the caller already waited
	// (for example the rotating HTTP transport).
	ctx, err = s.dialer.pool.WaitGlobal(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.dialer.pool.Allow(); err != nil {
		return nil, err
	}
	if s.proxy == nil {
		// Direct egress was pinned at session creation. No proxy failure can
		// move this session to another address mid-experiment.
		conn, err := s.dialer.base.DialContext(ctx, network, target)
		if err != nil {
			return nil, fmt.Errorf("omnislash: direct dial %s: %w", target, err)
		}
		return conn, nil
	}
	return s.dialer.dialProxy(ctx, s.proxy, target)
}

// DialTLSContext dials addr through the pinned proxy and performs a TLS
// handshake. The certificate is verified according to cfg, exactly like
// Dialer.DialTLSContext.

// TunnelWarmer keeps a small reserve of already established CONNECT + TLS
// tunnels for one active target. It is an optimization only: a warmed socket
// is used only by a session pinned to the very same proxy, so attribution,
// exit IP and experiment isolation are unchanged. Every warmed socket spends
// its own global token and obeys the per-host interval.
type TunnelWarmer struct {
	dialer *Dialer
	max    int
	ttl    time.Duration
	now    func() time.Time

	mu      sync.Mutex
	tunnels map[string][]*warmTunnel
	started map[string]context.CancelFunc
	targets map[string]warmTarget
	tlsCfg  *tls.Config
	closed  bool
	wg      sync.WaitGroup
}

type warmTarget struct {
	addr string // host:port used for scope checks and as the map key
	sni  string // original hostname; never a locally resolved IP
}

type warmTunnel struct {
	conn    net.Conn
	proxy   *Proxy
	addr    string
	expires time.Time
}

const (
	defaultMaxWarmTunnels = 4
	defaultWarmTTL        = 25 * time.Second
)

// warmedConn keeps ProxyOf working after the TLS wrapper is added. It also
// forwards ConnectionState so net/http and probe guards see a normal TLS conn.
type warmedConn struct {
	net.Conn
	proxy *Proxy
}

func (c *warmedConn) Proxy() *Proxy     { return c.proxy }
func (c *warmedConn) NetConn() net.Conn { return c.Conn }
func (c *warmedConn) ConnectionState() tls.ConnectionState {
	state, _ := TLSState(c.Conn)
	return state
}
func (c *warmedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
func (c *warmedConn) CloseRead() error {
	if cr, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
}

// NewTunnelWarmer creates a warmer. Non-positive max/ttl select 4 tunnels and
// a strict 25 second TTL: a tunnel older than that is never handed to a probe.
func NewTunnelWarmer(d *Dialer, max int, ttl time.Duration) *TunnelWarmer {
	w := &TunnelWarmer{
		dialer:  d,
		max:     max,
		ttl:     ttl,
		tunnels: make(map[string][]*warmTunnel),
		started: make(map[string]context.CancelFunc),
		targets: make(map[string]warmTarget),
	}
	if w.max <= 0 {
		w.max = defaultMaxWarmTunnels
	}
	if w.ttl <= 0 {
		w.ttl = defaultWarmTTL
	}
	if d != nil && d.pool != nil {
		w.now = d.pool.now
	}
	if w.now == nil {
		w.now = time.Now
	}
	return w
}

// SetTLSConfig supplies the trust roots and ALPN used for warmed tunnels. A
// nil config verifies against the system pool. In strict trust tier the warmer
// still refuses InsecureSkipVerify, exactly like a hedged race.
func (w *TunnelWarmer) SetTLSConfig(cfg *tls.Config) {
	if w == nil {
		return
	}
	var clone *tls.Config
	if cfg != nil {
		clone = cfg.Clone()
	}
	w.mu.Lock()
	w.tlsCfg = clone
	w.mu.Unlock()
}

// Start begins background refilling for addr (host:port). sni is the original
// hostname and must be kept when resolve_locally pins the CONNECT to an IP.
// Calling Start twice for the same addr is a no-op; each target has its own
// loop so one host cannot starve another.
func (w *TunnelWarmer) Start(ctx context.Context, addr, sni string) {
	if w == nil || ctx == nil {
		return
	}
	addr = strings.TrimSpace(addr)
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return
	}
	sni = strings.TrimSpace(sni)
	if sni == "" {
		sni, _, _ = net.SplitHostPort(addr)
	}
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	if _, ok := w.started[addr]; ok {
		w.mu.Unlock()
		return
	}
	loopCtx, cancel := context.WithCancel(ctx)
	w.started[addr] = cancel
	w.targets[addr] = warmTarget{addr: addr, sni: sni}
	w.mu.Unlock()

	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		w.loop(loopCtx, addr)
	}()
}

func (w *TunnelWarmer) loop(ctx context.Context, addr string) {
	interval := w.ttl / 5
	if interval < 250*time.Millisecond {
		interval = 250 * time.Millisecond
	}
	if interval > 5*time.Second {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	w.refill(ctx, addr)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.refill(ctx, addr)
		}
	}
}

// Take returns one warmed tunnel for addr when it is still within TTL. When pr
// is non-nil (the normal probe path) a tunnel is accepted only if it was opened
// through that exact proxy.
func (w *TunnelWarmer) Take(ctx context.Context, addr string, pr *Proxy) (net.Conn, bool) {
	if w == nil {
		return nil, false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	now := w.now()
	kept := make([]*warmTunnel, 0, len(w.tunnels[addr]))
	var taken net.Conn
	for _, t := range w.tunnels[addr] {
		usable := t != nil && t.conn != nil && now.Before(t.expires) && (pr == nil || t.proxy == pr)
		if usable && taken == nil {
			taken = t.conn
			continue
		}
		if t != nil && t.conn != nil && !usable {
			_ = t.conn.Close()
		}
		kept = append(kept, t)
	}
	if len(kept) == 0 {
		delete(w.tunnels, addr)
	} else {
		w.tunnels[addr] = kept
	}
	return taken, taken != nil
}

// WarmCount reports how many live tunnels are currently held for addr.
func (w *TunnelWarmer) WarmCount(addr string) int {
	if w == nil {
		return 0
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	now := w.now()
	n := 0
	for _, t := range w.tunnels[addr] {
		if t != nil && t.conn != nil && now.Before(t.expires) {
			n++
		}
	}
	return n
}

// Close stops all refill loops and closes every warmed socket.
func (w *TunnelWarmer) Close() {
	if w == nil {
		return
	}
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	w.closed = true
	for _, cancel := range w.started {
		cancel()
	}
	w.mu.Unlock()
	w.wg.Wait()

	w.mu.Lock()
	defer w.mu.Unlock()
	for host, list := range w.tunnels {
		for _, t := range list {
			if t != nil && t.conn != nil {
				_ = t.conn.Close()
			}
		}
		delete(w.tunnels, host)
	}
}

func (w *TunnelWarmer) refill(ctx context.Context, addr string) {
	if ctx.Err() != nil {
		return
	}
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	targetInfo, ok := w.targets[addr]
	tlsCfg := w.tlsCfg
	w.mu.Unlock()
	if !ok {
		return
	}
	now := w.now()
	w.mu.Lock()
	kept := make([]*warmTunnel, 0, w.max)
	for _, t := range w.tunnels[addr] {
		if t != nil && t.conn != nil && now.Before(t.expires) {
			kept = append(kept, t)
			continue
		}
		if t != nil && t.conn != nil {
			_ = t.conn.Close()
		}
	}
	w.tunnels[addr] = kept
	need := w.max - len(kept)
	w.mu.Unlock()

	for i := 0; i < need; i++ {
		if ctx.Err() != nil {
			return
		}
		dialCtx, cancel := context.WithTimeout(ctx, w.ttl)
		pr := w.bestProxy(now)
		if pr == nil {
			cancel()
			return
		}
		// A warmed tunnel is a physical socket: never reuse the application's
		// global marker here.
		dialCtx, err := w.dialer.pool.WaitGlobalSocket(dialCtx)
		if err != nil {
			cancel()
			return
		}
		// Scope checks need host:port. The SNI stays the original hostname,
		// even when the CONNECT target was pinned to a literal IP.
		target, err := w.dialer.pool.scope.CheckTarget(dialCtx, addr)
		if err != nil {
			cancel()
			return
		}
		conn, err := w.dialer.dialHedgedTLS(dialCtx, pr, target, targetInfo.sni, tlsCfg)
		if err != nil {
			cancel()
			if w.dialer.log != nil {
				w.dialer.log.Debug("tunnel warming failed", "proxy", pr.Label(), "addr", addr, "error", err)
			}
			continue
		}
		cancel()
		wrapped := &warmedConn{Conn: conn, proxy: pr}
		w.mu.Lock()
		if w.closed {
			w.mu.Unlock()
			_ = conn.Close()
			return
		}
		w.tunnels[addr] = append(w.tunnels[addr], &warmTunnel{
			conn: wrapped, proxy: pr, addr: addr, expires: w.now().Add(w.ttl),
		})
		w.mu.Unlock()
	}
}

// bestProxy prefers Sniper and then the lowest-P75 Infantry. It deliberately
// does not spend a rate-limit token; the caller charges only when it dials.
func (w *TunnelWarmer) bestProxy(now time.Time) *Proxy {
	if w == nil || w.dialer == nil || w.dialer.pool == nil {
		return nil
	}
	var best *Proxy
	var bestLatency time.Duration
	var bestTier string
	for _, pr := range w.dialer.pool.Proxies() {
		if pr == nil || !pr.available(now) {
			continue
		}
		tier := pr.Tier()
		if tier != TierSniper && tier != TierInfantry {
			continue
		}
		latency := pr.P75Latency()
		if latency <= 0 {
			latency = time.Hour
		}
		switch {
		case best == nil:
			best, bestLatency, bestTier = pr, latency, tier
		case tier == TierSniper && bestTier != TierSniper:
			best, bestLatency, bestTier = pr, latency, tier
		case tier == bestTier && latency < bestLatency:
			best, bestLatency = pr, latency
		}
	}
	return best
}

// sniFor keeps the TLS identity on the original hostname when the CONNECT
// target was pinned by scope.resolve_locally. Calling SplitHostPort alone would
// put the literal IP into SNI and break IP SAN certificate verification.
func (s *Session) sniFor(addr string) string {
	if s == nil || s.dialer == nil {
		return addr
	}
	if original := s.dialer.pool.scope.OriginalHost(addr); original != "" {
		return original
	}
	if host, _, err := net.SplitHostPort(addr); err == nil && host != "" {
		return host
	}
	return addr
}

func (s *Session) DialTLSContext(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
	raw, err := s.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		cfg = &tls.Config{}
	} else {
		cfg = cfg.Clone()
	}
	if cfg.ServerName == "" {
		cfg.ServerName = s.sniFor(addr)
	}
	if s.fingerprintName != "" {
		// raw already came from s.DialContext: it passed scope checks and is
		// pinned to s.proxy. uTLS only wraps it; it never opens a socket.
		//
		// If the uTLS handshake fails there is no fallback to crypto/tls,
		// another proxy, or a direct net.Dial. A retry would change both the
		// exit IP and the ClientHello, invalidating the experiment. The raw
		// connection is closed by dialTLSWithFingerprint and the error is
		// returned as a precision-preserving transport failure.
		conn, err := dialTLSWithFingerprint(ctx, raw, addr, cfg, s.fingerprint,
			s.dialer.pool.cfg.UTLSHandshakeTimeout.Std(), s.dialer.pool.cfg.TTFBTimeout.Std())
		if err != nil {
			return nil, fmt.Errorf("omnislash: fingerprinted TLS failed without fallback: %w", err)
		}
		return conn, nil
	}
	if hs := s.dialer.pool.cfg.UTLSHandshakeTimeout.Std(); hs > 0 {
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
	return newTTFBConn(tc, s.dialer.pool.cfg.TTFBTimeout.Std()), nil
}
