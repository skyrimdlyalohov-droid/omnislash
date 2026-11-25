package omnislash

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
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
		if host, _, splitErr := net.SplitHostPort(addr); splitErr == nil {
			cfg.ServerName = host
		}
	}
	if s.fingerprintName != "" {
		// raw already came from s.DialContext: it passed scope checks and is
		// pinned to s.proxy. uTLS only wraps it; it never opens a socket.
		return dialTLSWithFingerprint(ctx, raw, addr, cfg, s.fingerprint)
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
