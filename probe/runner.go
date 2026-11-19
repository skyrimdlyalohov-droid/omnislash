package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/skyrimdlyalohov-droid/omnislash"
)

// Runner wires probes to omnislash sessions. It is the only place in this
// package that opens connections, and it always opens them through a pinned
// Session: one probe run = one proxy = one exit IP.
type Runner struct {
	Dialer *omnislash.Dialer
	// TTL is the pinned session lifetime. Zero means two minutes.
	TTL time.Duration
	// TLS, when set, makes the runner dial TLS with exactly this config
	// (ALPN, SNI, verification). Nil dials plaintext.
	TLS *tls.Config
}

// NewRunner creates a runner for dialer.
func NewRunner(d *omnislash.Dialer) *Runner {
	return &Runner{Dialer: d, TTL: 2 * time.Minute}
}

// Outcome is one probe result together with the error that stopped it.
type Outcome struct {
	Probe  string  `json:"probe"`
	Result *Result `json:"result,omitempty"`
	Err    error   `json:"-"`
}

// Run executes one probe on one pinned session and closes the session and every
// connection afterwards. Connections are never reused for another probe: a
// desync or a half-consumed response would poison the next run.
func (r *Runner) Run(ctx context.Context, target Target, p Probe) (*Result, error) {
	if mp, ok := p.(MultiConnProbe); ok {
		session, err := r.newSession(target)
		if err != nil {
			return nil, err
		}
		defer session.Close()
		src := &sessionSource{session: session, tls: r.TLS, addr: target.Addr}
		res, err := mp.ExecuteMulti(ctx, target, src)
		src.closeAll()
		return res, err
	}
	session, conn, err := r.dial(ctx, target)
	if err != nil {
		return nil, err
	}
	defer session.Close()
	defer conn.Close()
	return p.Execute(ctx, target, conn)
}

// Rotate runs one probe per fresh session, so every probe uses a different exit
// IP. This is how a gadget list is spread across the pool: the IP rotation is
// omnislash's job, the probe only sees a socket.
func (r *Runner) Rotate(ctx context.Context, target Target, probes []Probe) []Outcome {
	out := make([]Outcome, 0, len(probes))
	for _, p := range probes {
		if err := ctx.Err(); err != nil {
			out = append(out, Outcome{Probe: p.Name(), Err: err})
			break
		}
		res, err := r.Run(ctx, target, p)
		out = append(out, Outcome{Probe: p.Name(), Result: res, Err: err})
	}
	return out
}

// Fanout runs the same probe on n independent sessions in parallel. Combined
// with RaceProbe it spreads synchronized bursts across several exit IPs, which
// is the rate-limit bypass primitive: no single IP sees the whole volume.
func (r *Runner) Fanout(ctx context.Context, target Target, p Probe, n, concurrency int) []Outcome {
	if n <= 0 {
		n = 1
	}
	if concurrency <= 0 || concurrency > n {
		concurrency = n
	}
	out := make([]Outcome, n)
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			res, err := r.Run(ctx, target, p)
			out[i] = Outcome{Probe: p.Name(), Result: res, Err: err}
		}(i)
	}
	wg.Wait()
	return out
}

func (r *Runner) newSession(target Target) (*omnislash.Session, error) {
	if r == nil || r.Dialer == nil {
		return nil, errors.New("probe: runner has no dialer")
	}
	if target.Addr == "" {
		return nil, errors.New("probe: target address is required")
	}
	ttl := r.TTL
	if ttl <= 0 {
		ttl = 2 * time.Minute
	}
	session, err := r.Dialer.NewSession(ttl)
	if err != nil {
		return nil, fmt.Errorf("probe: create session: %w", err)
	}
	return session, nil
}

func (r *Runner) dial(ctx context.Context, target Target) (*omnislash.Session, net.Conn, error) {
	session, err := r.newSession(target)
	if err != nil {
		return nil, nil, err
	}
	conn, err := r.dialSession(ctx, session, target)
	if err != nil {
		session.Close()
		return nil, nil, err
	}
	return session, conn, nil
}

func (r *Runner) dialSession(ctx context.Context, session *omnislash.Session, target Target) (net.Conn, error) {
	var conn net.Conn
	var err error
	if r.TLS != nil {
		conn, err = session.DialTLSContext(ctx, "tcp", target.Addr, r.TLS)
	} else {
		conn, err = session.DialContext(ctx, "tcp", target.Addr)
	}
	if err != nil {
		return nil, fmt.Errorf("probe: dial %s: %w", target.Addr, err)
	}
	return conn, nil
}

// sessionSource hands out connections from one pinned session and remembers
// them so Runner can close anything a probe forgot. All sockets therefore share
// the same proxy and exit IP.
type sessionSource struct {
	session *omnislash.Session
	tls     *tls.Config
	addr    string

	mu   sync.Mutex
	conn []net.Conn
}

func (s *sessionSource) Dial(ctx context.Context) (net.Conn, error) {
	var conn net.Conn
	var err error
	if s.tls != nil {
		conn, err = s.session.DialTLSContext(ctx, "tcp", s.addr, s.tls)
	} else {
		conn, err = s.session.DialContext(ctx, "tcp", s.addr)
	}
	if err != nil {
		return nil, fmt.Errorf("probe: dial %s: %w", s.addr, err)
	}
	s.mu.Lock()
	s.conn = append(s.conn, conn)
	s.mu.Unlock()
	return conn, nil
}

func (s *sessionSource) closeAll() {
	s.mu.Lock()
	conns := s.conn
	s.conn = nil
	s.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}
