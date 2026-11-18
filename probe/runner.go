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

// Run executes one probe on one pinned session and closes both the session and
// the connection afterwards. The connection is never reused for another probe:
// a desync or a half-consumed response would poison the next run.
func (r *Runner) Run(ctx context.Context, target Target, p Probe) (*Result, error) {
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

func (r *Runner) dial(ctx context.Context, target Target) (*omnislash.Session, net.Conn, error) {
	if r == nil || r.Dialer == nil {
		return nil, nil, errors.New("probe: runner has no dialer")
	}
	if target.Addr == "" {
		return nil, nil, errors.New("probe: target address is required")
	}
	ttl := r.TTL
	if ttl <= 0 {
		ttl = 2 * time.Minute
	}
	session, err := r.Dialer.NewSession(ttl)
	if err != nil {
		return nil, nil, fmt.Errorf("probe: create session: %w", err)
	}
	var conn net.Conn
	if r.TLS != nil {
		conn, err = session.DialTLSContext(ctx, "tcp", target.Addr, r.TLS)
	} else {
		conn, err = session.DialContext(ctx, "tcp", target.Addr)
	}
	if err != nil {
		session.Close()
		return nil, nil, fmt.Errorf("probe: dial %s: %w", target.Addr, err)
	}
	return session, conn, nil
}
