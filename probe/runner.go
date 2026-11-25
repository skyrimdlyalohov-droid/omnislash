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
	"github.com/skyrimdlyalohov-droid/omnislash/util"
)

const (
	defaultMaxResponseBytes = 4 << 20
	defaultProbeReadTimeout = 10 * time.Second
	// RaceReadTimeout is deliberately a code-level default, not a per-job
	// dynamic value. Race probes measure scheduling windows; changing the read
	// deadline between runs would change the measured jitter.
	RaceReadTimeout = 1500 * time.Millisecond
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

	// MaxResponseBytes bounds the bytes a probe may read from one connection.
	// Exceeding it returns ErrResponseTooLarge; the response is never truncated
	// and passed to NCD or framing analysis.
	MaxResponseBytes int64
	// ReadTimeout caps each read. Zero means defaultProbeReadTimeout.
	ReadTimeout time.Duration
	// RaceReadTimeout is the fixed per-read deadline for RaceProbe and
	// H2RaceProbe. Zero means the 1500 ms default. It is intentionally not
	// taken from the job's dynamic timeout.
	RaceReadTimeout time.Duration
}

// NewRunner creates a runner for dialer.
func NewRunner(d *omnislash.Dialer) *Runner {
	return &Runner{
		Dialer:           d,
		TTL:              2 * time.Minute,
		MaxResponseBytes: defaultMaxResponseBytes,
		ReadTimeout:      defaultProbeReadTimeout,
		RaceReadTimeout:  RaceReadTimeout,
	}
}

// SetLimits applies the transport config's probe section. Non-positive values
// keep the safe defaults instead of disabling the guard.
func (r *Runner) SetLimits(maxResponseBytes int64, readTimeout, raceReadTimeout time.Duration) {
	if r == nil {
		return
	}
	if maxResponseBytes > 0 {
		r.MaxResponseBytes = maxResponseBytes
	}
	if readTimeout > 0 {
		r.ReadTimeout = readTimeout
	}
	if raceReadTimeout > 0 {
		r.RaceReadTimeout = raceReadTimeout
	}
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
//
// A panic inside a probe is contained here. It becomes ErrPrecisionLost, the
// raw payload is appended to panic_audit.log, and the daemon keeps running.
// The error is explicitly not a WAF/proxy verdict and is never trainable.
func (r *Runner) Run(ctx context.Context, target Target, p Probe) (*Result, error) {
	if p == nil {
		return nil, errors.New("probe: nil probe")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	sink := &payloadSink{}
	ctx = withPayloadSink(ctx, sink)

	var out *Result
	err := util.SafeCallDynamic(sink.snapshot, func() error {
		var runErr error
		if mp, ok := p.(MultiConnProbe); ok {
			session, err := r.newSession(target)
			if err != nil {
				return err
			}
			defer session.Close()
			src := &sessionSource{
				session: session,
				tls:     r.TLS,
				addr:    target.Addr,
				race:    isRaceProbe(p),
				runner:  r,
			}
			defer src.closeAll()
			out, runErr = mp.ExecuteMulti(ctx, target, src)
			return runErr
		}
		session, conn, err := r.dial(ctx, target)
		if err != nil {
			return err
		}
		defer session.Close()
		guarded := r.guardConn(conn, isRaceProbe(p))
		defer guarded.Close()
		out, runErr = p.Execute(ctx, target, guarded)
		return runErr
	})
	if errors.Is(err, util.ErrPrecisionLost) {
		return out, fmt.Errorf("probe %s: %w", p.Name(), err)
	}
	return out, err
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

func (r *Runner) guardConn(conn net.Conn, race bool) net.Conn {
	maxRead := r.MaxResponseBytes
	if maxRead <= 0 {
		maxRead = defaultMaxResponseBytes
	}
	timeout := r.ReadTimeout
	if timeout <= 0 {
		timeout = defaultProbeReadTimeout
	}
	fixed := false
	if race {
		timeout = r.RaceReadTimeout
		if timeout <= 0 {
			timeout = RaceReadTimeout
		}
		fixed = true
	}
	return newGuardedConn(conn, maxRead, timeout, fixed)
}

// raceTimed is implemented only by probes whose timing analysis requires a
// fixed read deadline.
type raceTimed interface {
	fixedReadTimeout()
}

func (p *RaceProbe) fixedReadTimeout()   {}
func (p *H2RaceProbe) fixedReadTimeout() {}

func isRaceProbe(p Probe) bool {
	_, ok := p.(raceTimed)
	return ok
}

// sessionSource hands out connections from one pinned session and remembers
// them so Runner can close anything a probe forgot. All sockets therefore share
// the same proxy and exit IP.
type sessionSource struct {
	session *omnislash.Session
	tls     *tls.Config
	addr    string
	race    bool
	runner  *Runner

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
	if s.runner != nil {
		conn = s.runner.guardConn(conn, s.race)
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
