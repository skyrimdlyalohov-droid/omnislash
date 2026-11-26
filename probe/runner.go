package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
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

	// Warmer is optional. When set, TLS probes may reuse a pre-warmed tunnel,
	// but only one whose proxy matches the session's pinned exit.
	Warmer *omnislash.TunnelWarmer

	// ProxyRetries is the number of transparent retries after a proxy-only
	// transport failure. Zero means two retries (three total attempts).
	ProxyRetries int

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

	// mutation is opt-in. Without it, probes keep the byte-exact behavior the
	// existing differential-fuzz and smuggling jobs depend on.
	mutation *MutationPolicy
}

// MutationPolicy enables the additive raw-byte mutation pass. A scope guard is
// mandatory: enabling mutations without one is refused, never silently
// downgraded to "mutate everything".
type MutationPolicy struct {
	Enabled bool
	Scope   ScopeGuard
	Mode    MutationMode
	Seed    int64
}

// SetMutationPolicy installs or removes the mutation pass on every path this
// runner owns. Nil/Disabled restores the legacy byte-exact pipeline.
func (r *Runner) SetMutationPolicy(p *MutationPolicy) error {
	if r == nil {
		return errors.New("probe: nil runner")
	}
	if p == nil || !p.Enabled {
		r.mutation = nil
		return nil
	}
	if p.Scope == nil {
		return errors.New("probe: mutation policy requires a scope guard")
	}
	copyPolicy := *p
	r.mutation = &copyPolicy
	return nil
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
	retries := r.ProxyRetries
	if retries == 0 {
		retries = 2
	}
	if retries < 0 {
		retries = 0
	}
	var (
		out    *Result
		runErr error
	)
	for attempt := 0; attempt <= retries; attempt++ {
		out, runErr = r.runOnce(ctx, target, p)
		// A fingerprint that cannot negotiate h2 is a local precondition
		// failure. Drop the baseline response so it cannot be mistaken for a
		// verdict, then retry on a fresh session with the next fingerprint.
		if errors.Is(runErr, ErrNoH2ALPN) {
			out = nil
		}
		if runErr == nil {
			return out, nil
		}
		if attempt == retries || ctx.Err() != nil {
			break
		}
		// A proxy-only failure says nothing about the target. Retry with a
		// freshly selected exit; a parsed response is never retried because it
		// would double-count a WAF verdict as training evidence.
		if !errors.Is(runErr, ErrNoH2ALPN) && !isRetryableProxyFailure(out, runErr) {
			break
		}
	}
	if errors.Is(runErr, util.ErrPrecisionLost) {
		return out, fmt.Errorf("probe %s: %w", p.Name(), runErr)
	}
	return out, runErr
}

func isRetryableProxyFailure(res *Result, err error) bool {
	if errors.Is(err, util.ErrPrecisionLost) || errors.Is(err, omnislash.ErrDeceptionUncertain) {
		return false
	}
	if res != nil && len(res.Responses) > 0 {
		return false
	}
	return omnislash.IsProxyTransportError(err)
}

func (r *Runner) runOnce(ctx context.Context, target Target, p Probe) (*Result, error) {
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
				tls:     r.tlsConfigFor(target),
				addr:    target.Addr,
				race:    isRaceProbe(p),
				runner:  r,
				ctx:     ctx,
				target:  target,
			}
			defer src.closeAll()
			out, runErr = mp.ExecuteMulti(ctx, target, src)
			if fault := src.finishAll(out, runErr); fault != nil {
				runErr = errors.Join(runErr, fault)
			}
			return runErr
		}
		session, conn, err := r.dial(ctx, target)
		if err != nil {
			return err
		}
		defer session.Close()
		guarded := r.guardConn(conn, isRaceProbe(p))
		defer guarded.Close()
		mutated := r.wrapMutation(ctx, target, guarded)
		out, runErr = p.Execute(ctx, target, mutatedConn(guarded, mutated))
		if mutated != nil {
			if fault := mutated.finish(out, runErr); fault != nil {
				runErr = errors.Join(runErr, fault)
			}
		}
		return runErr
	})
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

// tlsConfigFor keeps TLS bound to the original hostname even when the scope
// pins CONNECT to a literal IP. ServerName drives both SNI and certificate
// chain verification, so using the resolved address here would break IP SANs.
func (r *Runner) tlsConfigFor(target Target) *tls.Config {
	if r == nil || r.TLS == nil {
		return nil
	}
	cfg := r.TLS.Clone()
	if host := strings.TrimSpace(target.Host); host != "" && net.ParseIP(host) == nil {
		cfg.ServerName = host
	}
	return cfg
}

// takeWarm reuses a warmed tunnel only when it belongs to this session's
// pinned proxy. A tunnel from another exit would silently move the experiment
// to a different IP, which is forbidden.
func (r *Runner) takeWarm(ctx context.Context, session *omnislash.Session, target Target) (net.Conn, bool) {
	if r == nil || r.Warmer == nil || r.TLS == nil || session == nil || session.Proxy() == nil {
		return nil, false
	}
	// The warmer is keyed by the scope-checked host:port, not by the hostname:
	// resolve_locally may pin CONNECT to an IP while TLS still uses target.Host.
	addr := strings.TrimSpace(target.Addr)
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return nil, false
	}
	return r.Warmer.Take(ctx, addr, session.Proxy())
}

func (r *Runner) dialSession(ctx context.Context, session *omnislash.Session, target Target) (net.Conn, error) {
	if conn, ok := r.takeWarm(ctx, session, target); ok {
		return conn, nil
	}
	var conn net.Conn
	var err error
	if tlsCfg := r.tlsConfigFor(target); tlsCfg != nil {
		conn, err = session.DialTLSContext(ctx, "tcp", target.Addr, tlsCfg)
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
	ctx     context.Context
	target  Target

	mu       sync.Mutex
	conn     []net.Conn
	mutation []*mutationConn
}

func (s *sessionSource) Dial(ctx context.Context) (net.Conn, error) {
	if conn, ok := s.runner.takeWarm(ctx, s.session, s.target); ok {
		conn = s.runner.guardConn(conn, s.race)
		if mc := s.runner.wrapMutation(s.ctx, s.target, conn); mc != nil {
			conn = mc
			s.mu.Lock()
			s.mutation = append(s.mutation, mc)
			s.mu.Unlock()
		}
		s.mu.Lock()
		s.conn = append(s.conn, conn)
		s.mu.Unlock()
		return conn, nil
	}
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
		if mc := s.runner.wrapMutation(s.ctx, s.target, conn); mc != nil {
			conn = mc
			s.mu.Lock()
			s.mutation = append(s.mutation, mc)
			s.mu.Unlock()
		}
	}
	s.mu.Lock()
	s.conn = append(s.conn, conn)
	s.mu.Unlock()
	return conn, nil
}

// finishAll runs the FSM over every mutated connection in a multi-connection
// probe. A panic in the FSM is contained by safeAnalyze and returned as an
// ErrPrecisionLost fault; it is never allowed to escape the daemon.
func (s *sessionSource) finishAll(res *Result, runErr error) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	conns := s.mutation
	s.mutation = nil
	s.mu.Unlock()
	var fault error
	for _, mc := range conns {
		fault = errors.Join(fault, mc.finish(res, runErr))
	}
	return fault
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

const maxMutationFSMBytes = 4 << 20

// wrapMutation returns nil when no policy is installed, so all existing probes
// keep writing the exact bytes they built.
func (r *Runner) wrapMutation(ctx context.Context, target Target, conn net.Conn) *mutationConn {
	if r == nil || r.mutation == nil || !r.mutation.Enabled || conn == nil {
		return nil
	}
	m := &PayloadMutator{
		Scope:  r.mutation.Scope,
		Target: target.Addr,
		Mode:   r.mutation.Mode,
		Ctx:    ctx,
	}
	return newMutationConn(conn, m, r.mutation.Seed, &ParserStateMachine{})
}

func mutatedConn(base net.Conn, mc *mutationConn) net.Conn {
	if mc == nil {
		return base
	}
	return mc
}

// mutationConn is a net.Conn decorator. It is the only place where a probe's
// raw bytes are rewritten before conn.Write, and where raw response bytes are
// captured for the FSM. No net/http value is involved on either path.
type mutationConn struct {
	net.Conn

	mut  *PayloadMutator
	seed int64

	mu       sync.Mutex
	fsm      *ParserStateMachine
	resp     []byte
	readErr  error
	fault    error
	finished bool
}

func newMutationConn(conn net.Conn, mut *PayloadMutator, seed int64, fsm *ParserStateMachine) *mutationConn {
	return &mutationConn{Conn: conn, mut: mut, seed: seed, fsm: fsm}
}

func (c *mutationConn) Write(p []byte) (int, error) {
	if !looksLikeHTTP1Request(p) {
		// Binary frames (HTTP/2, WebSocket after upgrade) must never be
		// rewritten as an HTTP/1 header block.
		return c.Conn.Write(p)
	}
	c.mu.Lock()
	if c.fsm != nil && asciiContainsFold(p, "transfer-encoding:") {
		c.fsm.RequestHadTE = true
	}
	c.mu.Unlock()

	mutated, err := safeMutate(c.mut, p, c.seed)
	if err != nil {
		c.mu.Lock()
		if c.fault == nil {
			c.fault = err
		}
		c.mu.Unlock()
		return 0, err
	}
	return c.Conn.Write(mutated)
}

func (c *mutationConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.mu.Lock()
		if len(c.resp) < maxMutationFSMBytes {
			remaining := maxMutationFSMBytes - len(c.resp)
			if n > remaining {
				c.resp = append(c.resp, p[:remaining]...)
			} else {
				c.resp = append(c.resp, p[:n]...)
			}
		}
		c.mu.Unlock()
	}
	if err != nil {
		c.mu.Lock()
		if c.readErr == nil {
			c.readErr = err
		}
		c.mu.Unlock()
	}
	return n, err
}

// finish is called once per probe run. It stores the FSM verdict on Result and
// escalates FE_Closed_BE_Waiting to a high-confidence desync finding.
func (c *mutationConn) finish(res *Result, runErr error) error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	if c.finished {
		fault := c.fault
		c.mu.Unlock()
		return fault
	}
	c.finished = true
	fsm := c.fsm
	if fsm == nil {
		fsm = &ParserStateMachine{}
	}
	// Snapshot the FSM: RequestHadTE is written by Write and read here.
	local := *fsm
	raw := append([]byte(nil), c.resp...)
	readErr := c.readErr
	fault := c.fault
	c.mu.Unlock()

	observedErr := runErr
	if observedErr == nil {
		observedErr = readErr
	}
	state, analyzeFault := safeAnalyze(&local, raw, observedErr)
	if analyzeFault != nil {
		fault = errors.Join(fault, analyzeFault)
	}
	if res != nil {
		res.ParserDivergence = string(state)
		switch state {
		case ParserFEClosedBEWaiting:
			addFindingOnce(res, Finding{
				Kind:       "desync_confirmed",
				Confidence: ConfidenceHigh,
				Detail:     "frontend closed the connection while the backend was still waiting for a smuggled body",
			})
		case ParserEngineFault:
			addFindingOnce(res, Finding{
				Kind:       "engine_fault",
				Confidence: ConfidenceHigh,
				Detail:     "FSM classified the exchange as a local correctness failure",
			})
		}
	}
	return fault
}

// NetConn, Unwrap and ConnectionState keep the proxy/TLS introspection that
// probes and omnislash.ProxyOf rely on through this decorator.
func (c *mutationConn) NetConn() net.Conn { return c.Conn }
func (c *mutationConn) Unwrap() net.Conn  { return c.Conn }
func (c *mutationConn) ConnectionState() tls.ConnectionState {
	state, _ := omnislash.TLSState(c.Conn)
	return state
}

func addFindingOnce(res *Result, f Finding) {
	if res == nil {
		return
	}
	for _, existing := range res.Findings {
		if existing.Kind == f.Kind {
			return
		}
	}
	res.Findings = append(res.Findings, f)
}

func looksLikeHTTP1Request(p []byte) bool {
	if len(p) == 0 {
		return false
	}
	limit := len(p)
	if limit > 128 {
		limit = 128
	}
	head := string(p[:limit])
	space := strings.IndexByte(head, ' ')
	return space > 0 && space < 12 && strings.Contains(head, "HTTP/1.")
}
