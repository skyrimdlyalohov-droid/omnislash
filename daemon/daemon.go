package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/skyrimdlyalohov-droid/omnislash"
	"github.com/skyrimdlyalohov-droid/omnislash/probe"
)

// Executor runs one probe with the transport chosen by tlsMode ("none", "h1",
// "h2"). The production implementation is a set of probe.Runner values sharing
// one dialer; tests can substitute a fake.
type Executor interface {
	Run(ctx context.Context, target probe.Target, p probe.Probe, tlsMode string) (*probe.Result, error)
}

// JobState is the runtime view of one job.
type JobState struct {
	Name        string    `json:"name"`
	Runs        int       `json:"runs"`
	Successes   int       `json:"successes"`
	Running     bool      `json:"running"`
	Done        bool      `json:"done"`
	LastRun     time.Time `json:"last_run,omitempty"`
	LastSuccess bool      `json:"last_success"`
	LastError   string    `json:"last_error,omitempty"`
	NextRun     time.Time `json:"next_run,omitempty"`
}

// Outcome is the result of one scheduled execution (all attempts included).
type Outcome struct {
	Job     string        `json:"job"`
	Success bool          `json:"success"`
	Result  *probe.Result `json:"result,omitempty"`
	Err     error         `json:"-"`
}

// Daemon schedules probe jobs until the context is cancelled or a job succeeds
// with ExitOnSuccess set.
type Daemon struct {
	cfg   Config
	exec  Executor
	log   *slog.Logger
	audit io.Writer
	now   func() time.Time

	mu      sync.Mutex
	states  map[string]*JobState
	auditMu sync.Mutex

	slots  chan struct{}
	wg     sync.WaitGroup
	cancel context.CancelFunc
	exit   atomic.Bool
}

// New validates cfg and prepares the scheduler. audit may be nil.
func New(cfg *Config, exec Executor, logger *slog.Logger, audit io.Writer) (*Daemon, error) {
	if cfg == nil {
		return nil, errors.New("daemon: nil config")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if exec == nil {
		return nil, errors.New("daemon: executor is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	conc := cfg.Concurrency
	if conc <= 0 {
		conc = 1
	}
	d := &Daemon{
		cfg:    *cfg,
		exec:   exec,
		log:    logger,
		audit:  audit,
		now:    time.Now,
		slots:  make(chan struct{}, conc),
		states: make(map[string]*JobState, len(cfg.Jobs)),
	}
	for i := range cfg.Jobs {
		j := &cfg.Jobs[i]
		d.states[j.Name] = &JobState{Name: j.Name}
	}
	return d, nil
}

// Run schedules jobs until ctx is cancelled or exit_on_success fires. A
// cancelled context is a clean shutdown, not an error.
func (d *Daemon) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	d.cancel = cancel
	defer cancel()

	if d.cfg.ControlAddr != "" {
		d.serveControl(ctx)
	}

	poll := d.cfg.PollInterval.Std()
	if poll <= 0 {
		poll = 2 * time.Second
	}
	d.schedule(ctx)
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			d.wg.Wait()
			return nil
		case <-ticker.C:
			d.schedule(ctx)
			if d.exit.Load() {
				d.wg.Wait()
				return nil
			}
		}
	}
}

// RunOnce executes every enabled job once, sequentially. It is the CI mode and
// the lab reproduction mode; interval and exit_on_success are ignored.
func (d *Daemon) RunOnce(ctx context.Context) []Outcome {
	out := make([]Outcome, 0, len(d.cfg.Jobs))
	for i := range d.cfg.Jobs {
		j := d.cfg.Jobs[i]
		if !j.IsEnabled() {
			continue
		}
		out = append(out, d.execute(ctx, &j))
	}
	return out
}

// RunJob executes one named job once. It is used by the command line -job flag.
func (d *Daemon) RunJob(ctx context.Context, name string) (Outcome, error) {
	for i := range d.cfg.Jobs {
		j := &d.cfg.Jobs[i]
		if j.Name != name {
			continue
		}
		return d.execute(ctx, j), nil
	}
	return Outcome{}, fmt.Errorf("daemon: unknown job %q", name)
}

// Status returns a copy of every job state.
func (d *Daemon) Status() []JobState {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]JobState, 0, len(d.states))
	for i := range d.cfg.Jobs {
		if st, ok := d.states[d.cfg.Jobs[i].Name]; ok {
			out = append(out, *st)
		}
	}
	return out
}

func (d *Daemon) schedule(ctx context.Context) {
	now := d.now()
	type due struct {
		job JobConfig
	}
	var batch []due
	d.mu.Lock()
	for i := range d.cfg.Jobs {
		j := &d.cfg.Jobs[i]
		if !j.IsEnabled() {
			continue
		}
		st := d.states[j.Name]
		if st.Running || st.Done {
			continue
		}
		if !st.NextRun.IsZero() && now.Before(st.NextRun) {
			continue
		}
		st.Running = true
		batch = append(batch, due{job: *j})
	}
	d.mu.Unlock()

	for _, b := range batch {
		d.wg.Add(1)
		go func(j JobConfig) {
			defer d.wg.Done()
			select {
			case d.slots <- struct{}{}:
				defer func() { <-d.slots }()
			case <-ctx.Done():
				d.finish(j.Name, Outcome{Job: j.Name, Err: ctx.Err()}, false)
				return
			}
			out := d.execute(ctx, &j)
			d.finish(j.Name, out, out.Success)
		}(b.job)
	}
}

func (d *Daemon) finish(name string, out Outcome, success bool) {
	j := d.job(name)
	d.mu.Lock()
	st := d.states[name]
	st.Running = false
	st.LastRun = d.now()
	st.LastSuccess = success
	st.Runs++
	if success {
		st.Successes++
		st.LastError = ""
	} else if out.Err != nil {
		st.LastError = out.Err.Error()
	}
	if success && j != nil && j.UntilSuccess {
		st.Done = true
	}
	interval := 30 * time.Second
	if j != nil {
		interval = j.interval()
	}
	st.NextRun = d.now().Add(interval)
	d.mu.Unlock()

	if success && d.cfg.ExitOnSuccess {
		d.exit.Store(true)
		if d.cancel != nil {
			d.cancel()
		}
	}
}

func (d *Daemon) job(name string) *JobConfig {
	for i := range d.cfg.Jobs {
		if d.cfg.Jobs[i].Name == name {
			return &d.cfg.Jobs[i]
		}
	}
	return nil
}

func (d *Daemon) execute(ctx context.Context, j *JobConfig) Outcome {
	target, err := j.target()
	if err != nil {
		return Outcome{Job: j.Name, Err: err}
	}
	attempts := j.attempts()
	var last *probe.Result
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return Outcome{Job: j.Name, Result: last, Err: err}
		}
		p, err := buildProbe(j)
		if err != nil {
			d.record(j, attempt, nil, err, false)
			return Outcome{Job: j.Name, Result: last, Err: err}
		}
		res, err := d.exec.Run(ctx, target, p, j.tlsMode())
		success := jobSucceeded(j, res, err)
		d.record(j, attempt, res, err, success)
		last, lastErr = res, err
		if success {
			d.log.Info("job succeeded", "job", j.Name, "attempt", attempt)
			return Outcome{Job: j.Name, Success: true, Result: res}
		}
		if attempt < attempts {
			if err := sleepCtx(ctx, j.retryDelay()); err != nil {
				return Outcome{Job: j.Name, Result: last, Err: err}
			}
		}
	}
	d.log.Warn("job finished without success", "job", j.Name, "attempts", attempts, "error", lastErr)
	return Outcome{Job: j.Name, Result: last, Err: lastErr}
}

// jobSucceeded decides whether one probe run met the declared goal. With a
// marker the check is exact: the marker must appear in a response body, header
// or reason. Without a marker the job succeeds when the probe completed without
// an error; the operator reads the evidence.
func jobSucceeded(j *JobConfig, res *probe.Result, err error) bool {
	if err != nil || res == nil {
		return false
	}
	if j.SuccessFinding != "" {
		found := false
		for _, f := range res.Findings {
			if f.Kind == j.SuccessFinding {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	marker := strings.ToLower(strings.TrimSpace(j.SuccessContains))
	if marker == "" {
		return true
	}
	for _, r := range res.Responses {
		if strings.Contains(strings.ToLower(r.Body), marker) ||
			strings.Contains(strings.ToLower(r.Reason), marker) {
			return true
		}
		for _, h := range r.Headers {
			if strings.Contains(strings.ToLower(h.Value), marker) {
				return true
			}
		}
	}
	return false
}

// Record is one JSONL audit line.
type Record struct {
	Time        time.Time         `json:"time"`
	Job         string            `json:"job"`
	Attempt     int               `json:"attempt"`
	Target      string            `json:"target"`
	Probe       string            `json:"probe"`
	TLS         string            `json:"tls"`
	Success     bool              `json:"success"`
	Error       string            `json:"error,omitempty"`
	DurationMS  float64           `json:"duration_ms,omitempty"`
	Attribution probe.Attribution `json:"attribution"`
	Findings    []probe.Finding   `json:"findings,omitempty"`
	Statuses    []int             `json:"statuses,omitempty"`
	Result      *probe.Result     `json:"result,omitempty"`
}

func (d *Daemon) record(j *JobConfig, attempt int, res *probe.Result, err error, success bool) {
	rec := Record{
		Time:    d.now(),
		Job:     j.Name,
		Attempt: attempt,
		Target:  j.Target.Addr,
		Probe:   j.Probe,
		TLS:     j.tlsMode(),
		Success: success,
	}
	if err != nil {
		rec.Error = err.Error()
	}
	if res != nil {
		rec.DurationMS = float64(res.Duration.Microseconds()) / 1000
		rec.Attribution = res.Attribution
		rec.Findings = res.Findings
		rec.Result = res
		for _, r := range res.Responses {
			rec.Statuses = append(rec.Statuses, r.Status)
		}
	}
	if d.audit != nil {
		line, marshalErr := json.Marshal(rec)
		if marshalErr == nil {
			d.auditMu.Lock()
			_, _ = d.audit.Write(append(line, '\n'))
			d.auditMu.Unlock()
		}
	}
}

func buildProbe(j *JobConfig) (probe.Probe, error) {
	timeout := j.Timeout.Std()
	idle := j.Idle.Std()
	switch j.Probe {
	case "smuggle-chain":
		return &probe.SmuggleChainProbe{
			VictimMethod:    j.VictimMethod,
			VictimPath:      j.VictimPath,
			SuccessContains: j.SuccessContains,
			Attempts:        j.attempts(),
			Timeout:         timeout,
			Idle:            idle,
		}, nil
	case "smuggle":
		variant := probe.SmuggleVariant(j.Variant)
		if variant == "" {
			variant = probe.VariantCLTE
		}
		return &probe.SmugglingProbe{Variant: variant, Timeout: timeout, Idle: idle, BaselinePath: j.Path}, nil
	case "race":
		return &probe.RaceProbe{
			Count:     j.Count,
			Method:    j.Method,
			Path:      j.Path,
			Timeout:   timeout,
			Idle:      idle,
			SingleUse: j.SingleUse,
		}, nil
	case "h2race":
		return &probe.H2RaceProbe{
			Count:     j.Count,
			Method:    j.Method,
			Path:      j.Path,
			Timeout:   timeout,
			Idle:      idle,
			SingleUse: j.SingleUse,
		}, nil
	case "h2-tunnel":
		return &probe.H2TunnelProbe{
			PoisonPath:   j.PoisonPath,
			GadgetPath:   j.GadgetPath,
			PaddingPaths: j.PaddingPaths,
			Marker:       j.SuccessContains,
			Timeout:      timeout,
			Idle:         idle,
		}, nil
	case "differential-fuzz":
		pairs := j.Pairs
		if pairs <= 0 {
			pairs = 5
		}
		jitter := j.JitterMaxIQR.Std()
		if jitter <= 0 {
			jitter = 25 * time.Millisecond
		}
		hold := j.Hold.Std()
		if hold <= 0 {
			hold = 50 * time.Millisecond
		}
		ncd := j.NeighborShiftNCD
		if ncd <= 0 {
			ncd = 0.6
		}
		return &probe.DifferentialFuzzProbe{
			Mutations:        j.Mutations,
			TechStack:        j.TechStack,
			Pairs:            pairs,
			JitterMaxIQR:     jitter,
			Hold:             hold,
			Timeout:          timeout,
			NeighborShiftNCD: ncd,
		}, nil
	case "raw-replay":
		return &probe.RawReplayProbe{
			RawPayloadB64:   j.RawPayloadB64,
			RawPayloadHex:   j.RawPayloadHex,
			SuccessContains: j.SuccessContains,
			Timeout:         timeout,
		}, nil
	case "upgrade-desync":
		return &probe.UpgradeDesyncProbe{
			UpgradeType:     j.UpgradeType,
			Path:            j.Path,
			SuccessContains: j.SuccessContains,
			Timeout:         timeout,
		}, nil
	default:
		return nil, fmt.Errorf("daemon: unsupported probe %q", j.Probe)
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (d *Daemon) serveControl(ctx context.Context) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{"jobs": d.Status()})
	})
	srv := &http.Server{Addr: d.cfg.ControlAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			d.log.Error("control server stopped", "addr", d.cfg.ControlAddr, "error", err)
		}
	}()
	d.log.Info("control server listening", "addr", d.cfg.ControlAddr)
}

// RunnerSet is the production Executor: one probe.Runner per TLS mode, all
// sharing a single omnislash Dialer and therefore one pool.
type RunnerSet struct {
	None *probe.Runner
	H1   *probe.Runner
	H2   *probe.Runner
}

// NewRunnerSet builds the three runners from one dialer.
func NewRunnerSet(d *omnislash.Dialer) *RunnerSet {
	return &RunnerSet{None: probe.NewRunner(d), H1: probe.NewRunner(d), H2: probe.NewRunner(d)}
}

// Run implements Executor.
func (s *RunnerSet) Run(ctx context.Context, target probe.Target, p probe.Probe, tlsMode string) (*probe.Result, error) {
	switch tlsMode {
	case "none":
		return s.None.Run(ctx, target, p)
	case "h2":
		return s.H2.Run(ctx, target, p)
	default:
		return s.H1.Run(ctx, target, p)
	}
}
