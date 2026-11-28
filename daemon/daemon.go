package daemon

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"net/url"
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

// proxyWaiter is implemented by the production RunnerSet. It lets the daemon
// wait for the health checker instead of failing when every exit is cooling
// down. Test executors may omit it.
type proxyWaiter interface {
	WaitForProxy(ctx context.Context) error
}

// targetCooler is implemented by the production RunnerSet. It pauses only the
// target that produced a block burst; other jobs keep scanning.
type targetCooler interface {
	TargetCooling(host string) (time.Time, bool)
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

	mu       sync.Mutex
	states   map[string]*JobState
	auditMu  sync.Mutex
	learning *ExperienceStore
	// online is the streaming feedback loop and its hot-reload state. It is
	// nil when cfg.OnlineLearning is false.
	online *onlineRuntime
	// orchestrator is an opt-in top-level FSM. When set, it owns learning
	// feedback for parsed attempts; job order and success semantics stay intact.
	orchestrator *Orchestrator

	// observations counts real attempts and drives exponential epsilon decay.
	observations atomic.Int64
	// rollFn and shuffleFn are injectable so exploration can be tested without
	// depending on the global random source.
	rollFn    func() float64
	shuffleFn func(n int, swap func(i, j int))

	slots  chan struct{}
	wg     sync.WaitGroup
	cancel context.CancelFunc
	exit   atomic.Bool

	// ui carries the optional transport/scope context used by the embedded
	// dashboard registered on the control server.
	ui omnislash.UIOptions
	// redirect is built from ui by SetUI. It resolves root redirect stubs to
	// the real application path before the byte-exact probes run.
	redirect *redirectResolver

	// fullAuto is the safety-gated -full-auto runtime. Nil until enabled.
	fullAutoMu    sync.Mutex
	fullAuto      *fullAutoRuntime
	fullAutoScope FullAutoScope
	// impact is the optional ImpactValidator. The safe pipeline calls it only
	// when --force-impact was supplied; a finding never escalates on its own.
	impact ImpactValidator
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
		cfg:       *cfg,
		exec:      exec,
		log:       logger,
		audit:     audit,
		now:       time.Now,
		slots:     make(chan struct{}, conc),
		states:    make(map[string]*JobState, len(cfg.Jobs)),
		learning:  NewExperienceStore(""),
		rollFn:    rand.Float64,
		shuffleFn: rand.Shuffle,
	}
	if cfg.IsLearningEnabled() {
		d.learning = NewExperienceStore(cfg.LogFile)
		if err := d.learning.Load(); err != nil {
			logger.Warn("experience load failed", "path", cfg.LogFile, "error", err)
		}
		sources := append([]string(nil), cfg.LearningSources...)
		if err := d.learning.LoadFiles(sources); err != nil {
			logger.Warn("experience sources load failed", "sources", sources, "error", err)
		}
		logger.Info("experience loaded", "own_log", cfg.LogFile, "sources", sources, "cells", len(d.learning.Summary()))
	}
	for i := range cfg.Jobs {
		j := &cfg.Jobs[i]
		d.states[j.Name] = &JobState{Name: j.Name}
	}
	if cfg.IsOnlineLearningEnabled() {
		d.online = newOnlineRuntime(d, cfg)
	}
	return d, nil
}

// Learn adds curated playbook priors to the same ranking table as audit
// records. It is a no-op when learning is disabled. Seeds keep their own
// counters and provenance, so /experience never mistakes them for observations.
func (d *Daemon) Learn(seeds []ExperienceSeed) {
	if d == nil || d.learning == nil || !d.cfg.IsLearningEnabled() {
		return
	}
	d.learning.Seed(seeds)
}

// SetUI supplies the transport context used by the embedded control UI. It is
// optional: without it the dashboard still serves legacy status endpoints but
// reports unavailable actions honestly.
func (d *Daemon) SetUI(opts omnislash.UIOptions) {
	if d != nil {
		d.ui = opts
		d.redirect = nil
		if opts.Pool != nil && opts.Config != nil {
			dialer := omnislash.NewDialer(opts.Pool, d.log)
			transport := omnislash.NewRotatingTransport(opts.Pool, dialer, opts.Config.HTTP, d.log)
			timeout := opts.Config.HTTP.Timeout.Std()
			if timeout <= 0 {
				timeout = 5 * time.Second
			}
			client := &http.Client{
				Transport: transport,
				Timeout:   timeout,
				// Redirects are resolved one hop at a time so every Location
				// can be scope-checked before it is dialed.
				CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			}
			scope := opts.Scope
			if scope == nil {
				scope = opts.Pool.Scope()
			}
			d.redirect = newRedirectResolver(client, scope, opts.Config.Scope.AllowHosts, d.log)
		}
		d.configureMutation()
		if d.orchestrator != nil {
			d.orchestrator.SetCaidoPush(opts.CaidoPush)
		}
	}
}

// SetOrchestrator installs the top-level FSM. It is opt-in: without it the
// daemon keeps its existing per-attempt ranking and audit behavior verbatim.
func (d *Daemon) SetOrchestrator(o *Orchestrator) {
	if d != nil {
		d.orchestrator = o
		if o != nil {
			o.SetCaidoPush(d.ui.CaidoPush)
		}
	}
}

// EnableOrchestrator installs the top-level FSM with the daemon's existing
// experience store, online beta priors and transport pool. It stays explicit so
// legacy deployments keep their audit format verbatim; omnislashd exposes it
// as -orchestrator. No second learning table or socket is created here.
func (d *Daemon) EnableOrchestrator() *Orchestrator {
	if d == nil {
		return nil
	}
	provider := &ExperienceProvider{Store: d.learning, Online: d.online, Pool: d.ui.Pool}
	o := NewOrchestrator(provider, d.audit)
	d.SetOrchestrator(o)
	return o
}

// EnableFullAuto turns on the safe pipeline and guarantees that the
// self-learning FSM is attached. The flag is opt-in; without it the daemon's
// existing per-job behavior is unchanged.
func (d *Daemon) EnableFullAuto() error {
	if d == nil {
		return errors.New("daemon: nil receiver")
	}
	d.cfg.FullAuto.Enabled = true
	if d.orchestrator == nil {
		d.EnableOrchestrator()
	}
	if d.orchestrator == nil {
		return errors.New("daemon: full-auto requires an orchestrator")
	}
	// The differential-fuzz probe builds its own GET-only mutation inside the
	// probe. The runner-level pass would rewrite recon and smuggling bytes, so
	// full-auto removes it: every non-fuzz request stays byte-exact.
	if setter, ok := d.exec.(interface {
		SetMutationPolicy(*probe.MutationPolicy) error
	}); ok {
		if err := setter.SetMutationPolicy(nil); err != nil {
			return fmt.Errorf("daemon: full-auto cannot disable runner mutation: %w", err)
		}
	}
	return nil
}

// SetImpactValidator installs the optional impact check. It is invoked only
// when full_auto.force_impact is true; a confirmed finding is otherwise parked
// at AWAITING_HUMAN_VERIFICATION and no escalation request is sent.
func (d *Daemon) SetImpactValidator(v ImpactValidator) {
	if d != nil {
		d.impact = v
	}
}

// SetFullAutoScope overrides the scope used by the safe pipeline. Production
// uses the transport pool's scope; tests and embedders can supply a fake.
func (d *Daemon) SetFullAutoScope(s FullAutoScope) {
	if d != nil {
		d.fullAutoScope = s
	}
}

// configureMutation is the daemon-side integration point: the transport config
// decides whether the mutation pass is on, and the already-loaded Scope is the
// only guard allowed to authorize it. A missing scope disables mutations
// instead of letting raw bytes reach an unreviewed target.
func (d *Daemon) configureMutation() {
	if d == nil {
		return
	}
	setter, ok := d.exec.(interface {
		SetMutationPolicy(*probe.MutationPolicy) error
	})
	if !ok {
		return
	}
	policy := (*probe.MutationPolicy)(nil)
	if d.ui.Config != nil && d.ui.Scope != nil && d.ui.Config.Probe.MutationEnabled {
		policy = &probe.MutationPolicy{
			Enabled: true,
			Scope:   d.ui.Scope,
			Mode:    probe.MutationMode(d.ui.Config.Probe.MutationMode),
			Seed:    1, // stable across restarts: evidence stays reproducible
		}
	}
	if err := setter.SetMutationPolicy(policy); err != nil && d.log != nil {
		d.log.Warn("mutation policy refused", "error", err)
	}
}

// Run schedules jobs until ctx is cancelled or exit_on_success fires. A
// cancelled context is a clean shutdown, not an error.
func (d *Daemon) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	d.cancel = cancel
	defer cancel()

	if d.online != nil {
		d.online.start(ctx)
		if err := d.online.reload(true); err != nil {
			d.log.Warn("online state reload failed", "error", err)
		}
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			ticker := time.NewTicker(500 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if err := d.online.reload(false); err != nil {
						d.log.Warn("online state reload failed", "error", err)
					}
				}
			}
		}()
	}
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

// RunAdHoc executes one dashboard-originated probe on a scope-checked target.
// It records the attempt in the same JSONL audit as scheduled jobs so the
// finding journal and Caido export see it.
func (d *Daemon) RunAdHoc(ctx context.Context, req omnislash.UIRunRequest) (omnislash.UIRunResult, error) {
	if d == nil {
		return omnislash.UIRunResult{}, errors.New("daemon: nil receiver")
	}
	// The HTTP handler already applies this gate; repeat it here so any other
	// caller of RunAdHoc cannot bypass the fail-closed scope contract.
	if d.ui.Scope == nil || !d.ui.Scope.Enabled() {
		return omnislash.UIRunResult{}, errors.New("daemon: scope is disabled: quick run denied (fail-closed)")
	}
	if d.ui.Config == nil || len(d.ui.Config.Scope.AllowHosts) == 0 {
		return omnislash.UIRunResult{}, errors.New("daemon: scope.allow_hosts is empty: quick run denied (fail-closed)")
	}
	if host := uiQuickHost(req); !uiRunHostAllowed(host, d.ui.Config.Scope.AllowHosts) {
		return omnislash.UIRunResult{}, fmt.Errorf("daemon: target host %q is not in scope.allow_hosts", host)
	}
	checked, err := d.ui.Scope.CheckTarget(ctx, req.Target)
	if err != nil {
		return omnislash.UIRunResult{}, err
	}
	req.Target = checked
	job, err := uiQuickJob(req)
	if err != nil {
		return omnislash.UIRunResult{}, err
	}
	p, err := buildProbe(&job)
	if err != nil {
		return omnislash.UIRunResult{}, err
	}
	target, err := job.target()
	if err != nil {
		return omnislash.UIRunResult{}, err
	}
	res, err := d.exec.Run(ctx, target, p, job.tlsMode())
	success := jobSucceeded(&job, res, err)
	d.record(&job, 1, res, err, success)
	return uiQuickResult(req, res, err, success), nil
}

func uiQuickJob(req omnislash.UIRunRequest) (JobConfig, error) {
	job := JobConfig{
		Name:     "ui-quick-run",
		Attempts: 1,
		Timeout:  omnislash.Duration(10 * time.Second),
		Path:     req.Path,
		Target: TargetConfig{
			Addr: req.Target,
			Host: uiQuickHost(req),
			Path: req.Path,
		},
	}
	switch req.Probe {
	case "adaptive":
		job.Probe = "differential-fuzz"
		job.Pairs = 3
	case "smuggle-chain":
		job.Probe = "smuggle-chain"
		job.Variant = string(probe.VariantCLTE)
		job.VictimMethod = "GET"
		job.VictimPath = req.Path
	case "h2-cl":
		job.Probe = "h2-cl"
		job.TLS = "h2"
		job.Method = "GET"
		job.Path = req.Path
		job.VictimMethod = "GET"
		job.VictimPath = req.Path
	case "raw-replay":
		return job, errors.New("daemon: raw-replay quick run needs a payload; use a configured job")
	default:
		return job, fmt.Errorf("daemon: unsupported quick-run probe %q", req.Probe)
	}
	return job, nil
}

func uiQuickHost(req omnislash.UIRunRequest) string {
	original := strings.TrimSpace(req.Original)
	if original != "" {
		if host, _, err := net.SplitHostPort(original); err == nil {
			return host
		}
		if !strings.Contains(original, "://") {
			return strings.Trim(original, "[]")
		}
	}
	if host, _, err := net.SplitHostPort(req.Target); err == nil {
		return strings.Trim(host, "[]")
	}
	return req.Target
}

func uiRunHostAllowed(host string, rules []string) bool {
	host = strings.ToLower(strings.Trim(strings.TrimSpace(host), "[]"))
	if host == "" {
		return false
	}
	for _, rule := range rules {
		rule = strings.ToLower(strings.Trim(strings.TrimSpace(rule), "[]"))
		if rule == host {
			return true
		}
		if strings.HasPrefix(rule, "*.") && strings.HasSuffix(host, rule[1:]) {
			return true
		}
	}
	return false
}

func uiQuickResult(req omnislash.UIRunRequest, res *probe.Result, runErr error, success bool) omnislash.UIRunResult {
	out := omnislash.UIRunResult{
		Job:     "ui-quick-run",
		Probe:   req.Probe,
		Target:  req.Target,
		Success: success,
	}
	if runErr != nil {
		out.Error = runErr.Error()
		out.Message = "quick run failed"
	} else if success {
		out.Message = "quick run reached its goal"
	} else {
		out.Message = "quick run completed without a confirmed goal"
	}
	if res != nil {
		for _, finding := range res.Findings {
			out.Findings = append(out.Findings, finding.Kind+" ("+finding.Confidence+")")
		}
		for _, response := range res.Responses {
			out.Statuses = append(out.Statuses, response.Status)
		}
		if len(out.Findings) > 0 && runErr == nil && !success {
			out.Message = "quick run completed with findings"
		}
	}
	return out
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

// resolveProbeTarget walks a short 301/302 chain before the byte-exact probes
// so a root redirect stub does not receive every diagnostic request. A blocked
// or unsettled chain leaves the operator's target untouched.
func (d *Daemon) resolveProbeTarget(ctx context.Context, j *JobConfig, target Target) Target {
	if d == nil || d.redirect == nil || target.Addr == "" {
		return target
	}
	host := target.Host
	if host == "" {
		host = hostFromAddr(target.Addr)
	}
	scheme := "https"
	if j.tlsMode() == "none" {
		scheme = "http"
	}
	path := target.Path
	if path == "" {
		path = "/"
	}
	start := &url.URL{Scheme: scheme, Host: host, Path: path}
	settled := d.redirect.Resolve(ctx, start)
	if settled == nil || settled.Path == "" || settled.Path == path {
		return target
	}
	out := target
	out.Path = settled.Path
	if d.log != nil {
		d.log.Debug("redirect target resolved", "job", j.Name, "from", path, "to", out.Path)
	}
	return out
}

func (d *Daemon) execute(ctx context.Context, j *JobConfig) Outcome {
	target, err := j.target()
	if err != nil {
		return Outcome{Job: j.Name, Err: err}
	}
	target = d.resolveProbeTarget(ctx, j, target)
	host := target.Host
	if host == "" {
		host = hostFromAddr(target.Addr)
	}
	attempts := j.attempts()
	var last *probe.Result
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return Outcome{Job: j.Name, Result: last, Err: err}
		}
		// Graceful degradation: an empty or fully cooling pool is a wait for
		// the health checker, not a reason to stop the daemon or drop the
		// in-memory experience store.
		if waiter, ok := d.exec.(proxyWaiter); ok {
			if err := waiter.WaitForProxy(ctx); err != nil {
				return Outcome{Job: j.Name, Result: last, Err: err}
			}
		}
		// A target-wide block burst pauses only this host. The loop re-checks
		// because another concurrent job may have tripped it while we waited.
		if cooler, ok := d.exec.(targetCooler); ok {
			for {
				until, cooling := cooler.TargetCooling(host)
				if !cooling {
					break
				}
				wait := until.Sub(d.now())
				if wait <= 0 {
					break
				}
				d.log.Info("target cooling down", "job", j.Name, "host", host, "wait", wait)
				if err := sleepCtx(ctx, wait); err != nil {
					return Outcome{Job: j.Name, Result: last, Err: err}
				}
			}
		}
		// One epsilon decision for the whole attempt: all ranking stages either
		// explore or exploit. It is taken before any probe bytes are written.
		roll := d.exploration()
		// Learning changes the *attempt*, not the declared job: the original
		// config stays as the operator wrote it, while each attempt uses the
		// currently best-ranked variant or mutation.
		attemptJob := d.applyLearningWithRoll(j, roll)
		p, err := buildProbe(&attemptJob)
		if err != nil {
			d.recordAttempt(&attemptJob, attempt, nil, err, false, roll)
			return Outcome{Job: j.Name, Result: last, Err: err}
		}
		res, err := d.exec.Run(ctx, target, p, attemptJob.tlsMode())
		success := jobSucceeded(&attemptJob, res, err)
		d.recordAttempt(&attemptJob, attempt, res, err, success, roll)
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

// explorationRoll is decided once per attempt. Both ranking stages consume the
// same decision: either all of them explore, or all of them exploit. Taking an
// independent roll per stage would produce a ~22.5% exploration rate with
// epsilon=0.12 instead of the configured 10-15%.
type explorationRoll struct {
	explore bool
	epsilon float64
}

func (d *Daemon) epsilon() float64 {
	if d == nil || !d.cfg.IsLearningEnabled() {
		return 0
	}
	return d.cfg.LearningPolicy.epsilonAt(d.observations.Load())
}

func (d *Daemon) exploration() explorationRoll {
	epsilon := d.epsilon()
	if d == nil || d.rollFn == nil || epsilon <= 0 {
		return explorationRoll{}
	}
	return explorationRoll{explore: d.rollFn() < epsilon, epsilon: epsilon}
}

func (d *Daemon) exploreStrings(candidates []string) []string {
	out := append([]string(nil), candidates...)
	if d == nil || d.shuffleFn == nil || len(out) < 2 {
		return out
	}
	d.shuffleFn(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

func (d *Daemon) exploreInts(candidates []int) []int {
	out := append([]int(nil), candidates...)
	if d == nil || d.shuffleFn == nil || len(out) < 2 {
		return out
	}
	d.shuffleFn(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

// applyLearning returns a per-attempt copy with learned choices applied and no
// exploration. Tests and one-shot UI runs use the deterministic path.
func (d *Daemon) applyLearning(j *JobConfig) JobConfig {
	return d.applyLearningWithRoll(j, explorationRoll{})
}

// applyLearningWithRoll applies the single exploration decision to every
// ranking stage. The stored config is never mutated, so a human can always
// reproduce the exact declared experiment from the JSON file.
func (d *Daemon) applyLearningWithRoll(j *JobConfig, roll explorationRoll) JobConfig {
	c := *j
	if d == nil || d.learning == nil || !d.cfg.IsLearningEnabled() {
		return c
	}
	host := c.Target.Host
	if host == "" {
		host = hostFromAddr(c.Target.Addr)
	}
	tech := ""
	if len(c.TechStack) > 0 {
		tech = probe.TechStackHash(c.TechStack)
	}
	base := ExperienceKey{
		Host:      host,
		TLS:       c.tlsMode(),
		Probe:     c.Probe,
		TechStack: tech,
	}

	// Exploration bypasses every prior in every ranking stage. It is a single
	// decision for the whole attempt, so the effective rate stays at epsilon.
	if roll.explore {
		if len(c.DeclaredLengths) > 1 {
			c.DeclaredLengths = d.exploreInts(c.DeclaredLengths)
		}
		if c.Probe == "differential-fuzz" {
			candidates := c.Mutations
			if len(candidates) == 0 {
				mutator := probe.Mutator{TechStack: c.TechStack}
				for _, m := range mutator.Mutations() {
					candidates = append(candidates, m.Name)
				}
			}
			c.Mutations = d.exploreStrings(candidates)
		}
		if c.Variant == "auto" {
			var candidates []string
			switch c.Probe {
			case "smuggle":
				candidates = []string{string(probe.VariantCLTE), string(probe.VariantTECL), string(probe.VariantTETE)}
				if c.tlsMode() == "h2" {
					candidates = append(candidates, string(probe.VariantH2Downgrade))
				}
			case "smuggle-chain":
				candidates = []string{string(probe.VariantCLTE), string(probe.VariantTECL)}
			}
			if len(candidates) > 0 {
				c.Variant = d.exploreStrings(candidates)[0]
			}
		}
		if d.orchestrator != nil {
			// No GetBestAction ran for this roll: without clearing, record()
			// would attribute the result to the previous job's action.
			d.orchestrator.ClearLastAction()
		}
		return c
	}

	// The streaming loop hot-reloads weights between attempts. Its priors only
	// reorder declared candidates; they never invent a probe or a verdict.
	if d.online != nil && len(c.DeclaredLengths) > 1 {
		c.DeclaredLengths = d.online.rankCL(c.DeclaredLengths, host, tech)
	}

	if c.Probe == "differential-fuzz" {
		candidates := c.Mutations
		if len(candidates) == 0 {
			mutator := probe.Mutator{TechStack: c.TechStack}
			for _, m := range mutator.Mutations() {
				candidates = append(candidates, m.Name)
			}
		}
		c.Mutations = d.learning.RankMutations(base, candidates)
		if d.online != nil {
			c.Mutations = d.online.rank("mutation", c.Mutations, host, tech)
		}
	}

	if c.Variant == "auto" {
		var candidates []string
		switch c.Probe {
		case "smuggle":
			candidates = []string{string(probe.VariantCLTE), string(probe.VariantTECL), string(probe.VariantTETE)}
			if c.tlsMode() == "h2" {
				candidates = append(candidates, string(probe.VariantH2Downgrade))
			}
		case "smuggle-chain":
			candidates = []string{string(probe.VariantCLTE), string(probe.VariantTECL)}
		}
		if len(candidates) > 0 {
			ranked := d.learning.Rank(base, candidates)
			if d.online != nil {
				// Preserve the daemon's own experience order and let online
				// priors refine it, not replace it.
				ranked = d.online.rank("variant", ranked, host, tech)
			}
			c.Variant = ranked[0]
		}
	}
	// Opt-in top-level FSM: the final mutation is the brain's best declared
	// candidate. TLS fingerprints are pinned per Session by the transport, so
	// the chosen fingerprint is audited but the job's TLS mode is not rewritten.
	if !roll.explore && d.orchestrator != nil {
		var fingerprints []string
		if d.ui.Config != nil {
			fingerprints = d.ui.Config.TLSFingerprints
		}
		if action, err := d.orchestrator.GetBestAction(orchestratorProfile(&c, fingerprints)); err == nil && action.Mutation != "" {
			c.Mutations = []string{action.Mutation}
		}
	}
	return c
}

// learningMeta extracts the stable training label from an attempt. Full
// evidence remains in Result, which is also written to the audit line.
func learningMeta(j *JobConfig, res *probe.Result) LearningMeta {
	host := j.Target.Host
	if host == "" {
		host = hostFromAddr(j.Target.Addr)
	}
	tech := ""
	if len(j.TechStack) > 0 {
		tech = probe.TechStackHash(j.TechStack)
	}
	meta := LearningMeta{Host: host, Variant: j.Variant, TechStack: tech}
	if res != nil {
		meta.Mutation = res.Mutation
		for _, f := range res.Findings {
			if f.Confidence == probe.ConfidenceHigh || f.Confidence == probe.ConfidenceMedium {
				meta.Finding = f.Kind
				break
			}
		}
	}
	return meta
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
	Learning    LearningMeta      `json:"learning,omitempty"`
	// DeceptionUncertain is true when a mandatory semantic/NCD check could not
	// run. Such a record is an engine fault, never a clean target response.
	DeceptionUncertain bool `json:"deception_uncertain,omitempty"`
	// Outcome separates proxy failures from real target responses. It is the
	// only field the learning loop may use to decide whether to train.
	Outcome string `json:"outcome,omitempty"`
	Explore bool   `json:"explore,omitempty"`
	// ParserDivergence is the FSM verdict for this attempt. It is promoted from
	// Result so an audit reader does not have to descend into the raw exchange.
	ParserDivergence string        `json:"parser_divergence"`
	Result           *probe.Result `json:"result,omitempty"`
}

func (d *Daemon) record(j *JobConfig, attempt int, res *probe.Result, err error, success bool) {
	d.recordAttempt(j, attempt, res, err, success, explorationRoll{})
}

func (d *Daemon) recordAttempt(j *JobConfig, attempt int, res *probe.Result, err error, success bool, roll explorationRoll) {
	label := classifyOutcome(res, err)
	// A broken exit is evidence about the proxy, never about the technique.
	// It is written to the audit line but must not reach learning (FSM sonar,
	// reward deltas, Python online loop or learned_weights.json).
	proxyFailure := label == OutcomeProxyFailed || omnislash.IsProxyTransportError(err) ||
		(res != nil && len(res.Responses) == 0 && err != nil)
	if proxyFailure {
		success = false
	}
	rec := Record{
		Time:     d.now(),
		Job:      j.Name,
		Attempt:  attempt,
		Target:   j.Target.Addr,
		Probe:    j.Probe,
		TLS:      j.tlsMode(),
		Success:  success,
		Learning: learningMeta(j, res),
		Outcome:  string(label),
		Explore:  roll.explore,
	}
	if err != nil {
		rec.Error = err.Error()
		if errors.Is(err, omnislash.ErrDeceptionUncertain) {
			rec.DeceptionUncertain = true
		}
	}
	if res != nil {
		rec.DurationMS = float64(res.Duration.Microseconds()) / 1000
		rec.Attribution = res.Attribution
		// A registered FSM verdict must never be lost between the runner and
		// the audit line, even when the result came from a test executor.
		rec.ParserDivergence = res.ParserDivergence
		// A timing-only differential verdict is promoted only when the byte
		// FSM has no stronger result. Keeping both in sync makes the FSM feed
		// and the audit line agree on what was observed.
		if res.TimingDivergence == string(probe.ParserTimingDesync) &&
			(rec.ParserDivergence == "" || rec.ParserDivergence == string(probe.ParserSyncOK)) {
			rec.ParserDivergence = res.TimingDivergence
			res.ParserDivergence = rec.ParserDivergence
		}
		if res.ParserDivergence == string(probe.FEClosedBEWaiting) {
			hasDesync := false
			for _, f := range res.Findings {
				if f.Kind == "desync_confirmed" {
					hasDesync = true
					break
				}
			}
			if !hasDesync {
				res.Findings = append(res.Findings, probe.Finding{
					Kind:       "desync_confirmed",
					Confidence: probe.ConfidenceHigh,
					Detail:     "FSM classified the exchange as frontend closed / backend waiting",
				})
			}
		}
		if res.ParserDivergence == string(probe.EngineFault) {
			rec.Outcome = string(OutcomeEngineFault)
		}
		rec.Findings = res.Findings
		rec.Result = res
		for _, r := range res.Responses {
			rec.Statuses = append(rec.Statuses, r.Status)
		}
	}
	// The orchestrator's sonar sees the same result the audit log records. No
	// extra dial happens here: latency, NCD and entropy are derived from bytes
	// already captured by the probe.
	if !proxyFailure && d.orchestrator != nil {
		d.orchestrator.ObserveResult(res)
	}
	if d.audit != nil {
		line, marshalErr := json.Marshal(rec)
		if marshalErr == nil {
			d.auditMu.Lock()
			_, _ = d.audit.Write(append(line, '\n'))
			d.auditMu.Unlock()
		}
	}
	fedBack := false
	if !proxyFailure && d.orchestrator != nil {
		state, ok := parserStateOf(rec.ParserDivergence)
		if !ok && rec.Outcome == string(OutcomeEngineFault) {
			state, ok = probe.ParserEngineFault, true
		}
		if !ok {
			// No registered parser verdict still completes an FSM branch.
			// SyncOK carries the scalar status/NCD/Z evidence into RewardFor,
			// so a 400 reject or a quiet redirect cannot be dropped silently.
			state, ok = probe.ParserSyncOK, true
		}
		action := d.orchestrator.LastAction()
		if ok && action.TLSFingerprint != "" && action.Mutation != "" {
			if action.Proxy == "" && res != nil {
				action.Proxy = res.Attribution.Proxy
			}
			// The FSM owns this attempt's feedback, so the shared store is
			// observed exactly once through its provider.
			if err := d.orchestrator.RecordOutcome(action, state); err != nil && d.log != nil {
				d.log.Warn("orchestrator feedback failed", "error", err)
			}
			fedBack = true
		}
	}
	if !proxyFailure && !fedBack && d.learning != nil && d.cfg.IsLearningEnabled() {
		d.learning.Observe(rec)
	}
	// Decay is driven by observed attempts, not by wall clock: a quiet lab does
	// not keep exploring forever and a busy one settles faster. Proxy failures
	// are excluded so a dead public pool cannot rewrite learned weights.
	if !proxyFailure {
		d.observations.Add(1)
	}
	if d.log != nil {
		d.log.Debug("probe outcome", "job", j.Name, "attempt", attempt,
			"outcome", string(label), "trainable", label.Trainable(), "explore", roll.explore)
	}
}

func buildProbe(j *JobConfig) (probe.Probe, error) {
	timeout := j.Timeout.Std()
	idle := j.Idle.Std()
	switch j.Probe {
	case "smuggle-chain":
		return &probe.SmuggleChainProbe{
			Variant:         probe.SmuggleVariant(j.Variant),
			CarrierMethod:   j.Method,
			VictimMethod:    j.VictimMethod,
			VictimPath:      j.VictimPath,
			SmuggledMethod:  j.SmuggledMethod,
			SmuggledPath:    j.SmuggledPath,
			SmuggledHost:    j.SmuggledHost,
			SmuggledBody:    j.SmuggledBody,
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
		return &probe.SmugglingProbe{Variant: variant, Method: j.Method, Timeout: timeout, Idle: idle, BaselinePath: j.Path}, nil
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
	case "h2-cl":
		var body []byte
		if j.Body != "" {
			body = []byte(j.Body)
		}
		return &probe.H2CLProbe{
			DeclaredLength:       j.DeclaredLength,
			DeclaredLengths:      j.DeclaredLengths,
			Body:                 body,
			Method:               j.Method,
			Path:                 j.Path,
			Authority:            j.Authority,
			Scheme:               j.Scheme,
			SmuggledMethod:       j.SmuggledMethod,
			SmuggledPath:         j.SmuggledPath,
			SmuggledHost:         j.SmuggledHost,
			SmuggledBody:         j.SmuggledBody,
			SmuggledPrefix:       j.SmuggledPrefix,
			VictimMethod:         j.VictimMethod,
			VictimPath:           j.VictimPath,
			SameConnectionVictim: j.SameConnectionVictim,
			SkipVictim:           j.SkipVictim,
			HoldAfterPoison:      j.HoldAfterPoison.Std(),
			ReadExtraStream:      j.ReadExtraStream,
			SuccessContains:      j.SuccessContains,
			Attempts:             j.attempts(),
			RetryDelay:           j.RetryDelay.Std(),
			VictimDelay:          j.VictimDelay.Std(),
			Timeout:              timeout,
			Idle:                 idle,
		}, nil
	case "h2-tunnel":
		return &probe.H2TunnelProbe{
			PoisonPath:   j.PoisonPath,
			GadgetPath:   j.GadgetPath,
			Host:         j.Host,
			TunnelHost:   j.TunnelHost,
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
	mux.HandleFunc("/experience", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if d.learning == nil {
			_ = enc.Encode(map[string]any{"enabled": false, "cells": []ExperienceStat{}})
			return
		}
		_ = enc.Encode(map[string]any{"enabled": d.cfg.IsLearningEnabled(), "cells": d.learning.Summary()})
	})

	// The dashboard shares this control server; legacy JSON routes above stay
	// byte-compatible with existing health checks and lab scripts.
	ui := d.ui
	if len(ui.AuditPaths) == 0 && d.cfg.LogFile != "" {
		ui.AuditPaths = []string{d.cfg.LogFile}
	}
	ui.Status = func() any { return map[string]any{"jobs": d.Status()} }
	ui.Experience = func() any {
		if d.learning == nil {
			return map[string]any{"enabled": false, "cells": []ExperienceStat{}}
		}
		return map[string]any{"enabled": d.cfg.IsLearningEnabled(), "cells": d.learning.Summary()}
	}
	ui.Run = d.RunAdHoc
	if d.online != nil {
		ui.OnlineOptions = d.online.opts
		ui.OnlineStatus = d.online.snapshot
		ui.OnlineToggle = d.online.toggle
		ui.OnlineFeedback = d.online.feedback
	}
	omnislash.RegisterUI(mux, ui)

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
	None   *probe.Runner
	H1     *probe.Runner
	H2     *probe.Runner
	dialer *omnislash.Dialer

	warmMu sync.Mutex
	warmer *omnislash.TunnelWarmer
}

// NewRunnerSet builds the three runners from one dialer.
func NewRunnerSet(d *omnislash.Dialer) *RunnerSet {
	return &RunnerSet{None: probe.NewRunner(d), H1: probe.NewRunner(d), H2: probe.NewRunner(d), dialer: d}
}

// WaitForProxy implements the daemon's graceful-degradation hook.
func (s *RunnerSet) WaitForProxy(ctx context.Context) error {
	if s == nil || s.dialer == nil {
		return nil
	}
	return s.dialer.WaitForProxy(ctx)
}

// TargetCooling implements the daemon's per-target pause hook.
func (s *RunnerSet) TargetCooling(host string) (time.Time, bool) {
	if s == nil || s.dialer == nil {
		return time.Time{}, false
	}
	return s.dialer.TargetCooling(host)
}

// EnableTunnelWarmer opts TLS runners into a shared tunnel reserve for one
// active target. addr must be host:port and sni must be the original hostname;
// keeping them separate is what makes resolve_locally safe. The warmer is
// stopped by cancelling ctx and its sockets are closed by CloseTunnelWarmer.
func (s *RunnerSet) EnableTunnelWarmer(ctx context.Context, addr, sni string, tlsCfg *tls.Config) error {
	if s == nil || s.dialer == nil || s.H1 == nil || s.H2 == nil {
		return errors.New("daemon: runner set has no TLS runners")
	}
	s.warmMu.Lock()
	defer s.warmMu.Unlock()
	if s.warmer == nil {
		s.warmer = omnislash.NewTunnelWarmer(s.dialer, 0, 0)
	}
	s.warmer.SetTLSConfig(tlsCfg)
	s.H1.Warmer = s.warmer
	s.H2.Warmer = s.warmer
	s.warmer.Start(ctx, addr, sni)
	return nil
}

// CloseTunnelWarmer releases every warmed socket. Calling it is safe even when
// warming was never enabled.
func (s *RunnerSet) CloseTunnelWarmer() {
	if s == nil {
		return
	}
	s.warmMu.Lock()
	w := s.warmer
	s.warmer = nil
	s.warmMu.Unlock()
	if w != nil {
		w.Close()
	}
}

// SetLimits applies the transport config's probe section to every TLS mode.
// The fixed race deadline is passed separately and is never derived from a
// per-job timeout.
func (s *RunnerSet) SetLimits(cfg omnislash.ProbeConfig) {
	if s == nil {
		return
	}
	for _, r := range []*probe.Runner{s.None, s.H1, s.H2} {
		if r != nil {
			r.SetLimits(cfg.MaxResponseBytes, cfg.ReadTimeout.Std(), cfg.RaceReadTimeout.Std())
		}
	}
}

// SetMutationPolicy applies the same scoped policy to every TLS mode. A policy
// without a scope guard is rejected by Runner, so all three modes fail closed.
func (s *RunnerSet) SetMutationPolicy(p *probe.MutationPolicy) error {
	if s == nil {
		return errors.New("daemon: nil runner set")
	}
	var errs []error
	for _, r := range []*probe.Runner{s.None, s.H1, s.H2} {
		if r != nil {
			errs = append(errs, r.SetMutationPolicy(p))
		}
	}
	return errors.Join(errs...)
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
