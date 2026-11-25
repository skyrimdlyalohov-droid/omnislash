package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
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

	mu       sync.Mutex
	states   map[string]*JobState
	auditMu  sync.Mutex
	learning *ExperienceStore
	// online is the streaming feedback loop and its hot-reload state. It is
	// nil when cfg.OnlineLearning is false.
	online *onlineRuntime

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
	// Outcome separates proxy failures from real target responses. It is the
	// only field the learning loop may use to decide whether to train.
	Outcome string        `json:"outcome,omitempty"`
	Explore bool          `json:"explore,omitempty"`
	Result  *probe.Result `json:"result,omitempty"`
}

func (d *Daemon) record(j *JobConfig, attempt int, res *probe.Result, err error, success bool) {
	d.recordAttempt(j, attempt, res, err, success, explorationRoll{})
}

func (d *Daemon) recordAttempt(j *JobConfig, attempt int, res *probe.Result, err error, success bool, roll explorationRoll) {
	label := classifyOutcome(res, err)
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
	if d.learning != nil && d.cfg.IsLearningEnabled() {
		d.learning.Observe(rec)
	}
	// Decay is driven by observed attempts, not by wall clock: a quiet lab does
	// not keep exploring forever and a busy one settles faster.
	d.observations.Add(1)
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
