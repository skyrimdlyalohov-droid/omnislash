package daemon

// full_auto.go implements the opt-in -full-auto pipeline:
//
//	recon (GET) -> DeceptionFilter/NCD -> Scope.CheckTarget
//	  -> self-learning TLS/mutation choice
//	  -> differential-fuzz + smuggling with GET carriers
//	  -> STOP at AWAITING_HUMAN_VERIFICATION
//
// The pipeline owns no second transport and no second learning table. It uses
// the daemon's Executor, the transport pool's Scope and the existing
// Orchestrator/ExperienceStore, so every decision is auditable and every
// request still travels through one pinned proxy session.
//
// Safety rules that are enforced here, not merely documented:
//   - scope must be enabled, allow_private must be false and allow_direct false;
//   - RFC1918/loopback/link-local literals are refused before a dial;
//   - a honeypot/tarpit response bans the host for the session;
//   - the global probe interval is one second by default;
//   - 429/503 (and 403 by default) stop the target for five minutes;
//   - a confirmed FE_Closed_BE_Waiting/desync_confirmed parks the FSM at
//     AWAITING_HUMAN_VERIFICATION and saves the PoC as raw + base64;
//   - /pay and /admin are refused unless --force-impact is present;
//   - ImpactValidator is never called without --force-impact.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/skyrimdlyalohov-droid/omnislash"
	"github.com/skyrimdlyalohov-droid/omnislash/probe"
)

var (
	// ErrFullAutoDisabled means the pipeline was called without enabling it.
	ErrFullAutoDisabled = errors.New("daemon: full-auto is not enabled")
	// ErrFullAutoScope means the scope is disabled, allows private addresses,
	// allows direct egress or has an empty allowlist. The pipeline never
	// degrades to an unchecked mode.
	ErrFullAutoScope = errors.New("daemon: full-auto requires an enabled, non-private scope")
	// ErrFullAutoCooldown means a WAF/rate-limit status paused the target.
	ErrFullAutoCooldown = errors.New("daemon: full-auto target is cooling down")
	// ErrFullAutoHoneypot means the deception filter flagged the target.
	ErrFullAutoHoneypot = errors.New("daemon: full-auto target is a honeypot/tarpit")
	// ErrFullAutoImpact means an escalation path was requested without the
	// manual --force-impact flag.
	ErrFullAutoImpact = errors.New("daemon: full-auto impact path requires --force-impact")
)

// ImpactValidator is the optional escalation check. The safe pipeline calls it
// only when ForceImpact is true; a confirmed finding is otherwise parked for a
// human and no impact request is sent.
type ImpactValidator interface {
	Validate(ctx context.Context, finding probe.Finding, poc []byte) error
}

// FullAutoScope is the fail-closed scope contract used by the pipeline.
// *omnislash.Scope implements it.
type FullAutoScope interface {
	Enabled() bool
	CheckTarget(ctx context.Context, target string) (string, error)
}

// FullAutoResult is one target's verdict. A finding never implies escalation:
// State is AWAITING_HUMAN_VERIFICATION until an operator reviews the PoC.
type FullAutoResult struct {
	Target   string            `json:"target"`
	Host     string            `json:"host"`
	State    OrchestratorState `json:"orchestrator_state"`
	Phase    OrchestratorPhase `json:"fsm_phase,omitempty"`
	Finding  *probe.Finding    `json:"finding,omitempty"`
	POCB64   string            `json:"poc_b64,omitempty"`
	POCRaw   string            `json:"poc_raw,omitempty"`
	POCHex   string            `json:"poc_hex,omitempty"`
	POCPath  string            `json:"poc_path,omitempty"`
	Attempts int               `json:"attempts"`
	Reason   string            `json:"reason,omitempty"`
	Error    string            `json:"error,omitempty"`
}

// FullAutoEvent is one JSONL line per safe-pipeline action. The
// "orchestrator_state" field is part of the audit contract and is present even
// when the daemon has no other audit writer configured.
type FullAutoEvent struct {
	Time              time.Time          `json:"time"`
	Target            string             `json:"target"`
	Host              string             `json:"host"`
	OrchestratorState OrchestratorState  `json:"orchestrator_state"`
	FSMPhase          OrchestratorPhase  `json:"fsm_phase,omitempty"`
	Probe             string             `json:"probe,omitempty"`
	Attempt           int                `json:"attempt,omitempty"`
	TLS               string             `json:"tls,omitempty"`
	Mutation          string             `json:"mutation,omitempty"`
	MutationMode      probe.MutationMode `json:"mutation_mode,omitempty"`
	Statuses          []int              `json:"statuses,omitempty"`
	Outcome           string             `json:"outcome,omitempty"`
	Reason            string             `json:"reason,omitempty"`
	ForceImpact       bool               `json:"force_impact"`
	POCB64            string             `json:"poc_b64,omitempty"`
	POCRaw            string             `json:"poc_raw,omitempty"`
	POCHex            string             `json:"poc_hex,omitempty"`
	POCPath           string             `json:"poc_path,omitempty"`
}

type fullAutoRuntime struct {
	cfg     FullAutoConfig
	filter  *omnislash.DeceptionFilter
	limiter *fullAutoLimiter
	scope   FullAutoScope

	cooldownMu sync.Mutex
	cooldowns  map[string]time.Time

	blockMu sync.Mutex
	blocks  map[string]int
}

type fullAutoLimiter struct {
	mu       sync.Mutex
	next     time.Time
	interval time.Duration
}

func newFullAutoLimiter(interval time.Duration) *fullAutoLimiter {
	return &fullAutoLimiter{interval: interval}
}

// wait reserves the next global slot. The reservation is taken before the
// sleep so concurrent pipelines cannot bunch up at the same instant.
func (l *fullAutoLimiter) wait(ctx context.Context) error {
	if l == nil || l.interval <= 0 {
		return nil
	}
	l.mu.Lock()
	now := time.Now()
	if l.next.Before(now) {
		l.next = now
	}
	wait := l.next.Sub(now)
	l.next = l.next.Add(l.interval)
	l.mu.Unlock()
	if wait <= 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// ensureFullAuto lazily builds the runtime from the daemon config. It is
// deliberately fail-closed: no scope, no pipeline.
func (d *Daemon) ensureFullAuto() (*fullAutoRuntime, error) {
	d.fullAutoMu.Lock()
	defer d.fullAutoMu.Unlock()
	if d.fullAuto != nil {
		return d.fullAuto, nil
	}
	cfg := d.cfg.FullAuto.withDefaults()
	scope := d.fullAutoScope
	if scope == nil {
		scope = d.ui.Scope
	}
	if scope == nil {
		return nil, fmt.Errorf("%w: no scope attached", ErrFullAutoScope)
	}
	dcfg := omnislash.DeceptionConfig{
		Enabled:         true,
		BaselineSamples: cfg.BaselineSamples,
		Action:          "mark",
		TargetBanTTL:    cfg.WAFCooldown,
	}
	if d.ui.Config != nil {
		dcfg = d.ui.Config.Safety.Deception
	}
	// Full-auto always runs the deception filter. An operator may tune it, but
	// may not silently disable the honeypot/tarpit gate.
	dcfg.Enabled = true
	if dcfg.Action == "" {
		dcfg.Action = "mark"
	}
	if dcfg.BaselineSamples <= 0 {
		dcfg.BaselineSamples = cfg.BaselineSamples
	}
	if dcfg.TargetBanTTL <= 0 {
		dcfg.TargetBanTTL = cfg.WAFCooldown
	}
	rt := &fullAutoRuntime{
		cfg:       cfg,
		filter:    omnislash.NewDeceptionFilter(dcfg, d.log),
		limiter:   newFullAutoLimiter(cfg.RateLimit.Std()),
		scope:     scope,
		cooldowns: make(map[string]time.Time),
		blocks:    make(map[string]int),
	}
	d.fullAuto = rt
	return rt, nil
}

// ExecuteSafePipeline runs one target through the safety-gated pipeline. It is
// safe to call directly from an embedder; -full-auto calls it through
// RunFullAuto for every declared target.
func (d *Daemon) ExecuteSafePipeline(ctx context.Context, target Target) (FullAutoResult, error) {
	if d == nil {
		return FullAutoResult{}, errors.New("daemon: nil receiver")
	}
	cfg := d.cfg.FullAuto.withDefaults()
	if !cfg.Enabled {
		return FullAutoResult{}, ErrFullAutoDisabled
	}
	if d.ui.Config == nil {
		return FullAutoResult{}, fmt.Errorf("%w: transport config is required", ErrFullAutoScope)
	}
	if d.ui.Config.Scope.AllowPrivate {
		return FullAutoResult{}, fmt.Errorf("%w: allow_private must be false", ErrFullAutoScope)
	}
	if d.ui.Config.AllowDirect {
		return FullAutoResult{}, fmt.Errorf("%w: allow_direct must be false", ErrFullAutoScope)
	}
	if len(d.ui.Config.Scope.AllowHosts) == 0 {
		return FullAutoResult{}, fmt.Errorf("%w: scope.allow_hosts is empty", ErrFullAutoScope)
	}
	if d.orchestrator == nil {
		d.EnableOrchestrator()
	}
	if d.orchestrator == nil {
		return FullAutoResult{}, errors.New("daemon: full-auto requires an orchestrator")
	}
	rt, err := d.ensureFullAuto()
	if err != nil {
		return FullAutoResult{}, err
	}
	if !rt.scope.Enabled() {
		return FullAutoResult{}, fmt.Errorf("%w: scope.enabled is false", ErrFullAutoScope)
	}
	host := fullAutoHost(target)
	if host == "" {
		return FullAutoResult{}, errors.New("daemon: full-auto target host is required")
	}
	if fullAutoPrivateLiteral(host) {
		return FullAutoResult{
			Target: target.Addr,
			Host:   host,
			State:  StateBlocked,
			Reason: "private/loopback/link-local literal",
		}, fmt.Errorf("%w: %s is a private address", ErrFullAutoScope, host)
	}
	checked, err := rt.scope.CheckTarget(ctx, target.Addr)
	if err != nil {
		return FullAutoResult{Target: target.Addr, Host: host, State: StateBlocked}, fmt.Errorf("%w: %v", ErrFullAutoScope, err)
	}
	target.Addr = checked
	run := &fullAutoRun{d: d, rt: rt, cfg: cfg, target: target, host: host}
	mutations, err := run.allowedMutations()
	if err != nil {
		run.writeEvent(FullAutoEvent{
			Time: d.now(), Target: target.Addr, Host: host,
			OrchestratorState: StateBlocked,
			Reason:            err.Error(),
		})
		return run.result(StateBlocked, err.Error()), err
	}
	run.mutations = mutations

	if decision, banned := rt.filter.TargetBanned(host); banned {
		run.writeEvent(FullAutoEvent{
			Time: d.now(), Target: target.Addr, Host: host,
			OrchestratorState: StateBlocked,
			Reason:            "target banned for this session: " + decision.Reason,
		})
		return run.result(StateBlocked, "target banned: "+decision.Reason),
			fmt.Errorf("%w: %s", ErrFullAutoHoneypot, decision.Reason)
	}

	if until, cooling := rt.cooling(host, d.now()); cooling {
		run.writeEvent(FullAutoEvent{
			Time: d.now(), Target: target.Addr, Host: host,
			OrchestratorState: StateCooldown,
			Reason:            fmt.Sprintf("target cooling down until %s", until.Format(time.RFC3339)),
		})
		return run.result(StateCooldown, "target cooling down"), fmt.Errorf("%w: until %s", ErrFullAutoCooldown, until.Format(time.RFC3339))
	}
	if cfg.impactPath(target.Path) && !cfg.ForceImpact {
		run.writeEvent(FullAutoEvent{
			Time: d.now(), Target: target.Addr, Host: host,
			OrchestratorState: StateBlocked,
			Reason:            "impact path blocked without --force-impact: " + target.Path,
			ForceImpact:       cfg.ForceImpact,
		})
		return run.result(StateBlocked, "impact path blocked"), fmt.Errorf("%w: %s", ErrFullAutoImpact, target.Path)
	}

	profile := run.profile("differential-fuzz", "")
	if err := d.orchestrator.StartRecon(profile); err != nil {
		run.writeEvent(FullAutoEvent{
			Time: d.now(), Target: target.Addr, Host: host,
			OrchestratorState: StateBlocked,
			Reason:            "recon refused: " + err.Error(),
		})
		return run.result(StateBlocked, "recon refused"), err
	}
	run.writeEvent(FullAutoEvent{
		Time: d.now(), Target: target.Addr, Host: host,
		OrchestratorState: StateRecon,
		FSMPhase:          d.orchestrator.Phase(),
		Probe:             "recon",
		Reason:            "scope checked; starting GET recon",
	})

	if err := run.recon(ctx); err != nil {
		state := StateBlocked
		if errors.Is(err, ErrFullAutoCooldown) {
			state = StateCooldown
		}
		out := run.result(state, err.Error())
		out.Error = err.Error()
		return out, err
	}

	ncd := 0.0
	if len(run.samples) >= 2 {
		ncd = omnislash.NormalizedCompressionDistance(run.samples[0], run.samples[1])
	}
	if err := d.orchestrator.Calibrate(ncd, false); err != nil {
		out := run.result(StateBlocked, "baseline refused: "+err.Error())
		out.Error = err.Error()
		return out, err
	}
	if run.baselineSet {
		d.orchestrator.SetBaseline(run.baseline, run.baselineStatus)
	}
	run.writeEvent(FullAutoEvent{
		Time: d.now(), Target: target.Addr, Host: host,
		OrchestratorState: StateBaseline,
		FSMPhase:          d.orchestrator.Phase(),
		Probe:             "recon",
		Reason:            fmt.Sprintf("NCD baseline calibrated (ncd=%.3f)", ncd),
	})

	out, err := run.attack(ctx)
	if err != nil {
		out.Error = err.Error()
	}
	return out, err
}

// RunFullAuto executes the safe pipeline for every configured target. It stops
// the whole run as soon as one target reaches AWAITING_HUMAN_VERIFICATION; a
// per-target scope/honeypot/cooldown stop does not abort the other targets.
func (d *Daemon) RunFullAuto(ctx context.Context) ([]FullAutoResult, error) {
	if d == nil {
		return nil, errors.New("daemon: nil receiver")
	}
	if !d.cfg.FullAuto.Enabled {
		return nil, ErrFullAutoDisabled
	}
	targets := d.fullAutoTargets()
	if len(targets) == 0 {
		return nil, errors.New("daemon: full-auto has no targets")
	}
	out := make([]FullAutoResult, 0, len(targets))
	for _, target := range targets {
		res, err := d.ExecuteSafePipeline(ctx, target)
		if err != nil {
			if res.Target == "" {
				res.Target = target.Addr
			}
			if res.State == "" {
				res.State = StateBlocked
			}
			res.Error = err.Error()
			d.log.Warn("full-auto target stopped", "target", target.Addr, "state", res.State, "error", err)
		}
		out = append(out, res)
		if res.State == StateAwaitingHumanVerification {
			break
		}
	}
	return out, nil
}

type fullAutoRun struct {
	d      *Daemon
	rt     *fullAutoRuntime
	cfg    FullAutoConfig
	target Target
	host   string

	mutations      []string
	samples        [][]byte
	baseline       []byte
	baselineStatus int
	baselineSet    bool
	attempts       int
}

func (run *fullAutoRun) profile(probeName, variant string) TargetProfile {
	return TargetProfile{
		Host:               run.host,
		Addr:               run.target.Addr,
		Probe:              probeName,
		Variant:            variant,
		TechStack:          append([]string(nil), run.cfg.TechStack...),
		Endpoints:          append([]string(nil), run.cfg.Endpoints...),
		TLSCandidates:      append([]string(nil), run.cfg.TLSCandidates...),
		MutationCandidates: append([]string(nil), run.mutations...),
	}
}

// getOnlyMutation reports whether the mutation's wire bytes use GET. The two
// historical framing mutations (cl_te_duplicate, te_obfuscation) emit POST and
// are therefore excluded unless the endpoint is explicitly listed in
// safe_post_paths.
func getOnlyMutation(name string) bool {
	switch strings.TrimSpace(name) {
	case "chunk_extensions", "boundary_shift",
		"ctl_nul", "ctl_tab", "ctl_vtab", "ctl_ff", "ctl_del",
		"unpaired_cr", "unpaired_lf", "space_before_colon":
		return true
	default:
		return false
	}
}

// allowedMutations is the per-target fail-closed filter. A config that lists
// only POST-only mutations on a read-only endpoint stops before recon instead
// of silently changing state.
func (run *fullAutoRun) allowedMutations() ([]string, error) {
	postAllowed := run.cfg.safePOST(run.target.Path)
	out := make([]string, 0, len(run.cfg.MutationCandidates))
	for _, raw := range run.cfg.MutationCandidates {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		if getOnlyMutation(name) || postAllowed {
			out = append(out, name)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: no GET-only mutation candidate for %s (POST carriers require safe_post_paths)", ErrFullAutoScope, run.target.Path)
	}
	return out, nil
}

// recon performs the GET-only discovery pass. It calibrates the deception
// baseline, checks every endpoint through DeceptionFilter and keeps the first
// clean body as the NCD reference for the orchestrator.
func (run *fullAutoRun) recon(ctx context.Context) error {
	if run.rt.filter != nil && run.rt.filter.Enabled() {
		if _, err := run.rt.filter.EnsureBaseline(ctx, "https://"+run.host, "/", run.deceptionRequest); err != nil {
			return fmt.Errorf("deception baseline: %w", err)
		}
		if d, ok := run.rt.filter.IsFlagged(run.host, "/"); ok {
			run.rt.filter.BanTarget(run.host, "/", d.Reason, d.Kind, run.cfg.WAFCooldown.Std())
			run.writeEvent(FullAutoEvent{
				Time: run.d.now(), Target: run.target.Addr, Host: run.host,
				OrchestratorState: StateBlocked,
				Probe:             "recon",
				Reason:            "honeypot/tarpit baseline: " + d.Reason,
			})
			return fmt.Errorf("%w: %s", ErrFullAutoHoneypot, d.Reason)
		}
	}
	for _, endpoint := range run.cfg.Endpoints {
		path := endpoint
		if path == "" {
			path = "/"
		}
		if run.cfg.impactPath(path) && !run.cfg.ForceImpact {
			run.writeEvent(FullAutoEvent{
				Time: run.d.now(), Target: run.target.Addr, Host: run.host,
				OrchestratorState: StateBlocked,
				Probe:             "recon",
				Reason:            "impact path blocked without --force-impact: " + path,
				ForceImpact:       run.cfg.ForceImpact,
			})
			continue
		}
		for sample := 0; sample < run.cfg.BaselineSamples; sample++ {
			t := run.target
			t.Path = path
			p := &fullAutoReconProbe{Path: path, Timeout: run.cfg.Timeout.Std()}
			res, err := run.runOnce(ctx, t, p)
			run.attempts++
			run.writeEvent(run.eventFor(StateRecon, "recon", AttackAction{}, res, err))
			if err != nil {
				return fmt.Errorf("recon %s: %w", path, err)
			}
			status, body, contentType, latency, err := fullAutoLastResponse(res)
			if err != nil {
				return fmt.Errorf("recon %s: %w", path, err)
			}
			if err := run.checkStatus(status); err != nil {
				return err
			}
			if run.rt.filter != nil && run.rt.filter.Enabled() {
				decision, ferr := run.rt.filter.InspectResponseWithContentType(run.host, path, status, body, contentType, latency)
				if ferr != nil {
					return fmt.Errorf("deception check %s: %w", path, ferr)
				}
				if decision.Flagged {
					run.rt.filter.BanTarget(run.host, path, decision.Reason, decision.Kind, run.cfg.WAFCooldown.Std())
					run.writeEvent(FullAutoEvent{
						Time: run.d.now(), Target: run.target.Addr, Host: run.host,
						OrchestratorState: StateBlocked,
						Probe:             "recon",
						Reason:            "honeypot/tarpit: " + decision.Reason,
					})
					return fmt.Errorf("%w: %s", ErrFullAutoHoneypot, decision.Reason)
				}
			}
			if sample == 0 {
				run.baseline = append([]byte(nil), body...)
				run.baselineStatus = status
				run.baselineSet = true
			}
			run.samples = append(run.samples, append([]byte(nil), body...))
		}
	}
	return nil
}

// attack runs differential-fuzz first and smuggling only while no confirmed
// finding exists. Every probe is recorded through the daemon's normal
// recordAttempt path so the audit, learning table and orchestrator all agree.
func (run *fullAutoRun) attack(ctx context.Context) (FullAutoResult, error) {
	profile := run.profile("differential-fuzz", "")
	action, err := run.d.orchestrator.GetBestAction(profile)
	if err != nil {
		return run.result(StateBlocked, "orchestrator refused differential-fuzz: "+err.Error()), err
	}
	fuzz := &probe.DifferentialFuzzProbe{
		Mutations: []string{action.Mutation},
		TechStack: append([]string(nil), run.cfg.TechStack...),
		Pairs:     run.cfg.Pairs,
		Timeout:   run.cfg.Timeout.Std(),
	}
	res, err := run.probe(ctx, "differential-fuzz", fuzz, action)
	if err != nil {
		return run.result(run.stateForError(err), err.Error()), err
	}
	if finding, ok := fullAutoFinding(res); ok {
		return run.finishFinding(ctx, finding, res, action)
	}

	for _, variant := range run.cfg.SmuggleVariants {
		profile = run.profile("smuggle", variant)
		action, err = run.d.orchestrator.GetBestAction(profile)
		if err != nil {
			return run.result(StateBlocked, "orchestrator refused smuggle: "+err.Error()), err
		}
		smuggle := &probe.SmugglingProbe{
			Variant:      probe.SmuggleVariant(variant),
			Method:       "GET",
			Timeout:      run.cfg.Timeout.Std(),
			Idle:         run.cfg.Idle.Std(),
			BaselinePath: run.target.Path,
		}
		res, err = run.probe(ctx, "smuggle", smuggle, action)
		if err != nil {
			return run.result(run.stateForError(err), err.Error()), err
		}
		if finding, ok := fullAutoFinding(res); ok {
			return run.finishFinding(ctx, finding, res, action)
		}
	}
	return run.result(StateFeedback, "no confirmed desync"), nil
}

func (run *fullAutoRun) probe(ctx context.Context, name string, p probe.Probe, action AttackAction) (*probe.Result, error) {
	run.attempts++
	res, err := run.runOnce(ctx, run.target, p)
	job := run.job(name, action)
	success := err == nil && res != nil && len(res.Responses) > 0
	run.d.recordAttempt(job, action.Attempt, res, err, success, explorationRoll{})
	run.writeEvent(run.eventFor(StateAttack, name, action, res, err))
	if err != nil {
		return res, err
	}
	if res == nil || len(res.Responses) == 0 {
		return res, fmt.Errorf("full-auto: %s returned no response", name)
	}
	for _, response := range res.Responses {
		if serr := run.checkStatus(response.Status); serr != nil {
			return res, serr
		}
	}
	return res, nil
}

func (run *fullAutoRun) finishFinding(ctx context.Context, finding probe.Finding, res *probe.Result, action AttackAction) (FullAutoResult, error) {
	poc := fullAutoPOC(res, action.Probe)
	pocB64 := base64.StdEncoding.EncodeToString(poc)
	pocPath, pocErr := run.d.writeFullAutoPOC(run.host, poc)
	run.d.orchestrator.AwaitHumanVerification(run.host, "confirmed "+finding.Kind+"; waiting for human verification", finding)

	ev := run.eventFor(StateAwaitingHumanVerification, action.Probe, action, res, nil)
	ev.Reason = "confirmed " + finding.Kind + "; impact validation is blocked until a human reviews the PoC"
	ev.POCB64 = pocB64
	ev.POCPath = pocPath
	if utf8.Valid(poc) {
		ev.POCRaw = string(poc)
	} else {
		ev.POCHex = hex.EncodeToString(poc)
	}
	if pocErr != nil {
		ev.Reason += "; poc write failed: " + pocErr.Error()
	}
	run.writeEvent(ev)

	out := run.result(StateAwaitingHumanVerification, ev.Reason)
	out.Finding = &finding
	out.POCB64 = pocB64
	out.POCPath = pocPath
	out.POCRaw = ev.POCRaw
	out.POCHex = ev.POCHex

	// The only path to impact validation is the explicit manual flag. Without
	// it, the pipeline returns here even when a validator is installed.
	if run.cfg.ForceImpact {
		if run.d.impact == nil {
			out.Reason += "; impact validator is not configured"
		} else if verr := run.d.impact.Validate(ctx, finding, poc); verr != nil {
			out.Reason += "; impact validator: " + verr.Error()
		}
	}
	return out, nil
}

func (run *fullAutoRun) runOnce(ctx context.Context, target Target, p probe.Probe) (*probe.Result, error) {
	if err := run.rt.limiter.wait(ctx); err != nil {
		return nil, err
	}
	return run.d.exec.Run(ctx, target, p, run.cfg.TLS)
}

func (run *fullAutoRun) job(name string, action AttackAction) *JobConfig {
	j := &JobConfig{
		Name:      "full-auto/" + name,
		Target:    TargetConfig{Addr: run.target.Addr, Host: run.target.Host, Path: run.target.Path},
		Probe:     name,
		TLS:       run.cfg.TLS,
		Variant:   action.Variant,
		Method:    "GET",
		Timeout:   run.cfg.Timeout,
		Idle:      run.cfg.Idle,
		TechStack: append([]string(nil), run.cfg.TechStack...),
		Pairs:     run.cfg.Pairs,
	}
	if name == "differential-fuzz" {
		j.Mutations = []string{action.Mutation}
	}
	return j
}

func (run *fullAutoRun) checkStatus(status int) error {
	for _, stop := range run.cfg.StopStatuses {
		if status == stop {
			return run.cooldown(status)
		}
	}
	for _, block := range run.cfg.BlockStatuses {
		if status != block {
			continue
		}
		run.rt.blockMu.Lock()
		run.rt.blocks[run.host]++
		count := run.rt.blocks[run.host]
		run.rt.blockMu.Unlock()
		if count >= run.cfg.BlockThreshold {
			return run.cooldown(status)
		}
	}
	return nil
}

func (run *fullAutoRun) cooldown(status int) error {
	until := run.d.now().Add(run.cfg.WAFCooldown.Std())
	run.rt.cooldownMu.Lock()
	run.rt.cooldowns[run.host] = until
	run.rt.cooldownMu.Unlock()
	run.writeEvent(FullAutoEvent{
		Time: run.d.now(), Target: run.target.Addr, Host: run.host,
		OrchestratorState: StateCooldown,
		Probe:             "waf",
		Statuses:          []int{status},
		Reason:            fmt.Sprintf("status %d; target paused until %s", status, until.Format(time.RFC3339)),
		ForceImpact:       run.cfg.ForceImpact,
	})
	return fmt.Errorf("%w: status %d until %s", ErrFullAutoCooldown, status, until.Format(time.RFC3339))
}

func (run *fullAutoRun) stateForError(err error) OrchestratorState {
	switch {
	case errors.Is(err, ErrFullAutoCooldown):
		return StateCooldown
	case errors.Is(err, ErrFullAutoHoneypot):
		return StateBlocked
	default:
		return StateBlocked
	}
}

func (run *fullAutoRun) result(state OrchestratorState, reason string) FullAutoResult {
	phase := OrchestratorPhase("")
	if run.d.orchestrator != nil {
		phase = run.d.orchestrator.Phase()
	}
	return FullAutoResult{
		Target:   run.target.Addr,
		Host:     run.host,
		State:    state,
		Phase:    phase,
		Attempts: run.attempts,
		Reason:   reason,
	}
}

func (run *fullAutoRun) eventFor(state OrchestratorState, probeName string, action AttackAction, res *probe.Result, err error) FullAutoEvent {
	ev := FullAutoEvent{
		Time:              run.d.now(),
		Target:            run.target.Addr,
		Host:              run.host,
		OrchestratorState: state,
		Probe:             probeName,
		Attempt:           run.attempts,
		TLS:               action.TLSFingerprint,
		Mutation:          action.Mutation,
		MutationMode:      action.MutationMode,
		ForceImpact:       run.cfg.ForceImpact,
	}
	if run.d.orchestrator != nil {
		ev.FSMPhase = run.d.orchestrator.Phase()
	}
	if res != nil {
		for _, response := range res.Responses {
			ev.Statuses = append(ev.Statuses, response.Status)
		}
		ev.Outcome = string(classifyOutcome(res, err))
	}
	if err != nil {
		ev.Reason = err.Error()
	}
	return ev
}

func (run *fullAutoRun) writeEvent(ev FullAutoEvent) {
	if run.d.log != nil {
		run.d.log.Info("full-auto",
			"orchestrator_state", string(ev.OrchestratorState),
			"host", ev.Host, "probe", ev.Probe, "reason", ev.Reason,
			"statuses", ev.Statuses)
	}
	if run.d.audit == nil {
		return
	}
	line, err := json.Marshal(ev)
	if err != nil {
		return
	}
	run.d.auditMu.Lock()
	_, _ = run.d.audit.Write(append(line, '\n'))
	run.d.auditMu.Unlock()
}

// deceptionRequest adapts the byte-exact recon probe to the DeceptionFilter's
// baseline callback. Only loopback analysis happens here; no request bypasses
// the pinned session.
func (run *fullAutoRun) deceptionRequest(ctx context.Context, rawURL string) (*http.Response, time.Duration, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, 0, err
	}
	t := run.target
	t.Path = u.RequestURI()
	if t.Path == "" {
		t.Path = "/"
	}
	p := &fullAutoReconProbe{Path: t.Path, Timeout: run.cfg.Timeout.Std()}
	res, err := run.runOnce(ctx, t, p)
	run.attempts++
	run.writeEvent(run.eventFor(StateRecon, "deception-baseline", AttackAction{}, res, err))
	if err != nil {
		return nil, 0, err
	}
	if res == nil || len(res.Responses) == 0 {
		return nil, 0, errors.New("deception baseline: no response")
	}
	r := res.Responses[len(res.Responses)-1]
	if err := run.checkStatus(r.Status); err != nil {
		return nil, 0, err
	}
	header := make(http.Header, len(r.Headers))
	for _, h := range r.Headers {
		header.Add(h.Key, h.Value)
	}
	return &http.Response{
		StatusCode: r.Status,
		Status:     fmt.Sprintf("%d %s", r.Status, r.Reason),
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(r.Body)),
		Request:    &http.Request{URL: u},
	}, res.Duration, nil
}

func (rt *fullAutoRuntime) cooling(host string, now time.Time) (time.Time, bool) {
	rt.cooldownMu.Lock()
	defer rt.cooldownMu.Unlock()
	until, ok := rt.cooldowns[host]
	if !ok {
		return time.Time{}, false
	}
	if !now.Before(until) {
		delete(rt.cooldowns, host)
		return time.Time{}, false
	}
	return until, true
}

func (d *Daemon) fullAutoTargets() []Target {
	cfg := d.cfg.FullAuto.withDefaults()
	seen := make(map[string]bool)
	var out []Target
	add := func(t Target) {
		key := t.Addr + "|" + t.Host + "|" + t.Path
		if t.Addr == "" || seen[key] {
			return
		}
		seen[key] = true
		out = append(out, t)
	}
	for _, raw := range cfg.Targets {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		t := Target{Addr: raw, Host: raw, Path: "/"}
		if host, _, err := net.SplitHostPort(raw); err == nil {
			t.Host = host
		}
		add(t)
	}
	if len(out) > 0 {
		return out
	}
	for i := range d.cfg.Jobs {
		j := &d.cfg.Jobs[i]
		if !j.IsEnabled() {
			continue
		}
		path := j.Target.Path
		if path == "" {
			path = "/"
		}
		add(Target{Addr: j.Target.Addr, Host: j.Target.Host, Path: path})
	}
	return out
}

func (d *Daemon) writeFullAutoPOC(host string, raw []byte) (string, error) {
	if len(raw) == 0 {
		return "", errors.New("empty PoC")
	}
	dir := d.cfg.FullAuto.withDefaults().PoCDir
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	name := fmt.Sprintf("%s-%d.http", sanitizeFullAutoName(host), d.now().UnixNano())
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func sanitizeFullAutoName(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	var b strings.Builder
	for _, r := range host {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "target"
	}
	return b.String()
}

func fullAutoHost(t Target) string {
	h := strings.TrimSpace(t.Host)
	if h == "" {
		h = t.Addr
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.ToLower(strings.Trim(h, "[]"))
}

func fullAutoPrivateLiteral(host string) bool {
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()
}

func fullAutoFinding(res *probe.Result) (probe.Finding, bool) {
	if res == nil {
		return probe.Finding{}, false
	}
	if res.ParserDivergence == string(probe.FEClosedBEWaiting) {
		for _, f := range res.Findings {
			if f.Kind == "desync_confirmed" {
				return f, true
			}
		}
		return probe.Finding{
			Kind:       "desync_confirmed",
			Confidence: probe.ConfidenceHigh,
			Detail:     "FSM classified the exchange as frontend closed / backend waiting",
		}, true
	}
	for _, f := range res.Findings {
		switch f.Kind {
		case "desync_confirmed", "upgrade_desync_confirmed":
			return f, true
		}
	}
	return probe.Finding{}, false
}

func fullAutoPOC(res *probe.Result, probeName string) []byte {
	if res == nil {
		return nil
	}
	if probeName == "differential-fuzz" {
		for i := len(res.Exchanges) - 1; i >= 0; i-- {
			if strings.Contains(res.Exchanges[i].Raw, "Transfer-Encoding") {
				return []byte(res.Exchanges[i].Raw)
			}
		}
		if n := len(res.Exchanges); n > 0 {
			return []byte(res.Exchanges[n-1].Raw)
		}
		if n := len(res.Payloads); n > 0 {
			return []byte(res.Payloads[n-1])
		}
		return nil
	}
	if n := len(res.Exchanges); n > 0 {
		return []byte(res.Exchanges[0].Raw)
	}
	if n := len(res.Payloads); n > 0 {
		return []byte(res.Payloads[0])
	}
	return nil
}

func fullAutoLastResponse(res *probe.Result) (int, []byte, string, time.Duration, error) {
	if res == nil || len(res.Responses) == 0 {
		return 0, nil, "", 0, errors.New("no response")
	}
	r := res.Responses[len(res.Responses)-1]
	contentType := ""
	for _, h := range r.Headers {
		if strings.EqualFold(h.Key, "Content-Type") {
			contentType = h.Value
			break
		}
	}
	return r.Status, []byte(r.Body), contentType, res.Duration, nil
}

// fullAutoReconProbe is a minimal, byte-exact GET. It exists so recon never
// depends on net/http and never changes state on the target.
type fullAutoReconProbe struct {
	Path    string
	Timeout time.Duration
	MaxBody int64
}

func (p *fullAutoReconProbe) Name() string { return "fullauto/recon" }

func (p *fullAutoReconProbe) Execute(ctx context.Context, target probe.Target, conn net.Conn) (*probe.Result, error) {
	path := p.Path
	if path == "" {
		path = "/"
	}
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline)
	raw := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: omnislash-fullauto/1\r\nAccept: */*\r\nConnection: close\r\n\r\n", path, target.HostHeader())
	start := time.Now()
	if _, err := conn.Write([]byte(raw)); err != nil {
		return nil, err
	}
	maxBody := p.MaxBody
	if maxBody <= 0 {
		maxBody = 1 << 20
	}
	var buf bytes.Buffer
	chunk := make([]byte, 32<<10)
	for int64(buf.Len()) < maxBody+64<<10 {
		n, err := conn.Read(chunk)
		if n > 0 {
			buf.Write(chunk[:n])
		}
		if err != nil {
			break
		}
	}
	if buf.Len() == 0 {
		return nil, errors.New("recon: empty response")
	}
	response := parseFullAutoResponse(buf.Bytes())
	return &probe.Result{
		Probe:     p.Name(),
		Target:    target.Addr,
		StartedAt: start,
		Duration:  time.Since(start),
		Exchanges: []probe.Exchange{{
			Seq: 1, At: 0, Raw: raw, Bytes: len(raw),
		}},
		Responses: []probe.Response{response},
	}, nil
}

func parseFullAutoResponse(raw []byte) probe.Response {
	resp := probe.Response{Raw: string(raw), Framing: "raw"}
	head, body, ok := bytes.Cut(raw, []byte("\r\n\r\n"))
	if !ok {
		resp.Body = string(raw)
		return resp
	}
	lines := bytes.Split(head, []byte("\r\n"))
	if len(lines) > 0 {
		parts := bytes.SplitN(lines[0], []byte(" "), 3)
		if len(parts) >= 2 {
			resp.Version = string(parts[0])
			resp.Status, _ = strconv.Atoi(string(parts[1]))
			if len(parts) == 3 {
				resp.Reason = string(parts[2])
			}
		}
	}
	for _, line := range lines[1:] {
		key, value, ok := bytes.Cut(line, []byte(":"))
		if !ok {
			continue
		}
		resp.Headers = append(resp.Headers, probe.Header{
			Key:   string(key),
			Value: strings.TrimSpace(string(value)),
		})
	}
	resp.Body = string(body)
	return resp
}
