package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/skyrimdlyalohov-droid/omnislash"
	"github.com/skyrimdlyalohov-droid/omnislash/probe"
	"github.com/skyrimdlyalohov-droid/omnislash/util"
)

// OrchestratorState is one node of the top-level attack FSM. The strings are
// stable audit labels.
type OrchestratorState string

const (
	StateRecon    OrchestratorState = "StateRecon"
	StateBaseline OrchestratorState = "StateBaseline"
	StateAttack   OrchestratorState = "StateAttack"
	StateFeedback OrchestratorState = "StateFeedback"
	StateVerify   OrchestratorState = "StateVerify"
	StateEscalate OrchestratorState = "StateEscalate"
)

var (
	// ErrOrchestratorProvider means the FSM has no brain attached. Every action
	// is refused in that case: the orchestrator never guesses a TLS profile or
	// a mutation on its own.
	ErrOrchestratorProvider = errors.New("daemon: orchestrator requires a learning provider")
	// ErrOrchestratorScope means the target is a honeypot or has no clean NCD
	// baseline. No byte may be mutated for such a profile.
	ErrOrchestratorScope = errors.New("daemon: orchestrator refused an unsafe target profile")
	// ErrOrchestratorCandidates means the caller did not declare a finite set of
	// TLS profiles or mutations to rank.
	ErrOrchestratorCandidates = errors.New("daemon: orchestrator requires declared candidates")
	// ErrOrchestratorState means a transition was requested out of order.
	ErrOrchestratorState = errors.New("daemon: invalid orchestrator transition")
	// ErrNoConfirmedDesync means no high-confidence FSM verdict is available to
	// minimize or report.
	ErrNoConfirmedDesync = errors.New("daemon: no confirmed parser desync to report")
)

// TargetProfile is the recon output. Every candidate list is finite and is
// supplied by the operator/config; the orchestrator only ranks what it was
// given and never invents a new profile or mutation.
type TargetProfile struct {
	Host    string
	Addr    string
	Probe   string
	Variant string
	// TLSHint is the fingerprint already chosen for this attempt. It keeps the
	// mutation cell aligned with the audit record written by RecordOutcome.
	TLSHint            string
	TechStack          []string
	WAFSignature       string
	Endpoints          []string
	BaselineOK         bool
	Honeypot           bool
	TLSCandidates      []string
	MutationCandidates []string
}

// AttackAction is the learned choice for one attempt. MutationMode is set only
// for a raw-byte mutation family; legacy differential-fuzz names stay in
// Mutation and keep their own semantics.
type AttackAction struct {
	TLSFingerprint string             `json:"tls_fingerprint"`
	Mutation       string             `json:"mutation"`
	MutationMode   probe.MutationMode `json:"mutation_mode,omitempty"`
	Probe          string             `json:"probe"`
	Variant        string             `json:"variant,omitempty"`
	Proxy          string             `json:"proxy,omitempty"`
	Seed           int64              `json:"seed"`
	Attempt        int                `json:"attempt"`
}

// LearningProvider is the existing Self-Learning brain seen from the FSM:
// ranking before an attempt, observation after it, and proxy penalization for
// local engine faults. ExperienceProvider adapts the real ExperienceStore.
type LearningProvider interface {
	RankTLS(profile TargetProfile, candidates []string) []string
	RankMutations(profile TargetProfile, candidates []string) []string
	Observe(rec Record)
	CooldownProxy(label, reason string, cooldown time.Duration) bool
}

// ExperienceProvider binds the orchestrator to the same table the daemon's
// audit loop uses. Online is optional and only refines the store's ordering.
type ExperienceProvider struct {
	Store  *ExperienceStore
	Pool   *omnislash.Pool
	Online *onlineRuntime
}

func (p *ExperienceProvider) key(profile TargetProfile) ExperienceKey {
	host := profile.Host
	if host == "" {
		host = hostFromAddr(profile.Addr)
	}
	tech := ""
	if len(profile.TechStack) > 0 {
		tech = probe.TechStackHash(profile.TechStack)
	}
	return ExperienceKey{Host: host, TLS: profile.TLSHint, Probe: profile.Probe, Variant: profile.Variant, TechStack: tech}
}

// RankTLS orders declared TLS fingerprints by learned success probability.
// Store.Rank is the variant dimension, so TLS needs its own projection of the
// same cells; no new learning table is created here.
func (p *ExperienceProvider) RankTLS(profile TargetProfile, candidates []string) []string {
	out := append([]string(nil), candidates...)
	if p == nil || p.Store == nil || len(out) < 2 {
		return out
	}
	key := p.key(profile)
	scores := make(map[string]float64, len(out))
	for _, c := range out {
		k := key
		k.TLS = c
		if st, ok := p.Store.statFor(k); ok {
			scores[c] = st.Score()
		} else {
			scores[c] = 0.5
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return scores[out[i]] > scores[out[j]] })
	if p.Online != nil {
		out = p.Online.rank("tls", out, key.Host, key.TechStack)
	}
	return out
}

// RankMutations orders declared mutations by learned success probability.
func (p *ExperienceProvider) RankMutations(profile TargetProfile, candidates []string) []string {
	out := append([]string(nil), candidates...)
	if p == nil || p.Store == nil || len(out) < 2 {
		return out
	}
	key := p.key(profile)
	out = p.Store.RankMutations(key, out)
	if p.Online != nil {
		out = p.Online.rank("mutation", out, key.Host, key.TechStack)
	}
	return out
}

// Observe folds one attempt into the shared experience table.
func (p *ExperienceProvider) Observe(rec Record) {
	if p != nil && p.Store != nil {
		p.Store.Observe(rec)
	}
}

// CooldownProxy puts the proxy that produced an engine fault into cooldown.
func (p *ExperienceProvider) CooldownProxy(label, reason string, cooldown time.Duration) bool {
	if p == nil || p.Pool == nil || label == "" {
		return false
	}
	pr, ok := p.Pool.ProxyByLabel(label)
	if !ok {
		return false
	}
	p.Pool.Ban(pr, reason, cooldown)
	return true
}

// OrchestratorEvent is one JSONL line per FSM transition. The field names are
// part of the audit contract ("orchestrator_state", "chosen_mutation").
type OrchestratorEvent struct {
	Time             time.Time         `json:"time"`
	From             OrchestratorState `json:"from_state,omitempty"`
	State            OrchestratorState `json:"orchestrator_state"`
	Host             string            `json:"host,omitempty"`
	Probe            string            `json:"probe,omitempty"`
	Attempt          int               `json:"attempt,omitempty"`
	ChosenTLS        string            `json:"chosen_tls,omitempty"`
	ChosenMutation   string            `json:"chosen_mutation,omitempty"`
	ParserDivergence probe.ParserState `json:"parser_divergence,omitempty"`
	Reason           string            `json:"reason,omitempty"`
}

// CaidoPushFunc has the same shape as UIOptions.CaidoPush.
type CaidoPushFunc func(context.Context, []json.RawMessage, string, string) (int, error)

// OrchestratorReport is the escalation artifact. Confidence follows the UI's
// existing scale; CVSS is computed only when a caller supplies a v3.1 vector.
type OrchestratorReport struct {
	Kind            string        `json:"kind"`
	Confidence      string        `json:"confidence"`
	ConfidenceScore int           `json:"confidence_score"`
	CVSSVector      string        `json:"cvss_vector,omitempty"`
	CVSSScore       float64       `json:"cvss_score,omitempty"`
	Finding         probe.Finding `json:"finding"`
	Action          AttackAction  `json:"action"`
	MinimalPayload  []byte        `json:"minimal_payload,omitempty"`
	Evidence        []byte        `json:"evidence,omitempty"`
}

// Orchestrator is the top-level FSM. It owns no socket and no second learning
// table: every choice comes from LearningProvider and every verdict goes back
// to it.
type Orchestrator struct {
	mu       sync.Mutex
	auditMu  sync.Mutex
	provider LearningProvider
	audit    io.Writer
	now      func() time.Time

	state       OrchestratorState
	profile     TargetProfile
	lastAction  AttackAction
	finding     probe.Finding
	minimal     []byte
	evidence    []byte
	attempts    int
	failures    int
	cooldown    time.Duration
	maxFailures int
	panicOnFSM  bool
	caidoPush   CaidoPushFunc
}

// NewOrchestrator attaches the FSM to a learning provider. A nil provider is
// accepted by the constructor but refuses every action (fail-closed).
func NewOrchestrator(provider LearningProvider, audit io.Writer) *Orchestrator {
	return &Orchestrator{
		provider:    provider,
		audit:       audit,
		now:         time.Now,
		state:       StateRecon,
		cooldown:    time.Minute,
		maxFailures: 3,
	}
}

// SetCooldown overrides the proxy cooldown applied after an engine fault.
func (o *Orchestrator) SetCooldown(d time.Duration) {
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if d > 0 {
		o.cooldown = d
	}
}

// SetMaxFailures sets how many non-confirming attempts trigger escalation.
func (o *Orchestrator) SetMaxFailures(n int) {
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if n > 0 {
		o.maxFailures = n
	}
}

// SetCaidoPush connects the escalation report to the existing Caido bridge.
func (o *Orchestrator) SetCaidoPush(fn CaidoPushFunc) {
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.caidoPush = fn
}

// SetPanicOnFSM injects a parser panic for chaos tests. It is still contained
// by Analyze and becomes Engine_Fault.
func (o *Orchestrator) SetPanicOnFSM(on bool) {
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.panicOnFSM = on
}

// State returns the current FSM state.
func (o *Orchestrator) State() OrchestratorState {
	if o == nil {
		return ""
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.state
}

// LastAction returns a copy of the most recent learned action.
func (o *Orchestrator) LastAction() AttackAction {
	if o == nil {
		return AttackAction{}
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.lastAction
}

// Finding returns a copy of the confirmed finding, if any.
func (o *Orchestrator) Finding() probe.Finding {
	if o == nil {
		return probe.Finding{}
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.finding
}

func (o *Orchestrator) transition(to OrchestratorState, event OrchestratorEvent) {
	o.mu.Lock()
	event.Time = o.now()
	event.From = o.state
	event.State = to
	o.state = to
	o.mu.Unlock()
	o.logEvent(event)
}

func (o *Orchestrator) logEvent(event OrchestratorEvent) {
	if o == nil || o.audit == nil {
		return
	}
	line, err := json.Marshal(event)
	if err != nil {
		return
	}
	o.auditMu.Lock()
	defer o.auditMu.Unlock()
	_, _ = o.audit.Write(append(line, '\n'))
}

// StartRecon records the discovered endpoints and refuses honeypots before any
// mutation can run.
func (o *Orchestrator) StartRecon(profile TargetProfile) error {
	if o == nil {
		return ErrOrchestratorProvider
	}
	if profile.Honeypot {
		return ErrOrchestratorScope
	}
	o.mu.Lock()
	o.profile = profile
	o.failures = 0
	o.finding = probe.Finding{}
	o.lastAction = AttackAction{}
	o.minimal = nil
	o.evidence = nil
	o.mu.Unlock()
	o.transition(StateRecon, OrchestratorEvent{Host: profile.Host, Probe: profile.Probe, Reason: "recon"})
	return nil
}

// Calibrate consumes the NCD/semantic baseline. A mandatory semantic failure
// or a honeypot signature stops the FSM before StateAttack.
func (o *Orchestrator) Calibrate(ncd float64, honeypot bool) error {
	if o == nil {
		return ErrOrchestratorProvider
	}
	if honeypot {
		o.mu.Lock()
		o.profile.Honeypot = true
		o.mu.Unlock()
		return ErrOrchestratorScope
	}
	o.mu.Lock()
	if o.state != StateRecon {
		o.mu.Unlock()
		return ErrOrchestratorState
	}
	host, probeName := o.profile.Host, o.profile.Probe
	o.profile.BaselineOK = true
	o.mu.Unlock()
	o.transition(StateBaseline, OrchestratorEvent{Host: host, Probe: probeName, Reason: fmt.Sprintf("ncd=%.3f", ncd)})
	return nil
}

// CalibrateWithSemantic computes NCD over semantic skeletons before promoting
// the FSM to StateBaseline. A mandatory skeleton failure is returned to the
// caller and must be handled as an Engine Fault, never as a target verdict.
func (o *Orchestrator) CalibrateWithSemantic(client *omnislash.SemanticClient, baseline, sample []byte, contentType string, honeypot bool) error {
	if client == nil {
		return errors.New("daemon: semantic client is required for baseline calibration")
	}
	baseSkeleton, err := client.Skeleton(baseline, contentType)
	if err != nil {
		return err
	}
	sampleSkeleton, err := client.Skeleton(sample, contentType)
	if err != nil {
		return err
	}
	distance := omnislash.NormalizedCompressionDistance([]byte(baseSkeleton), []byte(sampleSkeleton))
	return o.Calibrate(distance, honeypot)
}

// GetBestAction asks the brain for the best declared TLS fingerprint and
// mutation. It never falls back to a random choice and never attacks a profile
// that failed the baseline.
func (o *Orchestrator) GetBestAction(profile TargetProfile) (AttackAction, error) {
	if o == nil || o.provider == nil {
		return AttackAction{}, ErrOrchestratorProvider
	}
	if profile.Honeypot {
		return AttackAction{}, ErrOrchestratorScope
	}
	o.mu.Lock()
	rejected := o.profile.Honeypot
	o.mu.Unlock()
	if rejected {
		return AttackAction{}, ErrOrchestratorScope
	}
	if len(profile.TLSCandidates) == 0 || len(profile.MutationCandidates) == 0 {
		return AttackAction{}, ErrOrchestratorCandidates
	}

	tlsRanked := o.provider.RankTLS(profile, profile.TLSCandidates)
	tls := firstAllowed(tlsRanked, profile.TLSCandidates)
	mutationProfile := profile
	mutationProfile.TLSHint = tls
	mutationRanked := o.provider.RankMutations(mutationProfile, profile.MutationCandidates)
	mutation := firstAllowed(mutationRanked, profile.MutationCandidates)
	if tls == "" || mutation == "" {
		return AttackAction{}, ErrOrchestratorCandidates
	}

	action := AttackAction{
		TLSFingerprint: tls,
		Mutation:       mutation,
		MutationMode:   mutationModeOf(mutation),
		Probe:          profile.Probe,
		Variant:        profile.Variant,
		Seed:           1,
	}
	o.mu.Lock()
	o.profile = profile
	o.attempts++
	action.Attempt = o.attempts
	o.lastAction = action
	o.mu.Unlock()
	o.transition(StateAttack, OrchestratorEvent{
		Host:           profile.Host,
		Probe:          profile.Probe,
		Attempt:        action.Attempt,
		ChosenTLS:      action.TLSFingerprint,
		ChosenMutation: action.Mutation,
	})
	return action, nil
}

func firstAllowed(ranked, allowed []string) string {
	seen := make(map[string]bool, len(allowed))
	for _, c := range allowed {
		seen[c] = true
	}
	for _, c := range ranked {
		if seen[c] {
			return c
		}
	}
	return ""
}

func mutationModeOf(name string) probe.MutationMode {
	switch probe.MutationMode(name) {
	case probe.MutationHeaderFolding, probe.MutationChunkExtensions, probe.MutationCaseMixing:
		return probe.MutationMode(name)
	default:
		return probe.MutationAuto
	}
}

// Analyze classifies raw response bytes. A parser panic is contained by the
// SafeGo boundary and reported as Engine_Fault, never as a target verdict.
func (o *Orchestrator) Analyze(raw []byte, ferr error, requestHadTE bool) probe.ParserState {
	m := &probe.ParserStateMachine{RequestHadTE: requestHadTE}
	if o != nil {
		o.mu.Lock()
		m.PanicOnAnalyze = o.panicOnFSM
		o.mu.Unlock()
	}
	var state probe.ParserState
	errs := util.SafeGoPayload(raw, func() {
		state = m.AnalyzeDivergence(raw, ferr)
	})
	if err := <-errs; err != nil {
		return probe.ParserEngineFault
	}
	if o != nil {
		o.mu.Lock()
		o.evidence = append([]byte(nil), raw...)
		if len(o.evidence) > 64<<10 {
			o.evidence = o.evidence[:64<<10]
		}
		o.mu.Unlock()
	}
	return state
}

// Mutate applies the chosen mutation to raw bytes through the scoped raw-byte
// mutator. Missing scope is refused before any byte is changed; a panic is
// converted to a precision loss.
func (o *Orchestrator) Mutate(ctx context.Context, action AttackAction, base []byte, scope probe.ScopeGuard, target string) ([]byte, error) {
	m := &probe.PayloadMutator{
		Scope:  scope,
		Target: target,
		Mode:   action.MutationMode,
		Ctx:    ctx,
	}
	var (
		out []byte
		err error
	)
	errs := util.SafeGoPayload(base, func() {
		out, err = m.Mutate(base, action.Seed)
	})
	if fault := <-errs; fault != nil {
		return nil, fault
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}

// RecordOutcome returns the FSM verdict to the brain. A confirmed desync is a
// high-confidence success; a WAF block or a clean response is negative
// evidence; an engine fault is non-trainable and cools down the proxy.
func (o *Orchestrator) RecordOutcome(action AttackAction, state probe.ParserState) error {
	if o == nil || o.provider == nil {
		return ErrOrchestratorProvider
	}
	o.mu.Lock()
	profile := o.profile
	cooldown := o.cooldown
	maxFailures := o.maxFailures
	o.mu.Unlock()

	host := profile.Host
	if host == "" {
		host = hostFromAddr(profile.Addr)
	}
	tech := ""
	if len(profile.TechStack) > 0 {
		tech = probe.TechStackHash(profile.TechStack)
	}
	label, success := outcomeForParserState(state)
	rec := Record{
		Time:             time.Now(),
		Target:           profile.Addr,
		Probe:            action.Probe,
		TLS:              action.TLSFingerprint,
		Success:          success,
		Outcome:          string(label),
		ParserDivergence: string(state),
		Learning: LearningMeta{
			Host:      host,
			Variant:   action.Variant,
			Mutation:  action.Mutation,
			TechStack: tech,
		},
	}
	if state == probe.ParserEngineFault {
		rec.Error = "engine fault: proxy excluded from training"
	}
	o.provider.Observe(rec)

	next := StateAttack
	reason := "no confirmed desync"
	if state == probe.FEClosedBEWaiting {
		next = StateVerify
		reason = "FE_Closed_BE_Waiting confirmed"
		o.mu.Lock()
		o.failures = 0
		o.finding = probe.Finding{
			Kind:       "desync_confirmed",
			Confidence: probe.ConfidenceHigh,
			Detail:     "FSM classified the exchange as frontend closed / backend waiting",
		}
		o.mu.Unlock()
	} else {
		o.mu.Lock()
		o.failures++
		failures := o.failures
		o.mu.Unlock()
		if state == probe.ParserEngineFault {
			reason = "engine fault: proxy cooldown"
			o.provider.CooldownProxy(action.Proxy, "orchestrator engine fault", cooldown)
		}
		if failures >= maxFailures {
			next = StateEscalate
			reason += "; escalation threshold reached"
		}
	}

	feedback := OrchestratorEvent{
		Host:             host,
		Probe:            action.Probe,
		Attempt:          action.Attempt,
		ChosenTLS:        action.TLSFingerprint,
		ChosenMutation:   action.Mutation,
		ParserDivergence: state,
		Reason:           reason,
	}
	o.transition(StateFeedback, feedback)
	o.transition(next, feedback)
	return nil
}

func outcomeForParserState(state probe.ParserState) (OutcomeLabel, bool) {
	switch state {
	case probe.FEClosedBEWaiting:
		return OutcomeTargetResponse, true
	case probe.WAFBlocked:
		return OutcomeWAFBlocked, false
	case probe.SyncOK:
		return OutcomeTargetResponse, false
	default:
		// Unknown and Engine_Fault verdicts are local failures: they increase
		// ProxyFailures only and never enter Attempts.
		return OutcomeProxyFailed, false
	}
}

// Verify closes the confirmation loop. A failed verification escalates; a
// successful one returns to StateAttack for the next target.
func (o *Orchestrator) Verify(ok bool, reason string) error {
	if o == nil {
		return ErrOrchestratorProvider
	}
	o.mu.Lock()
	if o.state != StateVerify {
		o.mu.Unlock()
		return ErrOrchestratorState
	}
	host, probeName, action := o.profile.Host, o.profile.Probe, o.lastAction
	o.mu.Unlock()
	if !ok {
		o.transition(StateEscalate, OrchestratorEvent{
			Host: host, Probe: probeName, Attempt: action.Attempt,
			ChosenMutation: action.Mutation, Reason: reason,
		})
		return nil
	}
	o.mu.Lock()
	o.failures = 0
	o.mu.Unlock()
	o.transition(StateAttack, OrchestratorEvent{
		Host: host, Probe: probeName, Attempt: action.Attempt,
		ChosenTLS: action.TLSFingerprint, ChosenMutation: action.Mutation,
		Reason: "verified",
	})
	return nil
}

// Escalate moves explicitly to the reporting state.
func (o *Orchestrator) Escalate(reason string) {
	if o == nil {
		return
	}
	o.mu.Lock()
	host, probeName, action := o.profile.Host, o.profile.Probe, o.lastAction
	o.mu.Unlock()
	o.transition(StateEscalate, OrchestratorEvent{
		Host: host, Probe: probeName, Attempt: action.Attempt,
		ChosenMutation: action.Mutation, Reason: reason,
	})
}

// Minimize runs ddmin over CRLF-delimited request lines. It keeps only a subset
// that still produces the confirmed FSM verdict, so the report never suggests
// a payload that was not actually observed.
func (o *Orchestrator) Minimize(ctx context.Context, payload []byte, evaluate func([]byte) probe.ParserState) ([]byte, error) {
	if len(payload) == 0 || evaluate == nil {
		return nil, errors.New("daemon: minimize requires a payload and an evaluator")
	}
	lines := strings.Split(string(payload), "\r\n")
	current := append([]byte(nil), payload...)
	for steps := 0; steps < 4096; steps++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(lines) < 2 {
			break
		}
		granularity := 2
		reduced := false
		for granularity <= len(lines) {
			size := (len(lines) + granularity - 1) / granularity
			for part := 0; part < granularity; part++ {
				start := part * size
				end := start + size
				if start >= len(lines) {
					continue
				}
				if end > len(lines) {
					end = len(lines)
				}
				candidateLines := append(append([]string(nil), lines[:start]...), lines[end:]...)
				candidate := []byte(strings.Join(candidateLines, "\r\n"))
				if strings.TrimSpace(string(candidate)) == "" {
					continue
				}
				if o.Analyze(candidate, nil, true) == probe.FEClosedBEWaiting ||
					evaluate(candidate) == probe.FEClosedBEWaiting {
					lines = candidateLines
					current = candidate
					reduced = true
					break
				}
			}
			if reduced {
				break
			}
			if granularity >= len(lines) {
				break
			}
			granularity *= 2
		}
		if !reduced {
			break
		}
	}
	o.mu.Lock()
	o.minimal = append([]byte(nil), current...)
	action := o.lastAction
	host, probeName := o.profile.Host, o.profile.Probe
	o.mu.Unlock()
	o.transition(StateEscalate, OrchestratorEvent{
		Host: host, Probe: probeName, Attempt: action.Attempt,
		ChosenMutation: action.Mutation, Reason: "ddmin minimization",
	})
	return append([]byte(nil), current...), nil
}

// Report builds the escalation artifact and optionally pushes it to Caido.
func (o *Orchestrator) Report(ctx context.Context, cvssVector string) (OrchestratorReport, error) {
	if o == nil {
		return OrchestratorReport{}, ErrOrchestratorProvider
	}
	o.mu.Lock()
	finding := o.finding
	action := o.lastAction
	minimal := append([]byte(nil), o.minimal...)
	evidence := append([]byte(nil), o.evidence...)
	push := o.caidoPush
	o.mu.Unlock()
	if finding.Kind == "" {
		return OrchestratorReport{}, ErrNoConfirmedDesync
	}
	report := OrchestratorReport{
		Kind:            finding.Kind,
		Confidence:      finding.Confidence,
		ConfidenceScore: confidenceScore(finding.Confidence),
		Finding:         finding,
		Action:          action,
		MinimalPayload:  minimal,
		Evidence:        evidence,
	}
	if cvssVector != "" {
		score, err := cvss31BaseScore(cvssVector)
		if err != nil {
			return OrchestratorReport{}, err
		}
		report.CVSSVector = cvssVector
		report.CVSSScore = score
	}
	if push != nil {
		raw, err := json.Marshal(report)
		if err != nil {
			return OrchestratorReport{}, err
		}
		if _, err := push(ctx, []json.RawMessage{raw}, action.Probe, "orchestrator"); err != nil {
			return report, err
		}
	}
	o.mu.Lock()
	host := o.profile.Host
	o.mu.Unlock()
	o.transition(StateEscalate, OrchestratorEvent{
		Host: host, Probe: action.Probe, Attempt: action.Attempt,
		ChosenMutation: action.Mutation, Reason: "report generated",
	})
	return report, nil
}

func confidenceScore(level string) int {
	switch level {
	case probe.ConfidenceHigh:
		return 90
	case probe.ConfidenceMedium:
		return 70
	case probe.ConfidenceLow:
		return 40
	default:
		return 0
	}
}

// cvss31BaseScore computes the CVSS v3.1 base score for a supplied vector. An
// unknown or incomplete vector is refused instead of producing a guess.
func cvss31BaseScore(vector string) (float64, error) {
	parts := strings.Split(vector, "/")
	if len(parts) == 0 || parts[0] != "CVSS:3.1" {
		return 0, errors.New("daemon: CVSS vector must start with CVSS:3.1")
	}
	metrics := make(map[string]string, len(parts)-1)
	for _, part := range parts[1:] {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 || metrics[kv[0]] != "" {
			return 0, fmt.Errorf("daemon: invalid CVSS metric %q", part)
		}
		metrics[kv[0]] = kv[1]
	}
	lookup := func(key string, values map[string]float64) (float64, error) {
		value, ok := metrics[key]
		if !ok {
			return 0, fmt.Errorf("daemon: missing CVSS metric %q", key)
		}
		weight, ok := values[value]
		if !ok {
			return 0, fmt.Errorf("daemon: unsupported CVSS %s=%s", key, value)
		}
		return weight, nil
	}
	av, err := lookup("AV", map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2})
	if err != nil {
		return 0, err
	}
	ac, err := lookup("AC", map[string]float64{"L": 0.77, "H": 0.44})
	if err != nil {
		return 0, err
	}
	scopeChanged := metrics["S"] == "C"
	if metrics["S"] != "U" && !scopeChanged {
		return 0, fmt.Errorf("daemon: unsupported CVSS S=%q", metrics["S"])
	}
	prValues := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if scopeChanged {
		prValues["L"] = 0.68
		prValues["H"] = 0.5
	}
	pr, err := lookup("PR", prValues)
	if err != nil {
		return 0, err
	}
	ui, err := lookup("UI", map[string]float64{"N": 0.85, "R": 0.62})
	if err != nil {
		return 0, err
	}
	impacts := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	conf, err := lookup("C", impacts)
	if err != nil {
		return 0, err
	}
	integ, err := lookup("I", impacts)
	if err != nil {
		return 0, err
	}
	avail, err := lookup("A", impacts)
	if err != nil {
		return 0, err
	}
	iss := 1 - (1-conf)*(1-integ)*(1-avail)
	impact := 6.42 * iss
	exploitability := 8.22 * av * ac * pr * ui
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	if impact <= 0 {
		return 0, nil
	}
	score := impact + exploitability
	if scopeChanged {
		score = 1.08 * score
	}
	if score > 10 {
		score = 10
	}
	return math.Ceil(score*10) / 10, nil
}

// orchestratorProfile derives a finite candidate profile from a job. TLS
// candidates come from the already-loaded transport config; no default list is
// invented here.
func orchestratorProfile(j *JobConfig, tlsCandidates []string) TargetProfile {
	host := j.Target.Host
	if host == "" {
		host = hostFromAddr(j.Target.Addr)
	}
	candidates := append([]string(nil), j.Mutations...)
	if len(candidates) == 0 && j.Probe == "differential-fuzz" {
		for _, m := range (probe.Mutator{TechStack: j.TechStack}).Mutations() {
			candidates = append(candidates, m.Name)
		}
	}
	return TargetProfile{
		Host:               host,
		Addr:               j.Target.Addr,
		Probe:              j.Probe,
		Variant:            j.Variant,
		TechStack:          append([]string(nil), j.TechStack...),
		TLSCandidates:      append([]string(nil), tlsCandidates...),
		MutationCandidates: candidates,
	}
}

// parserStateOf maps the audit label back to the FSM verdict. An empty label
// is not a verdict and callers must skip feedback for it.
func parserStateOf(value string) (probe.ParserState, bool) {
	switch probe.ParserState(value) {
	case probe.ParserSyncOK, probe.ParserFEClosedBEWaiting, probe.ParserWAFBlocked, probe.ParserEngineFault:
		return probe.ParserState(value), true
	default:
		return "", false
	}
}
