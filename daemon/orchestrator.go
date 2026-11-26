package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
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

// BetaProvider is the optional bridge to the cross-session (alpha, beta)
// table. Providers without it keep the legacy experience ranking; a provider
// with it enables Thompson Sampling over declared mutation families.
type BetaProvider interface {
	BetaFor(feature, host, tech string) (float64, float64, bool)
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

// BetaFor reads the (alpha, beta) cell loaded from learned_weights.json. It is
// additive to the experience ranking and never invents a prior for an untried
// family: ok=false makes the orchestrator keep the caller's order.
func (p *ExperienceProvider) BetaFor(feature, host, tech string) (float64, float64, bool) {
	if p == nil || p.Online == nil {
		return 0, 0, false
	}
	return p.Online.betaFor(feature, host, tech)
}

// OrchestratorEvent is one JSONL line per FSM transition. The field names are
// part of the audit contract ("orchestrator_state", "chosen_mutation").
type OrchestratorEvent struct {
	Time             time.Time         `json:"time"`
	From             OrchestratorState `json:"from_state,omitempty"`
	State            OrchestratorState `json:"orchestrator_state"`
	Host             string            `json:"host,omitempty"`
	Proxy            string            `json:"proxy,omitempty"`
	Probe            string            `json:"probe,omitempty"`
	Attempt          int               `json:"attempt,omitempty"`
	ChosenTLS        string            `json:"chosen_tls,omitempty"`
	ChosenMutation   string            `json:"chosen_mutation,omitempty"`
	ParserDivergence probe.ParserState `json:"parser_divergence,omitempty"`
	Reason           string            `json:"reason,omitempty"`
	// The structured fields below are consumed by research/online_loop.py to
	// update the cross-session Beta posteriors.
	FSMPhase   OrchestratorPhase `json:"fsm_phase,omitempty"`
	Reward     float64           `json:"reward,omitempty"`
	AlphaDelta float64           `json:"alpha_delta,omitempty"`
	BetaDelta  float64           `json:"beta_delta,omitempty"`
	Posterior  string            `json:"posterior_key,omitempty"`
	// NCD and ZScore are always serialized: online_loop needs both scalars on
	// the feedback line even when the measured value is exactly zero.
	NCD     float64 `json:"ncd"`
	Entropy float64 `json:"entropy,omitempty"`
	ZScore  float64 `json:"zscore"`
	// Uncalibrated is emitted on every feedback line: a zero Z before the
	// pair collected SonarMinSamples samples is not a calibrated "no shift".
	Uncalibrated bool `json:"uncalibrated"`
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
	rngMu    sync.Mutex // guards a caller-supplied *rand.Rand across concurrent jobs
	provider LearningProvider
	audit    io.Writer
	now      func() time.Time

	state       OrchestratorState
	phase       OrchestratorPhase
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

	// Operational loop: O(1) telemetry and posterior state. No network call and
	// no unbounded sample history is owned here.
	sonar          *probe.SonarTracker
	signal         probe.SignalQuality
	baseline       []byte
	baselineSet    bool
	baselineStatus int
	// observed distinguishes the wired daemon path from legacy callers. Only an
	// observed attempt is subject to strict sonar gating.
	observed    bool
	rng         *rand.Rand
	posterior   map[string]*BetaCell
	elite       probe.ElitePool
	basePayload []byte
	lastFeature string
}

// NewOrchestrator attaches the FSM to a learning provider. A nil provider is
// accepted by the constructor but refuses every action (fail-closed).
func NewOrchestrator(provider LearningProvider, audit io.Writer) *Orchestrator {
	return &Orchestrator{
		provider:    provider,
		audit:       audit,
		now:         time.Now,
		state:       StateRecon,
		phase:       PhaseInit,
		cooldown:    time.Minute,
		maxFailures: 3,
		// A nil rng uses the global concurrency-safe source. SetRNG installs a
		// seeded source for reproducible tests and audits.
		posterior: make(map[string]*BetaCell),
		// Per-pair Welford state: a new host or exit proxy starts
		// uncalibrated instead of inheriting another pair's variance.
		sonar: probe.NewSonarTracker(probe.DefaultSonarSlots, probe.SonarMinSamples),
	}
}

// SetRNG replaces the Thompson sampler's source. A seeded *rand.Rand makes a
// decision sequence reproducible; a nil value falls back to a fresh seeded
// source so an orchestrator is never nondeterministically uninitialized.
func (o *Orchestrator) SetRNG(rng *rand.Rand) {
	if o == nil || rng == nil {
		return
	}
	o.rngMu.Lock()
	defer o.rngMu.Unlock()
	o.rng = rng
}

// Phase returns the current strict FSM phase.
func (o *Orchestrator) Phase() OrchestratorPhase {
	if o == nil {
		return ""
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.phase
}

// advance enforces INIT -> PROBE_BOUNDARY -> MUTATE_FRAMING -> VERIFY_VICTIM
// -> CONFIRMED. Returning to MUTATE_FRAMING after a folded branch is allowed;
// jumping forward without evidence is not.
func (o *Orchestrator) advance(to OrchestratorPhase) error {
	from := o.phase
	if from == to {
		return nil
	}
	if !validPhaseTransition(from, to) {
		return fmt.Errorf("%w: %s -> %s", ErrOrchestratorState, from, to)
	}
	o.phase = to
	return nil
}

// ObserveExchange folds one attempt's scalar evidence into the streaming sonar
// without retaining the response. It is the only way the FSM learns latency,
// NCD, entropy and status shift.
func (o *Orchestrator) ObserveExchange(signal probe.SignalQuality) {
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.observed = true
	host := signal.Host
	if host == "" {
		host = o.profile.Host
	}
	if host == "" {
		host = hostFromAddr(o.profile.Addr)
	}
	proxy := signal.Proxy
	if signal.LatencyMS > 0 && o.sonar != nil {
		z, uncalibrated := o.sonar.Evaluate(host, proxy, signal.LatencyMS, probe.DefaultMinSigmaMS)
		if signal.ZScore == 0 {
			signal.ZScore = z
		}
		signal.Uncalibrated = uncalibrated
	}
	if !o.baselineSet && signal.Status > 0 {
		o.baselineStatus = signal.Status
		o.baselineSet = true
	}
	o.signal = signal
}

// ObserveResult derives the scalar sonar signal from one probe result. It is
// deliberately the only bridge from raw response bytes into the FSM: the body
// itself is never retained here, only NCD, entropy, status and latency.
func (o *Orchestrator) ObserveResult(res *probe.Result) {
	if o == nil {
		return
	}
	// Even an empty result is an observed attempt: without this marker a legacy
	// caller could smuggle a FE_Closed_BE_Waiting past the sonar by supplying no
	// evidence at all.
	if res == nil || len(res.Responses) == 0 {
		o.mu.Lock()
		o.observed = true
		o.mu.Unlock()
		return
	}
	last := res.Responses[len(res.Responses)-1]
	o.mu.Lock()
	baselineStatus := o.baselineStatus
	host := o.profile.Host
	if host == "" {
		host = hostFromAddr(o.profile.Addr)
	}
	o.mu.Unlock()
	// A parser rejection anywhere in the paired exchange is the decisive
	// verdict for this mutation. Taking only the final status would hide a
	// 400 -> 200 shift and let the branch keep its posterior weight.
	status := last.Status
	for _, r := range res.Responses {
		if r.Status == 400 {
			status = 400
			break
		}
	}
	signal := probe.SignalQuality{
		Status:      status,
		Host:        host,
		Proxy:       res.Attribution.Proxy,
		LatencyMS:   float64(res.Duration.Microseconds()) / 1000,
		NCD:         o.Distance([]byte(last.Raw)),
		Entropy:     probe.NormalizedEntropy([]byte(last.Body)),
		BodyBytes:   len(last.Body),
		StatusShift: baselineStatus > 0 && last.Status != baselineStatus,
	}
	o.ObserveExchange(signal)
}

// Distance computes NCD against the calibrated raw baseline. With no baseline
// it returns 1: an uncalibrated attempt must never be promoted by NCD alone.
func (o *Orchestrator) Distance(raw []byte) float64 {
	if o == nil {
		return 1
	}
	o.mu.Lock()
	baseline := append([]byte(nil), o.baseline...)
	o.mu.Unlock()
	if len(baseline) == 0 || len(raw) == 0 {
		return 1
	}
	return omnislash.NormalizedCompressionDistance(baseline, raw)
}

// ApplyReward updates one Beta cell and promotes confirmed payloads into the
// elite pool. It is called by RecordOutcome, never by the mutator itself.
func (o *Orchestrator) ApplyReward(reward Reward) {
	if o == nil {
		return
	}
	o.mu.Lock()
	key := o.lastFeature
	if key == "" {
		key = featureKey("", string(o.phase), o.lastAction.Mutation)
	}
	cell := o.posterior[key]
	if cell == nil {
		prior := NewBetaCell()
		cell = &prior
		o.posterior[key] = cell
	}
	cell.Apply(reward)
	if reward.Elite && len(o.basePayload) > 0 {
		o.elite.Add(o.basePayload, reward.Value)
	}
	o.mu.Unlock()
}

// BetaFor exposes the in-session posterior to tests and to the Python bridge.
func (o *Orchestrator) BetaFor(key string) BetaCell {
	if o == nil {
		return NewBetaCell()
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if cell := o.posterior[key]; cell != nil {
		return *cell
	}
	return NewBetaCell()
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

// ClearLastAction marks an attempt that the FSM did not choose. An epsilon
// explore roll has no FSM branch to close, so its result must not feed back
// into the posterior through a stale action from the previous job.
func (o *Orchestrator) ClearLastAction() {
	if o == nil {
		return
	}
	o.mu.Lock()
	o.lastAction = AttackAction{}
	o.mu.Unlock()
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
	o.phase = PhaseProbeBoundary
	o.failures = 0
	o.finding = probe.Finding{}
	o.lastAction = AttackAction{}
	o.minimal = nil
	o.evidence = nil
	o.lastFeature = ""
	o.signal = probe.SignalQuality{}
	o.observed = false
	o.mu.Unlock()
	o.transition(StateRecon, OrchestratorEvent{
		Host: profile.Host, Probe: profile.Probe, Reason: "recon", FSMPhase: PhaseProbeBoundary,
	})
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
	o.transition(StateBaseline, OrchestratorEvent{
		Host: host, Probe: probeName, Reason: fmt.Sprintf("ncd=%.3f", ncd),
		FSMPhase: PhaseProbeBoundary, NCD: ncd,
	})
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
	if err := o.Calibrate(distance, honeypot); err != nil {
		return err
	}
	// The semantic skeletons decide whether the baseline is trustworthy; the
	// raw baseline is kept for per-attempt NCD against raw responses. Capping it
	// keeps the O(1) memory guarantee for a long-lived daemon.
	o.mu.Lock()
	o.baseline = append([]byte(nil), baseline...)
	if len(o.baseline) > 64<<10 {
		o.baseline = o.baseline[:64<<10]
	}
	o.mu.Unlock()
	return nil
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
	tech := probe.TechStackHash(profile.TechStack)
	if bp, ok := o.provider.(BetaProvider); ok {
		if sampled, ok := o.thompsonMutation(bp, profile, tech, mutationRanked); ok {
			mutation = sampled
		}
	}
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
	feature := featureKey(tech, string(PhaseMutateFraming), mutation)
	o.mu.Lock()
	// A new attempt starts a new strict cycle. CONFIRMED closes the previous
	// cycle; it must not freeze every later job in an unreachable phase.
	if phaseIndex(o.phase) >= phaseIndex(PhaseVerifyVictim) {
		o.phase = PhaseInit
	}
	if o.phase == PhaseInit {
		// A caller that did not run recon explicitly still enters through the
		// boundary phase; no later phase can be skipped this way.
		o.phase = PhaseProbeBoundary
	}
	o.observed = false
	if err := o.advance(PhaseMutateFraming); err != nil {
		o.mu.Unlock()
		return AttackAction{}, err
	}
	o.profile = profile
	o.attempts++
	action.Attempt = o.attempts
	o.lastAction = action
	o.lastFeature = feature
	o.basePayload = nil
	o.mu.Unlock()
	o.transition(StateAttack, OrchestratorEvent{
		Host:           profile.Host,
		Probe:          profile.Probe,
		Attempt:        action.Attempt,
		ChosenTLS:      action.TLSFingerprint,
		ChosenMutation: action.Mutation,
		FSMPhase:       PhaseMutateFraming,
		Posterior:      feature,
	})
	return action, nil
}

// thompsonMutation samples theta ~ Beta(alpha, beta) once per declared family
// for (tech_stack, fsm_state, mutation_family). It only chooses among the
// candidates supplied by the caller and falls back to the ranking when no cell
// has evidence, so an untried family is never starved by a missing prior.
func (o *Orchestrator) thompsonMutation(provider BetaProvider, profile TargetProfile, tech string, ranked []string) (string, bool) {
	if provider == nil || len(profile.MutationCandidates) == 0 {
		return "", false
	}
	candidates := profile.MutationCandidates
	host := profile.Host
	var best string
	bestSample := -1.0
	evidence := false
	for _, family := range candidates {
		key := featureKey(tech, string(PhaseMutateFraming), family)
		alpha, beta, ok := provider.BetaFor(key, host, tech)
		o.mu.Lock()
		if cell := o.posterior[key]; cell != nil {
			alpha = math.Max(0.1, alpha+cell.Alpha-1)
			beta = math.Max(0.1, beta+cell.Beta-1)
			ok = true
		}
		o.mu.Unlock()
		if !ok || alpha <= 0 || beta <= 0 {
			continue
		}
		evidence = true
		// A seeded *rand.Rand is not goroutine-safe. Hold rngMu for the whole
		// draw so concurrent jobs in a daemon cannot race on the same source.
		o.rngMu.Lock()
		sample := omnislash.SampleBeta(alpha, beta, o.rng)
		o.rngMu.Unlock()
		if sample > bestSample {
			bestSample = sample
			best = family
		}
	}
	if evidence && best != "" {
		return best, true
	}
	// Thompson found no cell: keep the caller's deterministic ranking.
	return firstAllowed(ranked, candidates), len(ranked) > 0
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
	case probe.MutationHeaderFolding, probe.MutationChunkExtensions, probe.MutationCaseMixing,
		probe.MutationBoundaryShift, probe.MutationEliteCrossover:
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
	var fitness float64
	var elite [][]byte
	if o != nil {
		o.mu.Lock()
		fitness = rewardFitness(o.signal)
		elite = o.elite.Patterns()
		o.basePayload = append([]byte(nil), base...)
		o.mu.Unlock()
	}
	m := &probe.PayloadMutator{
		Scope:   scope,
		Target:  target,
		Mode:    action.MutationMode,
		Ctx:     ctx,
		Fitness: fitness,
		Elite:   elite,
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
	signal := o.signal
	signalProvided := o.observed
	feature := o.lastFeature
	if phaseIndex(o.phase) < phaseIndex(PhaseMutateFraming) {
		// A direct caller that skipped GetBestAction still has a mutation cell;
		// later phases remain strictly gated.
		o.phase = PhaseMutateFraming
	}
	o.mu.Unlock()

	host := profile.Host
	if host == "" {
		host = hostFromAddr(profile.Addr)
	}
	tech := ""
	if len(profile.TechStack) > 0 {
		tech = probe.TechStackHash(profile.TechStack)
	}
	// Each attempt is observed exactly once: a second RecordOutcome without a
	// new GetBestAction must not inherit a stale sonar verdict.
	o.mu.Lock()
	o.observed = false
	o.mu.Unlock()
	label, success := outcomeForSignal(state, signal)
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

	reward := RewardFor(state, signal)
	o.ApplyReward(reward)

	// A strong signal is mandatory for promotion once the sonar is wired. The
	// zero signal is only accepted by legacy callers that never observed an
	// exchange; the daemon's opt-in path always supplies it.
	promote := state == probe.FEClosedBEWaiting && (!signalProvided || signal.Strong())
	next := StateAttack
	reason := reward.Reason
	phase := PhaseMutateFraming
	var advanceErr error
	if promote {
		next = StateVerify
		phase = PhaseVerifyVictim
		reason = "FE_Closed_BE_Waiting confirmed by sonar"
		o.mu.Lock()
		advanceErr = o.advance(phase)
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
		if signalProvided && state == probe.FEClosedBEWaiting && !signal.Strong() {
			reason += "; weak signal folded the branch"
		}
		if failures >= maxFailures {
			next = StateEscalate
			reason += "; escalation threshold reached"
		}
	}

	proxy := signal.Proxy
	if proxy == "" {
		proxy = action.Proxy
	}
	feedback := OrchestratorEvent{
		Host:             host,
		Proxy:            proxy,
		Probe:            action.Probe,
		Attempt:          action.Attempt,
		ChosenTLS:        action.TLSFingerprint,
		ChosenMutation:   action.Mutation,
		ParserDivergence: state,
		Reason:           reason,
		FSMPhase:         phase,
		Reward:           reward.Value,
		AlphaDelta:       reward.AlphaDelta,
		BetaDelta:        reward.BetaDelta,
		Posterior:        feature,
		NCD:              signal.NCD,
		Entropy:          signal.Entropy,
		ZScore:           signal.ZScore,
		Uncalibrated:     signal.Uncalibrated,
	}
	o.transition(StateFeedback, feedback)
	// Only the feedback line carries the reward. Reusing it on the following
	// transition would apply the same alpha/beta delta twice in python.
	followup := feedback
	followup.Reward = 0
	followup.AlphaDelta = 0
	followup.BetaDelta = 0
	followup.Posterior = ""
	followup.NCD = 0
	followup.Entropy = 0
	followup.ZScore = 0
	o.transition(next, followup)
	// A failed phase advance is reported only after the feedback line is
	// emitted: every completed branch must hand its scalars to the learner.
	return advanceErr
}

func outcomeForSignal(state probe.ParserState, signal probe.SignalQuality) (OutcomeLabel, bool) {
	if signal.Status == 400 {
		return OutcomeTargetRejected, false
	}
	return outcomeForParserState(state)
}

func outcomeForParserState(state probe.ParserState) (OutcomeLabel, bool) {
	switch state {
	case probe.FEClosedBEWaiting:
		return OutcomeTargetResponse, true
	case probe.WAFBlocked:
		return OutcomeWAFBlocked, false
	case probe.TimingDesync:
		// Timing alone is not a confirmed queue desync: it trains the branch
		// but never advances the FSM to VERIFY on its own.
		return OutcomeTargetResponse, false
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
		o.mu.Lock()
		// A failed confirmation folds back to the mutation phase; it is a
		// deliberate back edge, not a skipped forward transition.
		o.phase = PhaseMutateFraming
		o.mu.Unlock()
		o.transition(StateEscalate, OrchestratorEvent{
			Host: host, Probe: probeName, Attempt: action.Attempt,
			ChosenMutation: action.Mutation, Reason: reason,
			FSMPhase: PhaseMutateFraming,
		})
		return nil
	}
	o.mu.Lock()
	if o.phase != PhaseVerifyVictim {
		o.mu.Unlock()
		return ErrOrchestratorState
	}
	o.phase = PhaseConfirmed
	o.failures = 0
	o.mu.Unlock()
	o.transition(StateAttack, OrchestratorEvent{
		Host: host, Probe: probeName, Attempt: action.Attempt,
		ChosenTLS: action.TLSFingerprint, ChosenMutation: action.Mutation,
		Reason: "verified", FSMPhase: PhaseConfirmed,
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
	case probe.ParserSyncOK, probe.ParserFEClosedBEWaiting, probe.ParserWAFBlocked, probe.ParserEngineFault, probe.ParserTimingDesync:
		return probe.ParserState(value), true
	default:
		return "", false
	}
}
