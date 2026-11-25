package daemon

import (
	"fmt"
	"math"
	"math/rand/v2"
	"strings"

	"github.com/skyrimdlyalohov-droid/omnislash"
	"github.com/skyrimdlyalohov-droid/omnislash/probe"
)

// OrchestratorPhase is the strict top-level FSM. Only the orchestrator may
// advance it; the mutator, the parser FSM and the python worker only supply
// evidence. Skipping a phase is refused with ErrOrchestratorState.
type OrchestratorPhase string

const (
	PhaseInit          OrchestratorPhase = "INIT"
	PhaseProbeBoundary OrchestratorPhase = "PROBE_BOUNDARY"
	PhaseMutateFraming OrchestratorPhase = "MUTATE_FRAMING"
	PhaseVerifyVictim  OrchestratorPhase = "VERIFY_VICTIM"
	PhaseConfirmed     OrchestratorPhase = "CONFIRMED"
)

var phaseOrder = []OrchestratorPhase{
	PhaseInit, PhaseProbeBoundary, PhaseMutateFraming, PhaseVerifyVictim, PhaseConfirmed,
}

func phaseIndex(p OrchestratorPhase) int {
	for i, candidate := range phaseOrder {
		if candidate == p {
			return i
		}
	}
	return -1
}

func validPhaseTransition(from, to OrchestratorPhase) bool {
	a, b := phaseIndex(from), phaseIndex(to)
	return a >= 0 && b == a+1
}

// Reward is the single scalar currency exchanged between the FSM, the mutator
// and the self-learning layer. Alpha/Beta deltas are expressed in the same
// units as the Beta posterior persisted in state/learned_weights.json.
type Reward struct {
	Value      float64
	AlphaDelta float64
	BetaDelta  float64
	Elite      bool
	Boundary   bool
	Stop       bool
	Reason     string
}

// RewardFor converts one FSM verdict plus its sonar evidence into reward. A
// WAF block is always a loss; a parser rejection is a small win that permits a
// boundary tweak; only a strong confirmed anomaly earns elite promotion.
func RewardFor(state probe.ParserState, signal probe.SignalQuality) Reward {
	switch state {
	case probe.ParserEngineFault:
		// A local fault is not target evidence and must not move the posterior.
		return Reward{Value: 0, Stop: true, Reason: "engine_fault"}
	case probe.ParserWAFBlocked:
		return Reward{Value: -0.5, BetaDelta: 0.5, Stop: true, Reason: "waf_block"}
	}
	if signal.Status == 400 {
		return Reward{Value: 0.1, AlphaDelta: 0.1, Boundary: true, Reason: "parser_reject"}
	}
	if state == probe.ParserFEClosedBEWaiting {
		if signal.Strong() {
			return Reward{Value: 2.0, AlphaDelta: 2.0, Elite: true, Reason: "confirmed_anomaly"}
		}
		return Reward{Value: -0.25, BetaDelta: 0.25, Stop: true, Reason: "weak_signal"}
	}
	return Reward{Value: 0, Reason: "sync_ok"}
}

// rewardFitness maps the current signal to the scalar handed to the mutator.
// The mutator itself only edits bytes: the FSM decides which fitness applies.
func rewardFitness(signal probe.SignalQuality) float64 {
	if signal.Status == 400 {
		return 0.1
	}
	if signal.Strong() {
		return 2.0
	}
	return 0
}

// BetaCell is the O(1) posterior state for one (tech_stack, fsm_state,
// mutation_family) triple. Priors come from learned_weights.json and rewards
// are accumulated in memory until python persists the next generation.
type BetaCell struct {
	Alpha float64 `json:"alpha"`
	Beta  float64 `json:"beta"`
}

// NewBetaCell returns the uninformative Beta(1,1) prior.
func NewBetaCell() BetaCell { return BetaCell{Alpha: 1, Beta: 1} }

// Valid rejects corrupt persisted parameters instead of sampling NaN.
func (c BetaCell) Valid() bool {
	return c.Alpha > 0 && c.Beta > 0 && !math.IsNaN(c.Alpha) && !math.IsNaN(c.Beta) &&
		!math.IsInf(c.Alpha, 0) && !math.IsInf(c.Beta, 0)
}

// Sample draws theta ~ Beta(alpha, beta). A nil rng uses the shared,
// concurrency-safe math/rand source.
func (c BetaCell) Sample(rng *rand.Rand) float64 {
	if !c.Valid() {
		c = NewBetaCell()
	}
	return omnislash.SampleBeta(c.Alpha, c.Beta, rng)
}

// Apply folds one reward into the posterior with a floor that keeps both
// parameters strictly positive.
func (c *BetaCell) Apply(reward Reward) {
	if c == nil {
		return
	}
	if !c.Valid() {
		*c = NewBetaCell()
	}
	c.Alpha = math.Max(0.1, c.Alpha+reward.AlphaDelta)
	c.Beta = math.Max(0.1, c.Beta+reward.BetaDelta)
}

// featureKey is the stable identifier shared with the python learner. The
// fields are deliberately ordered so audit readers can grep a single cell.
func featureKey(tech, phase, family string) string {
	return fmt.Sprintf("tech:%s|state:%s|family:%s",
		strings.ToLower(strings.TrimSpace(tech)),
		strings.ToUpper(strings.TrimSpace(phase)),
		strings.ToLower(strings.TrimSpace(family)))
}
