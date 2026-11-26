package daemon

import (
	"bytes"
	"encoding/json"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skyrimdlyalohov-droid/omnislash/probe"
)

type betaStubProvider struct {
	cells map[string]BetaCell
}

func (p *betaStubProvider) RankTLS(_ TargetProfile, candidates []string) []string {
	return append([]string(nil), candidates...)
}

func (p *betaStubProvider) RankMutations(_ TargetProfile, candidates []string) []string {
	return append([]string(nil), candidates...)
}

func (p *betaStubProvider) Observe(Record) {}

func (p *betaStubProvider) CooldownProxy(string, string, time.Duration) bool { return false }

func (p *betaStubProvider) BetaFor(feature, _, _ string) (float64, float64, bool) {
	cell, ok := p.cells[feature]
	if !ok {
		return 0, 0, false
	}
	return cell.Alpha, cell.Beta, true
}

func TestThompsonSamplingConvergesToStrongPosterior(t *testing.T) {
	profile := orchestratorTestProfile()
	profile.TLSCandidates = []string{"chrome"}
	profile.MutationCandidates = []string{"good", "bad"}
	tech := probe.TechStackHash(profile.TechStack)
	provider := &betaStubProvider{cells: map[string]BetaCell{
		featureKey(tech, string(PhaseMutateFraming), "good"): {Alpha: 20, Beta: 1},
		featureKey(tech, string(PhaseMutateFraming), "bad"):  {Alpha: 1, Beta: 20},
	}}
	orch := NewOrchestrator(provider, nil)
	orch.SetRNG(rand.New(rand.NewPCG(3, 5)))

	counts := map[string]int{}
	for i := 0; i < 200; i++ {
		action, err := orch.GetBestAction(profile)
		if err != nil {
			t.Fatal(err)
		}
		counts[action.Mutation]++
	}
	if counts["good"] < 190 || counts["bad"] > 10 {
		t.Fatalf("Thompson sampling did not converge: good=%d bad=%d", counts["good"], counts["bad"])
	}
}

func TestThompsonSamplingWithSeededRNGIsConcurrentSafe(t *testing.T) {
	profile := orchestratorTestProfile()
	profile.TLSCandidates = []string{"chrome"}
	profile.MutationCandidates = []string{"good", "bad"}
	tech := probe.TechStackHash(profile.TechStack)
	provider := &betaStubProvider{cells: map[string]BetaCell{
		featureKey(tech, string(PhaseMutateFraming), "good"): {Alpha: 8, Beta: 1},
		featureKey(tech, string(PhaseMutateFraming), "bad"):  {Alpha: 1, Beta: 8},
	}}
	orch := NewOrchestrator(provider, nil)
	orch.SetRNG(rand.New(rand.NewPCG(9, 11)))

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				if _, err := orch.GetBestAction(profile); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent GetBestAction failed: %v", err)
	}
}

func TestRewardCurrencyAndPhaseGating(t *testing.T) {
	waf := RewardFor(probe.WAFBlocked, probe.SignalQuality{Status: 403})
	if waf.Value != -0.5 || waf.BetaDelta != 0.5 || !waf.Stop {
		t.Fatalf("WAF reward = %+v, want -0.5 / beta+0.5 / stop", waf)
	}
	reject := RewardFor(probe.SyncOK, probe.SignalQuality{Status: 400})
	if reject.Value != -0.1 || reject.BetaDelta != 0.1 || !reject.Stop {
		t.Fatalf("parser reject reward = %+v, want -0.1 / beta+0.1 / stop", reject)
	}
	redirect := RewardFor(probe.SyncOK, probe.SignalQuality{Status: 302})
	if redirect.Value != -0.15 || redirect.BetaDelta != 0.15 {
		t.Fatalf("quiet redirect reward = %+v, want -0.15 / beta+0.15", redirect)
	}
	shifted := RewardFor(probe.SyncOK, probe.SignalQuality{Status: 301, StatusShift: true})
	if shifted.Value != 0 {
		t.Fatalf("a redirect with a status shift must not take the quiet penalty: %+v", shifted)
	}
	strong := probe.SignalQuality{Status: 502, NCD: 0.9, Entropy: 0.5, ZScore: 3, StatusShift: true}
	confirmed := RewardFor(probe.FEClosedBEWaiting, strong)
	if confirmed.Value != 2.0 || confirmed.AlphaDelta != 2.0 || !confirmed.Elite {
		t.Fatalf("confirmed reward = %+v, want +2 / alpha+2 / elite", confirmed)
	}
	if RewardFor(probe.ParserEngineFault, strong).AlphaDelta != 0 {
		t.Fatal("an engine fault must never move the posterior")
	}
	timing := RewardFor(probe.TimingDesync, probe.SignalQuality{ZScore: probe.SignalZThreshold + 0.5})
	if timing.Value != 0.25 || timing.AlphaDelta != 0.25 || timing.Elite {
		t.Fatalf("timing reward = %+v, want +0.25 / alpha+0.25 / not elite", timing)
	}
	if RewardFor(probe.TimingDesync, probe.SignalQuality{ZScore: 0}).Value != 0 {
		t.Fatal("an uncalibrated timing verdict must not move the posterior")
	}

	var audit bytes.Buffer
	orch := NewOrchestrator(&ExperienceProvider{Store: orchestratorTestStore()}, &audit)
	if orch.Phase() != PhaseInit {
		t.Fatalf("initial phase = %s, want INIT", orch.Phase())
	}
	if err := orch.advance(PhaseConfirmed); err == nil {
		t.Fatal("a skipped FSM transition must be refused")
	}
	profile := orchestratorTestProfile()
	if err := orch.StartRecon(profile); err != nil {
		t.Fatal(err)
	}
	if err := orch.Calibrate(0.1, false); err != nil {
		t.Fatal(err)
	}
	action, err := orch.GetBestAction(profile)
	if err != nil {
		t.Fatal(err)
	}
	if orch.Phase() != PhaseMutateFraming {
		t.Fatalf("phase after action = %s, want MUTATE_FRAMING", orch.Phase())
	}

	weak := probe.SignalQuality{Status: 200, NCD: 0.9, Entropy: 0.5, ZScore: 1, StatusShift: true, LatencyMS: 12}
	orch.ObserveExchange(weak)
	if err := orch.RecordOutcome(action, probe.FEClosedBEWaiting); err != nil {
		t.Fatal(err)
	}
	if orch.Phase() != PhaseMutateFraming {
		t.Fatalf("weak signal promoted the branch to %s", orch.Phase())
	}
	if !strings.Contains(audit.String(), `"alpha_delta":2`) && !strings.Contains(audit.String(), `"beta_delta":0.25`) {
		t.Fatalf("audit lost the weak-signal penalty: %s", audit.String())
	}

	orch.ObserveExchange(strong)
	if err := orch.RecordOutcome(action, probe.FEClosedBEWaiting); err != nil {
		t.Fatal(err)
	}
	if orch.Phase() != PhaseVerifyVictim {
		t.Fatalf("strong signal phase = %s, want VERIFY_VICTIM", orch.Phase())
	}
	if err := orch.Verify(false, "cross-proxy mismatch"); err != nil {
		t.Fatal(err)
	}
	if orch.Phase() != PhaseMutateFraming {
		t.Fatalf("failed verification must fold back to MUTATE_FRAMING, got %s", orch.Phase())
	}
	orch.ObserveExchange(strong)
	if err := orch.RecordOutcome(action, probe.FEClosedBEWaiting); err != nil {
		t.Fatal(err)
	}
	if err := orch.Verify(true, "cross-proxy confirmed"); err != nil {
		t.Fatal(err)
	}
	if orch.Phase() != PhaseConfirmed {
		t.Fatalf("verified phase = %s, want CONFIRMED", orch.Phase())
	}
	for _, want := range []string{`"fsm_phase":"MUTATE_FRAMING"`, `"fsm_phase":"VERIFY_VICTIM"`, `"fsm_phase":"CONFIRMED"`, `"reward":2`} {
		if !strings.Contains(audit.String(), want) {
			t.Fatalf("audit line %q does not contain %s", audit.String(), want)
		}
	}
}

func TestEnableOrchestratorUsesSharedBrainAndRestartsCycle(t *testing.T) {
	cfg := testConfig(testJob())
	d, err := New(cfg, &fakeExec{}, nil, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	o := d.EnableOrchestrator()
	if o == nil || d.orchestrator != o {
		t.Fatal("EnableOrchestrator did not install the FSM")
	}
	provider, ok := o.provider.(*ExperienceProvider)
	if !ok || provider.Store != d.learning {
		t.Fatalf("orchestrator provider = %T/%+v, want the daemon's own experience store", o.provider, provider)
	}
	profile := orchestratorTestProfile()
	first, err := o.GetBestAction(profile)
	if err != nil {
		t.Fatal(err)
	}
	strong := probe.SignalQuality{Status: 502, NCD: 0.9, Entropy: 0.5, ZScore: 3, StatusShift: true}
	o.ObserveExchange(strong)
	if err := o.RecordOutcome(first, probe.FEClosedBEWaiting); err != nil {
		t.Fatal(err)
	}
	if err := o.Verify(true, "cross-proxy confirmed"); err != nil {
		t.Fatal(err)
	}
	if o.Phase() != PhaseConfirmed {
		t.Fatalf("phase after confirmation = %s, want CONFIRMED", o.Phase())
	}
	if _, err := o.GetBestAction(profile); err != nil {
		t.Fatalf("a confirmed cycle must not block the next attempt: %v", err)
	}
	if o.Phase() != PhaseMutateFraming {
		t.Fatalf("phase for the next attempt = %s, want MUTATE_FRAMING", o.Phase())
	}
}

func TestGoFSMRewardReachesPythonBetaWeights(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not installed")
	}
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	audit, err := os.Create(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	orch := NewOrchestrator(&ExperienceProvider{Store: orchestratorTestStore()}, audit)
	profile := orchestratorTestProfile()
	action, err := orch.GetBestAction(profile)
	if err != nil {
		t.Fatal(err)
	}
	orch.ObserveExchange(probe.SignalQuality{Status: 502, NCD: 0.9, Entropy: 0.5, ZScore: 3, StatusShift: true, LatencyMS: 12})
	if err := orch.RecordOutcome(action, probe.FEClosedBEWaiting); err != nil {
		t.Fatal(err)
	}
	if err := audit.Close(); err != nil {
		t.Fatal(err)
	}

	weightsPath := filepath.Join(dir, "weights.json")
	script := filepath.Join("..", "research", "online_loop.py")
	args := []string{
		script, "--audit", auditPath, "--weights", weightsPath,
		"--jobs", filepath.Join(dir, "jobs.json"),
		"--offset", filepath.Join(dir, "offset.json"),
		"--status", filepath.Join(dir, "status.json"),
		"--control", filepath.Join(dir, "control.json"),
		"--once",
	}
	cmd := exec.Command(python, args...)
	cmd.Dir = "."
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("python online loop failed: %v\n%s", err, out)
	}

	data, err := os.ReadFile(weightsPath)
	if err != nil {
		t.Fatal(err)
	}
	var weights struct {
		Beta map[string]struct {
			Alpha float64 `json:"alpha"`
			Beta  float64 `json:"beta"`
		} `json:"beta"`
		Online struct {
			FSMRewards int `json:"fsm_rewards"`
		} `json:"online"`
	}
	if err := json.Unmarshal(data, &weights); err != nil {
		t.Fatal(err)
	}
	key := featureKey(probe.TechStackHash(profile.TechStack), string(PhaseMutateFraming), action.Mutation)
	cell, ok := weights.Beta[key]
	if !ok {
		t.Fatalf("weights %s have no cell %q: %s", weightsPath, key, data)
	}
	// One Go transition carries alpha+2 once: a duplicated feedback line would
	// silently push the posterior to 5 and train the same attempt twice.
	if cell.Alpha != 3.0 || weights.Online.FSMRewards != 1 {
		t.Fatalf("Go alpha+2 reward was not persisted exactly once: cell=%+v meta=%+v", cell, weights.Online)
	}
}
