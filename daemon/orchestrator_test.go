package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/skyrimdlyalohov-droid/omnislash"
	"github.com/skyrimdlyalohov-droid/omnislash/probe"
)

func TestRareFramingModesRequireExplicitOptIn(t *testing.T) {
	for _, mode := range []probe.MutationMode{
		probe.MutationOWSBeforeColon,
		probe.MutationOWSInValue,
		probe.MutationConflictingFraming,
		probe.MutationChunkBoundaryExt,
	} {
		if got := mutationModeOf(string(mode)); got != mode {
			t.Fatalf("mutationModeOf(%q) = %q, want explicit opt-in", mode, got)
		}
	}
	if got := mutationModeOf("unknown_mode"); got != probe.MutationAuto {
		t.Fatalf("unknown mode = %q, want MutationAuto", got)
	}
}

func orchestratorTestProfile() TargetProfile {
	return TargetProfile{
		Host:               "lab.test",
		Addr:               "lab.test:443",
		Probe:              "smuggle",
		Variant:            "cl.te",
		TechStack:          []string{"nginx"},
		TLSCandidates:      []string{"chrome", "okhttp"},
		MutationCandidates: []string{"case_mixing", "header_folding"},
	}
}

func orchestratorTestStore() *ExperienceStore {
	store := NewExperienceStore("")
	tech := probe.TechStackHash([]string{"nginx"})
	global := ExperienceSeed{
		Host: "*", Probe: "smuggle", Variant: "cl.te", TechStack: tech,
		Attempts: 10, Successes: 0, Provenance: "test-prior",
	}
	goodTLS := global
	goodTLS.TLS = "okhttp"
	goodTLS.Successes = 10
	goodMutation := goodTLS
	goodMutation.Mutation = "header_folding"
	store.Seed([]ExperienceSeed{global, goodTLS, goodMutation})
	return store
}

func orchestratorTestStat(t *testing.T, store *ExperienceStore, key ExperienceKey) ExperienceStat {
	t.Helper()
	for _, st := range store.Summary() {
		if st.Key == key {
			return st
		}
	}
	t.Fatalf("experience cell %+v not found in %+v", key, store.Summary())
	return ExperienceStat{}
}

func TestOrchestratorPicksHighestRankedAction(t *testing.T) {
	store := orchestratorTestStore()
	var audit bytes.Buffer
	orch := NewOrchestrator(&ExperienceProvider{Store: store}, &audit)

	action, err := orch.GetBestAction(orchestratorTestProfile())
	if err != nil {
		t.Fatal(err)
	}
	if action.TLSFingerprint != "okhttp" {
		t.Fatalf("TLS fingerprint = %q, want okhttp from the experience store", action.TLSFingerprint)
	}
	if action.Mutation != "header_folding" || action.MutationMode != probe.MutationHeaderFolding {
		t.Fatalf("mutation = %q/%q, want header_folding raw-byte mode", action.Mutation, action.MutationMode)
	}
	if orch.State() != StateAttack {
		t.Fatalf("state = %s, want StateAttack", orch.State())
	}
	for _, want := range []string{
		`"orchestrator_state":"StateAttack"`,
		`"chosen_tls":"okhttp"`,
		`"chosen_mutation":"header_folding"`,
	} {
		if !strings.Contains(audit.String(), want) {
			t.Fatalf("audit line %q does not contain %s", audit.String(), want)
		}
	}
}

func TestOrchestratorTrainsWeightsAfterConfirmedDesync(t *testing.T) {
	store := orchestratorTestStore()
	var audit bytes.Buffer
	orch := NewOrchestrator(&ExperienceProvider{Store: store}, &audit)
	profile := orchestratorTestProfile()
	action, err := orch.GetBestAction(profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := orch.RecordOutcome(action, probe.FEClosedBEWaiting); err != nil {
		t.Fatal(err)
	}
	if orch.State() != StateVerify {
		t.Fatalf("state = %s, want StateVerify after a confirmed desync", orch.State())
	}
	finding := orch.Finding()
	if finding.Kind != "desync_confirmed" || finding.Confidence != probe.ConfidenceHigh {
		t.Fatalf("finding = %+v, want high-confidence desync_confirmed", finding)
	}

	wantKey := ExperienceKey{
		Host: "lab.test", TLS: "okhttp", Probe: "smuggle", Variant: "cl.te",
		Mutation: "header_folding", TechStack: probe.TechStackHash(profile.TechStack),
	}
	st := orchestratorTestStat(t, store, wantKey)
	if st.Attempts != 1 || st.Successes != 1 {
		t.Fatalf("weights = %d/%d, want 1/1 learned attempts/successes", st.Attempts, st.Successes)
	}
	if !strings.Contains(audit.String(), `"parser_divergence":"FE_Closed_BE_Waiting"`) {
		t.Fatalf("audit lost the FSM verdict: %q", audit.String())
	}
	if !strings.Contains(audit.String(), `"orchestrator_state":"StateFeedback"`) {
		t.Fatalf("audit lost the feedback transition: %q", audit.String())
	}
}

func TestOrchestratorEmitsFeedbackForParserRejectAndQuietRedirect(t *testing.T) {
	cases := []struct {
		name        string
		status      int
		statusShift bool
		ncd         float64
		zscore      float64
		wantReward  float64
		wantDelta   float64
		wantReason  string
	}{
		{
			name: "parser_reject_400", status: 400,
			ncd: 0.42, zscore: 2.5,
			wantReward: -0.1, wantDelta: 0.1, wantReason: "parser_reject",
		},
		{
			name: "quiet_redirect_301", status: 301,
			ncd: 0.12, zscore: -1.25,
			wantReward: -0.15, wantDelta: 0.15, wantReason: "redirect_no_shift",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := orchestratorTestStore()
			var audit bytes.Buffer
			orch := NewOrchestrator(&ExperienceProvider{Store: store}, &audit)
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
			feature := orch.lastFeature
			before := orch.BetaFor(feature)
			orch.ObserveExchange(probe.SignalQuality{
				Status: tc.status, StatusShift: tc.statusShift,
				NCD: tc.ncd, ZScore: tc.zscore, Entropy: 0.5,
				LatencyMS: 12,
			})
			if err := orch.RecordOutcome(action, probe.SyncOK); err != nil {
				t.Fatal(err)
			}

			var feedback map[string]any
			found := false
			for _, line := range strings.Split(strings.TrimSpace(audit.String()), "\n") {
				var event map[string]any
				if err := json.Unmarshal([]byte(line), &event); err != nil {
					t.Fatalf("invalid audit line %q: %v", line, err)
				}
				if event["orchestrator_state"] == string(StateFeedback) {
					feedback, found = event, true
				}
			}
			if !found {
				t.Fatalf("StateFeedback was not emitted: %s", audit.String())
			}
			for key, want := range map[string]float64{
				"reward": tc.wantReward, "beta_delta": tc.wantDelta,
				"alpha_delta": 0, "ncd": tc.ncd, "zscore": tc.zscore,
			} {
				got := 0.0
				if value, ok := feedback[key].(float64); ok {
					got = value
				}
				if math.Abs(got-want) > 1e-9 {
					t.Fatalf("feedback[%q] = %v, want %v: %v", key, feedback[key], want, feedback)
				}
			}
			if feedback["posterior_key"] != feature {
				t.Fatalf("posterior_key = %v, want %q", feedback["posterior_key"], feature)
			}
			if reason, _ := feedback["reason"].(string); reason != tc.wantReason {
				t.Fatalf("reason = %q, want %q: %v", reason, tc.wantReason, feedback)
			}
			after := orch.BetaFor(feature)
			if math.Abs(after.Alpha-before.Alpha) > 1e-9 ||
				math.Abs(after.Beta-before.Beta-tc.wantDelta) > 1e-9 {
				t.Fatalf("posterior = (%v,%v), want (%v,%v)", before.Alpha, before.Beta, after.Alpha, after.Beta)
			}
		})
	}
}

func TestDaemonEmitsFeedbackWithoutRegisteredParserVerdict(t *testing.T) {
	cfg := testConfig(testJob())
	audit := &bytes.Buffer{}
	d, err := New(cfg, &fakeExec{}, nil, audit)
	if err != nil {
		t.Fatal(err)
	}
	orch := d.EnableOrchestrator()
	if _, err := orch.GetBestAction(orchestratorTestProfile()); err != nil {
		t.Fatal(err)
	}
	res := &probe.Result{
		Probe:    "smuggle-chain",
		Duration: 5 * time.Millisecond,
		Responses: []probe.Response{{
			Seq: 1, Status: 400, Raw: "HTTP/1.1 400 Bad Request\r\nContent-Length: 3\r\n\r\nbad", Body: "bad",
		}},
	}
	d.record(&cfg.Jobs[0], 1, res, nil, false)

	feedback := ""
	for _, line := range strings.Split(strings.TrimSpace(audit.String()), "\n") {
		if strings.Contains(line, `"orchestrator_state":"StateFeedback"`) {
			feedback = line
		}
	}
	if feedback == "" {
		t.Fatalf("a 400 without parser divergence lost its feedback line: %s", audit.String())
	}
	for _, want := range []string{
		`"parser_divergence":"SyncOK"`, `"reward":-0.1`, `"beta_delta":0.1`,
		`"ncd":`, `"zscore":`,
	} {
		if !strings.Contains(feedback, want) {
			t.Fatalf("feedback %q is missing %s", feedback, want)
		}
	}
}

func TestParserRejectInPairedExchangeIsNotHiddenByFinalResponse(t *testing.T) {
	cfg := testConfig(testJob())
	audit := &bytes.Buffer{}
	d, err := New(cfg, &fakeExec{}, nil, audit)
	if err != nil {
		t.Fatal(err)
	}
	orch := d.EnableOrchestrator()
	if _, err := orch.GetBestAction(orchestratorTestProfile()); err != nil {
		t.Fatal(err)
	}
	res := &probe.Result{
		Probe:    "differential-fuzz",
		Duration: 5 * time.Millisecond,
		Responses: []probe.Response{
			{Seq: 1, Status: 400, Raw: "HTTP/1.1 400 Bad Request\r\n\r\nbad", Body: "bad"},
			{Seq: 2, Status: 200, Raw: "HTTP/1.1 200 OK\r\n\r\nok", Body: "ok"},
		},
	}
	d.record(&cfg.Jobs[0], 1, res, nil, false)

	feedback := ""
	for _, line := range strings.Split(strings.TrimSpace(audit.String()), "\n") {
		if strings.Contains(line, `"orchestrator_state":"StateFeedback"`) {
			feedback = line
		}
	}
	if feedback == "" {
		t.Fatalf("paired exchange lost its feedback line: %s", audit.String())
	}
	for _, want := range []string{`"reward":-0.1`, `"beta_delta":0.1`, `"reason":"parser_reject"`} {
		if !strings.Contains(feedback, want) {
			t.Fatalf("feedback %q is missing %s", feedback, want)
		}
	}
}

func TestExploreRollDoesNotReuseStaleFSMAction(t *testing.T) {
	cfg := testConfig(testJob())
	audit := &bytes.Buffer{}
	d, err := New(cfg, &fakeExec{}, nil, audit)
	if err != nil {
		t.Fatal(err)
	}
	orch := d.EnableOrchestrator()
	if _, err := orch.GetBestAction(orchestratorTestProfile()); err != nil {
		t.Fatal(err)
	}
	job := cfg.Jobs[0]
	d.applyLearningWithRoll(&job, explorationRoll{explore: true})
	if action := orch.LastAction(); action.Mutation != "" || action.TLSFingerprint != "" {
		t.Fatalf("explore roll kept a stale FSM action: %+v", action)
	}

	res := &probe.Result{
		Probe:    "smuggle-chain",
		Duration: 5 * time.Millisecond,
		Responses: []probe.Response{{
			Seq: 1, Status: 400, Raw: "HTTP/1.1 400 Bad Request\r\n\r\nbad", Body: "bad",
		}},
	}
	d.record(&job, 1, res, nil, false)
	if strings.Contains(audit.String(), `"orchestrator_state":"StateFeedback"`) {
		t.Fatalf("an explore roll with no FSM action emitted feedback: %s", audit.String())
	}
}

func TestOrchestratorEngineFaultCoolsDownProxyWithoutTraining(t *testing.T) {
	store := orchestratorTestStore()
	pr, err := omnislash.NewProxy("http://127.0.0.1:18081", "")
	if err != nil {
		t.Fatal(err)
	}
	cfg := omnislash.DefaultConfig()
	pool, err := omnislash.NewPool(&cfg, []*omnislash.Proxy{pr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var audit bytes.Buffer
	orch := NewOrchestrator(&ExperienceProvider{Store: store, Pool: pool}, &audit)
	orch.SetCooldown(5 * time.Minute)
	action, err := orch.GetBestAction(orchestratorTestProfile())
	if err != nil {
		t.Fatal(err)
	}
	action.Proxy = pr.Label()
	if err := orch.RecordOutcome(action, probe.ParserEngineFault); err != nil {
		t.Fatal(err)
	}

	stats := pool.Stats()
	if len(stats.Proxies) != 1 {
		t.Fatalf("proxy stats = %+v, want one proxy", stats.Proxies)
	}
	if !stats.Proxies[0].InCooldown || stats.Proxies[0].Bans == 0 {
		t.Fatalf("proxy was not cooled down: %+v", stats.Proxies[0])
	}
	wantKey := ExperienceKey{
		Host: "lab.test", TLS: "okhttp", Probe: "smuggle", Variant: "cl.te",
		Mutation: "header_folding", TechStack: probe.TechStackHash([]string{"nginx"}),
	}
	st := orchestratorTestStat(t, store, wantKey)
	if st.Attempts != 0 || st.Successes != 0 {
		t.Fatalf("engine fault was trained as a target response: %d/%d", st.Attempts, st.Successes)
	}
	if st.ProxyFailures != 1 {
		t.Fatalf("proxy failures = %d, want 1", st.ProxyFailures)
	}
	if !strings.Contains(audit.String(), `"parser_divergence":"Engine_Fault"`) {
		t.Fatalf("audit lost the engine fault verdict: %q", audit.String())
	}
}

func TestOrchestratorFailClosedWithoutBrainOrCandidates(t *testing.T) {
	profile := orchestratorTestProfile()
	if _, err := NewOrchestrator(nil, nil).GetBestAction(profile); err == nil {
		t.Fatal("a missing learning provider must refuse every action")
	}
	orch := NewOrchestrator(&ExperienceProvider{Store: orchestratorTestStore()}, nil)
	if err := orch.StartRecon(TargetProfile{Honeypot: true}); err == nil {
		t.Fatal("a honeypot profile must not enter the attack FSM")
	}
	if err := orch.CalibrateWithSemantic(nil, nil, nil, "", false); err == nil {
		t.Fatal("baseline calibration without a semantic client must be refused")
	}
	if err := orch.StartRecon(profile); err != nil {
		t.Fatal(err)
	}
	if err := orch.Calibrate(0.1, true); err == nil {
		t.Fatal("a honeypot baseline must be refused")
	}
	if _, err := orch.GetBestAction(profile); err == nil {
		t.Fatal("a rejected baseline must block every later action")
	}
	if err := orch.StartRecon(profile); err != nil {
		t.Fatal(err)
	}
	empty := profile
	empty.TLSCandidates = nil
	if _, err := orch.GetBestAction(empty); err == nil {
		t.Fatal("undeclared TLS candidates must be refused")
	}
}

type allowAllScope struct{}

func (allowAllScope) CheckTarget(context.Context, string) (string, error) { return "ok", nil }

func TestOrchestratorMinimizeAndReport(t *testing.T) {
	store := orchestratorTestStore()
	var audit bytes.Buffer
	orch := NewOrchestrator(&ExperienceProvider{Store: store}, &audit)
	action, err := orch.GetBestAction(orchestratorTestProfile())
	if err != nil {
		t.Fatal(err)
	}
	if err := orch.RecordOutcome(action, probe.FEClosedBEWaiting); err != nil {
		t.Fatal(err)
	}

	raw := []byte("GET / HTTP/1.1\r\nHost: lab.test\r\nX-Padding: 1\r\n\r\n")
	minimal, err := orch.Minimize(context.Background(), raw, func([]byte) probe.ParserState {
		return probe.FEClosedBEWaiting
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(minimal) == 0 || len(minimal) > len(raw) {
		t.Fatalf("minimal payload = %q, expected a shorter non-empty request", minimal)
	}

	var pushed [][]byte
	orch.SetCaidoPush(func(_ context.Context, findings []json.RawMessage, _, _ string) (int, error) {
		for _, f := range findings {
			pushed = append(pushed, append([]byte(nil), f...))
		}
		return len(findings), nil
	})
	report, err := orch.Report(context.Background(), "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L")
	if err != nil {
		t.Fatal(err)
	}
	if report.Kind != "desync_confirmed" || report.ConfidenceScore != 90 {
		t.Fatalf("report = %+v, want high-confidence desync", report)
	}
	if report.CVSSScore <= 0 || !bytes.Equal(report.MinimalPayload, minimal) {
		t.Fatalf("report CVSS/minimal payload = %v/%q, want a score and %q", report.CVSSScore, report.MinimalPayload, minimal)
	}
	if len(pushed) != 1 {
		t.Fatalf("Caido push count = %d, want 1", len(pushed))
	}

	// The raw-byte mutation path is fail-closed even when the FSM is healthy:
	// with no scope guard no payload may be changed.
	if _, err := orch.Mutate(context.Background(), action, raw, nil, "lab.test:443"); err == nil {
		t.Fatal("mutation without a scope guard must be refused")
	}
	if _, err := orch.Mutate(context.Background(), action, raw, allowAllScope{}, "lab.test:443"); err != nil {
		t.Fatal(err)
	}
}

func TestOrchestratorSonarIsPerPairAndNeedsWarmup(t *testing.T) {
	var audit bytes.Buffer
	orch := NewOrchestrator(&ExperienceProvider{Store: orchestratorTestStore()}, &audit)
	if err := orch.StartRecon(orchestratorTestProfile()); err != nil {
		t.Fatal(err)
	}
	observe := func(host, proxy string, latency float64) probe.SignalQuality {
		orch.ObserveExchange(probe.SignalQuality{
			Host: host, Proxy: proxy, Status: http.StatusOK,
			LatencyMS: latency, NCD: 0.1, Entropy: 0.5,
		})
		return orch.signal
	}

	for i := 0; i < int(probe.SonarMinSamples); i++ {
		got := observe("hostA", "proxy1", 10)
		if got.ZScore != 0 || !got.Uncalibrated {
			t.Fatalf("sample %d: z=%v uncalibrated=%v, want 0/true", i+1, got.ZScore, got.Uncalibrated)
		}
	}
	if got := observe("hostA", "proxy1", 10.5); got.Uncalibrated || math.Abs(got.ZScore) > 100 {
		t.Fatalf("calibrated z=%v uncalibrated=%v", got.ZScore, got.Uncalibrated)
	}
	// A different pair must not inherit hostA/proxy1's tiny variance.
	if got := observe("hostB", "proxy2", 5000); got.ZScore != 0 || !got.Uncalibrated {
		t.Fatalf("pair switch produced a huge Z: z=%v uncalibrated=%v", got.ZScore, got.Uncalibrated)
	}
}
