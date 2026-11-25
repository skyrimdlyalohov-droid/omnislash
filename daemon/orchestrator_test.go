package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/skyrimdlyalohov-droid/omnislash"
	"github.com/skyrimdlyalohov-droid/omnislash/probe"
)

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
