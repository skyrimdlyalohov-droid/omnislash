package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skyrimdlyalohov-droid/omnislash"
	"github.com/skyrimdlyalohov-droid/omnislash/probe"
)

type fullAutoExec struct {
	mu            sync.Mutex
	names         []string
	reconStatus   int
	fuzzClean     bool
	gadgetFinding *probe.Finding
}

func (f *fullAutoExec) Run(_ context.Context, target probe.Target, p probe.Probe, _ string) (*probe.Result, error) {
	f.mu.Lock()
	f.names = append(f.names, p.Name())
	f.mu.Unlock()
	if strings.HasPrefix(p.Name(), "gadget/") && f.gadgetFinding != nil {
		return &probe.Result{
			Probe:     p.Name(),
			Target:    target.Addr,
			Duration:  5 * time.Millisecond,
			Findings:  []probe.Finding{*f.gadgetFinding},
			Responses: []probe.Response{{Seq: 1, Status: 301, Body: "ok"}},
			Exchanges: []probe.Exchange{{Seq: 1, Raw: "GET / HTTP/1.1\r\nHost: " + target.HostHeader() + "\r\n\r\n"}},
		}, nil
	}
	switch p.Name() {
	case "fullauto/recon":
		status := f.reconStatus
		if status == 0 {
			status = 200
		}
		body := "ok"
		raw := fmt.Sprintf("HTTP/1.1 %d OK\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n%s", status, len(body), body)
		return &probe.Result{
			Probe:     p.Name(),
			Target:    target.Addr,
			Duration:  5 * time.Millisecond,
			Responses: []probe.Response{{Seq: 1, Status: status, Body: body, Raw: raw, Framing: "content-length", Headers: []probe.Header{{Key: "Content-Type", Value: "text/html"}}}},
			Exchanges: []probe.Exchange{{Seq: 1, Raw: "GET " + target.RequestPath() + " HTTP/1.1\r\nHost: " + target.HostHeader() + "\r\n\r\n"}},
		}, nil
	case "differential-fuzz":
		raw := "GET /?x=1 HTTP/1.1\r\nHost: lab.test\r\nTransfer-Encoding: chunked\r\n\r\n1;omnislash=1\r\nX\r\n0\r\n\r\n"
		res := &probe.Result{
			Probe:     p.Name(),
			Target:    target.Addr,
			Duration:  5 * time.Millisecond,
			Responses: []probe.Response{{Seq: 1, Status: 200, Body: "ok", Raw: "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"}},
			Exchanges: []probe.Exchange{{Seq: 1, Raw: raw}},
		}
		if !f.fuzzClean {
			res.ParserDivergence = string(probe.FEClosedBEWaiting)
			res.Findings = []probe.Finding{{Kind: "desync_confirmed", Confidence: probe.ConfidenceHigh, Detail: "test finding"}}
		}
		return res, nil
	default:
		return nil, fmt.Errorf("unexpected probe %s", p.Name())
	}
}

func (f *fullAutoExec) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.names...)
}

type fullAutoTestScope struct{ enabled bool }

func (s fullAutoTestScope) Enabled() bool { return s.enabled }

func (s fullAutoTestScope) CheckTarget(_ context.Context, target string) (string, error) {
	return target, nil
}

type countingImpact struct{ calls int }

func (c *countingImpact) Validate(context.Context, probe.Finding, []byte) error {
	c.calls++
	return nil
}

func fullAutoTestConfig(t *testing.T, exec *fullAutoExec) (*Daemon, *bytes.Buffer, *countingImpact) {
	t.Helper()
	cfg := testConfig(testJob())
	cfg.FullAuto = FullAutoConfig{
		Enabled:            true,
		Endpoints:          []string{"/"},
		TLS:                "h1",
		Pairs:              1,
		BaselineSamples:    2,
		RateLimit:          omnislash.Duration(-1), // test only: no pacing
		WAFCooldown:        omnislash.Duration(5 * time.Minute),
		StopStatuses:       []int{429, 503},
		BlockStatuses:      []int{403},
		BlockThreshold:     1,
		ImpactPaths:        []string{"/pay", "/admin"},
		PoCDir:             t.TempDir(),
		Timeout:            omnislash.Duration(time.Second),
		Idle:               omnislash.Duration(10 * time.Millisecond),
		MutationCandidates: []string{"chunk_extensions", "boundary_shift"},
		SmuggleVariants:    []string{string(probe.VariantCLTE)},
	}
	audit := &bytes.Buffer{}
	d, err := New(cfg, exec, nil, audit)
	if err != nil {
		t.Fatal(err)
	}
	d.SetUI(omnislash.UIOptions{Config: &omnislash.Config{
		Scope: omnislash.ScopeConfig{
			Enabled:      true,
			AllowHosts:   []string{"lab.test"},
			AllowPrivate: false,
		},
		AllowDirect: false,
	}})
	d.SetFullAutoScope(fullAutoTestScope{enabled: true})
	impact := &countingImpact{}
	d.SetImpactValidator(impact)
	return d, audit, impact
}

// TestFullAutoStopsOnFindingAndAwaitsHumanVerification is the safety contract:
// a confirmed desync ends the pipeline, the PoC is persisted, and no impact
// validator runs until a human supplies --force-impact.
func TestFullAutoStopsOnFindingAndAwaitsHumanVerification(t *testing.T) {
	exec := &fullAutoExec{}
	d, audit, impact := fullAutoTestConfig(t, exec)

	res, err := d.ExecuteSafePipeline(context.Background(), Target{Addr: "lab.test:443", Host: "lab.test", Path: "/"})
	if err != nil {
		t.Fatalf("pipeline error: %v", err)
	}
	if res.State != StateAwaitingHumanVerification {
		t.Fatalf("state = %s, want %s", res.State, StateAwaitingHumanVerification)
	}
	if res.Finding == nil || res.Finding.Kind != "desync_confirmed" {
		t.Fatalf("finding = %+v, want desync_confirmed", res.Finding)
	}
	if res.POCB64 == "" || res.POCRaw == "" || res.POCPath == "" {
		t.Fatalf("PoC not persisted: b64=%q raw=%q path=%q", res.POCB64, res.POCRaw, res.POCPath)
	}
	if impact.calls != 0 {
		t.Fatalf("impact validator calls = %d, want 0 without --force-impact", impact.calls)
	}
	if got := d.orchestrator.State(); got != StateAwaitingHumanVerification {
		t.Fatalf("orchestrator state = %s, want %s", got, StateAwaitingHumanVerification)
	}
	if got := d.orchestrator.Phase(); got == PhaseConfirmed {
		t.Fatalf("FSM phase = %s; a finding must not be auto-confirmed", got)
	}

	calls := exec.calls()
	want := []string{"fullauto/recon", "fullauto/recon", "fullauto/recon", "fullauto/recon", "differential-fuzz", "gadget/binary-search"}
	if strings.Join(calls, ",") != strings.Join(want, ",") {
		t.Fatalf("probe calls = %v, want %v (two baseline GETs, two endpoint GETs, differential-fuzz, then the chained gadget stage; smuggling must not run after a finding)", calls, want)
	}

	lines := strings.Split(strings.TrimSpace(audit.String()), "\n")
	var found bool
	for _, line := range lines {
		if !strings.Contains(line, `"orchestrator_state":"AWAITING_HUMAN_VERIFICATION"`) {
			continue
		}
		if !strings.Contains(line, `"poc_b64"`) {
			// The orchestrator also emits its own AWAITING transition; the
			// full-auto event is the one that carries the saved PoC.
			continue
		}
		found = true
		var ev FullAutoEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("bad full-auto JSONL: %v", err)
		}
		if ev.POCB64 == "" || ev.POCRaw == "" || ev.POCPath == "" {
			t.Fatalf("AWAITING event lost the PoC: %+v", ev)
		}
	}
	if !found {
		t.Fatalf("audit has no AWAITING_HUMAN_VERIFICATION line:\n%s", audit.String())
	}
}

// TestFullAutoStandaloneGadgetStageRunsBeforeDesync proves mode B is reachable
// on a live target that never produced a parser divergence.
func TestFullAutoStandaloneGadgetStageRunsBeforeDesync(t *testing.T) {
	exec := &fullAutoExec{
		fuzzClean: true,
		gadgetFinding: &probe.Finding{
			Kind:       "cache_poisoned",
			Confidence: probe.ConfidenceHigh,
			Detail:     "canary retained on clean GET",
		},
	}
	d, _, _ := fullAutoTestConfig(t, exec)
	d.cfg.FullAuto.GadgetMode = "standalone"
	d.cfg.FullAuto.GadgetHeaders = []string{"X-Original-URL"}

	res, err := d.ExecuteSafePipeline(context.Background(), Target{Addr: "lab.test:443", Host: "lab.test", Path: "/"})
	if err != nil {
		t.Fatal(err)
	}
	if res.State != StateAwaitingHumanVerification || res.Finding == nil || res.Finding.Kind != "cache_poisoned" {
		t.Fatalf("result = %+v, want a confirmed cache gadget", res)
	}
	calls := exec.calls()
	joined := strings.Join(calls, ",")
	if !strings.Contains(joined, "gadget/unkeyed-cache") {
		t.Fatalf("standalone gadget stage was skipped: %v", calls)
	}
	if strings.Contains(joined, "smuggle") {
		t.Fatalf("smuggling ran after a confirmed gadget: %v", calls)
	}
}

func TestFullAutoRefusesPrivateLiteralBeforeDial(t *testing.T) {
	exec := &fullAutoExec{}
	d, _, _ := fullAutoTestConfig(t, exec)

	res, err := d.ExecuteSafePipeline(context.Background(), Target{Addr: "10.0.0.1:443", Host: "10.0.0.1", Path: "/"})
	if err == nil || !strings.Contains(err.Error(), "private address") {
		t.Fatalf("error = %v, want private-address refusal", err)
	}
	if res.State != StateBlocked {
		t.Fatalf("state = %s, want %s", res.State, StateBlocked)
	}
	if calls := exec.calls(); len(calls) != 0 {
		t.Fatalf("private target reached the executor: %v", calls)
	}
}

func TestFullAutoCooldownStopsAndSkipsNextRun(t *testing.T) {
	exec := &fullAutoExec{reconStatus: 429}
	d, audit, _ := fullAutoTestConfig(t, exec)

	res, err := d.ExecuteSafePipeline(context.Background(), Target{Addr: "lab.test:443", Host: "lab.test", Path: "/"})
	if err == nil || !strings.Contains(err.Error(), "cooling") {
		t.Fatalf("error = %v, want WAF cooldown", err)
	}
	if res.State != StateCooldown {
		t.Fatalf("state = %s, want %s", res.State, StateCooldown)
	}
	first := exec.calls()
	if len(first) != 1 {
		t.Fatalf("probe calls = %v, want one recon GET", first)
	}
	if !strings.Contains(audit.String(), `"orchestrator_state":"COOLDOWN"`) {
		t.Fatalf("audit has no COOLDOWN line:\n%s", audit.String())
	}

	if _, err := d.ExecuteSafePipeline(context.Background(), Target{Addr: "lab.test:443", Host: "lab.test", Path: "/"}); err == nil {
		t.Fatal("second run during cooldown returned nil error")
	}
	if calls := exec.calls(); len(calls) != len(first) {
		t.Fatalf("cooldown sent another probe: %v", calls)
	}
}

func TestFullAutoImpactPathRequiresForceFlag(t *testing.T) {
	exec := &fullAutoExec{}
	d, _, _ := fullAutoTestConfig(t, exec)

	res, err := d.ExecuteSafePipeline(context.Background(), Target{Addr: "lab.test:443", Host: "lab.test", Path: "/admin"})
	if err == nil || !strings.Contains(err.Error(), "force-impact") {
		t.Fatalf("error = %v, want impact refusal", err)
	}
	if res.State != StateBlocked {
		t.Fatalf("state = %s, want %s", res.State, StateBlocked)
	}
	if calls := exec.calls(); len(calls) != 0 {
		t.Fatalf("impact path reached the executor: %v", calls)
	}
}

// TestFullAutoRejectsPOSTOnlyMutationOutsideSafePaths is the mutation
// counterpart of the impact gate: a POST-emitting mutation may only run on an
// endpoint explicitly listed in safe_post_paths. Otherwise the pipeline stops
// before recon and no request is sent.
func TestFullAutoRejectsPOSTOnlyMutationOutsideSafePaths(t *testing.T) {
	exec := &fullAutoExec{}
	d, _, _ := fullAutoTestConfig(t, exec)
	d.cfg.FullAuto.MutationCandidates = []string{"cl_te_duplicate"}

	res, err := d.ExecuteSafePipeline(context.Background(), Target{Addr: "lab.test:443", Host: "lab.test", Path: "/"})
	if err == nil || !strings.Contains(err.Error(), "GET-only") {
		t.Fatalf("error = %v, want GET-only refusal", err)
	}
	if res.State != StateBlocked {
		t.Fatalf("state = %s, want %s", res.State, StateBlocked)
	}
	if calls := exec.calls(); len(calls) != 0 {
		t.Fatalf("POST-only mutation reached the executor: %v", calls)
	}
}

// TestFullAutoRefusesSessionBannedTarget proves a honeypot/tarpit ban from an
// earlier target is enforced before any new request, not only after recon.
func TestFullAutoRefusesSessionBannedTarget(t *testing.T) {
	exec := &fullAutoExec{}
	d, _, _ := fullAutoTestConfig(t, exec)
	rt, err := d.ensureFullAuto()
	if err != nil {
		t.Fatal(err)
	}
	rt.filter.BanTarget("lab.test", "/", "tarpit template", omnislash.DeceptionTarpit, time.Minute)

	res, err := d.ExecuteSafePipeline(context.Background(), Target{Addr: "lab.test:443", Host: "lab.test", Path: "/"})
	if err == nil || !strings.Contains(err.Error(), "tarpit") {
		t.Fatalf("error = %v, want session-ban refusal", err)
	}
	if res.State != StateBlocked {
		t.Fatalf("state = %s, want %s", res.State, StateBlocked)
	}
	if calls := exec.calls(); len(calls) != 0 {
		t.Fatalf("banned target reached the executor: %v", calls)
	}
}

// TestFullAutoRefusesDisabledScope proves the pipeline never degrades to an
// unchecked mode when scope.enabled is false.
func TestFullAutoRefusesDisabledScope(t *testing.T) {
	exec := &fullAutoExec{}
	d, _, _ := fullAutoTestConfig(t, exec)
	d.SetFullAutoScope(fullAutoTestScope{enabled: false})

	_, err := d.ExecuteSafePipeline(context.Background(), Target{Addr: "lab.test:443", Host: "lab.test", Path: "/"})
	if err == nil || !strings.Contains(err.Error(), "scope.enabled") {
		t.Fatalf("error = %v, want disabled-scope refusal", err)
	}
	if calls := exec.calls(); len(calls) != 0 {
		t.Fatalf("disabled scope reached the executor: %v", calls)
	}
}
