package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/skyrimdlyalohov-droid/omnislash"
	"github.com/skyrimdlyalohov-droid/omnislash/probe"
)

func TestConfiguredMutationModesAreExplicit(t *testing.T) {
	modes, err := configuredMutationModes([]string{
		"ows_before_colon", "ows_in_value", "conflicting_framing", "chunk_boundary", "case_mixing",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []probe.MutationMode{
		probe.MutationOWSBeforeColon, probe.MutationOWSInValue,
		probe.MutationConflictingFraming, probe.MutationChunkBoundaryExt,
		probe.MutationCaseMixing,
	}
	if !reflect.DeepEqual(modes, want) {
		t.Fatalf("modes = %v, want %v", modes, want)
	}
	if got, err := configuredMutationModes(nil); err != nil || got != nil {
		t.Fatalf("empty mode list = %v, %v; want nil, nil", got, err)
	}
	if _, err := configuredMutationModes([]string{"auto", "unknown_mode"}); err == nil {
		t.Fatal("unknown mutation mode silently fell back to auto rotation")
	}
}

func TestBuildProbeGadgetJob(t *testing.T) {
	job := &JobConfig{
		Name:              "standalone-gadget",
		Probe:             "gadget",
		GadgetMode:        "unkeyed-cache",
		GadgetHeaders:     []string{"X-Original-URL", "X-Host"},
		GadgetBatchSize:   4,
		GadgetMaxRequests: 12,
		Timeout:           omnislash.Duration(2 * time.Second),
		Idle:              omnislash.Duration(250 * time.Millisecond),
	}
	p, err := buildProbe(job)
	if err != nil {
		t.Fatal(err)
	}
	g, ok := p.(*probe.GadgetProbe)
	if !ok {
		t.Fatalf("probe type = %T, want *probe.GadgetProbe", p)
	}
	if g.Mode != probe.GadgetUnkeyedCache || g.Name() != "gadget/unkeyed-cache" {
		t.Fatalf("mode = %q, name = %q; want unkeyed-cache", g.Mode, g.Name())
	}
	if !reflect.DeepEqual(g.Headers, job.GadgetHeaders) {
		t.Fatalf("headers = %v, want %v", g.Headers, job.GadgetHeaders)
	}
	if g.BatchSize != 4 || g.MaxRequests != 12 || g.Timeout != 2*time.Second || g.Idle != 250*time.Millisecond {
		t.Fatalf("built probe lost job settings: %+v", g)
	}
}

func TestActiveResearchConfigsLoadWithoutDialing(t *testing.T) {
	transport, err := omnislash.LoadConfig("../examples/daemon/config.active-research.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := transport.Validate(); err != nil {
		t.Fatal(err)
	}
	if transport.TrustTier != omnislash.TrustTierStrict || transport.AllowDirect {
		t.Fatalf("transport is not strict and proxy-only: tier=%q direct=%v", transport.TrustTier, transport.AllowDirect)
	}
	if !transport.Scope.Enabled || transport.Scope.AllowPrivate {
		t.Fatalf("scope is not strict: %+v", transport.Scope)
	}
	if !transport.Probe.MutationEnabled || len(transport.Probe.MutationModes) != 4 {
		t.Fatalf("rare framing rotation is not configured: %+v", transport.Probe)
	}
	if !transport.Health.Enabled || !transport.Health.StartupCheck {
		t.Fatal("startup healthcheck is not configured")
	}

	cfg, err := LoadConfig("../examples/daemon/daemon-active-research.json")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(cfg.OmnislashConfig, "config.active-research.json") {
		t.Fatalf("omnislash_config = %q", cfg.OmnislashConfig)
	}
	if cfg.FullAuto.GadgetMode != "standalone" || !cfg.FullAuto.AutoCaidoPush {
		t.Fatalf("full_auto gadget settings = %+v", cfg.FullAuto)
	}
	if len(cfg.Jobs) != 2 || cfg.Jobs[0].Probe != "gadget" || cfg.Jobs[0].GadgetMode != "standalone" {
		t.Fatalf("jobs = %+v", cfg.Jobs)
	}
	if cfg.Jobs[0].AutoCaidoPush == nil || !*cfg.Jobs[0].AutoCaidoPush {
		t.Fatal("standalone job did not opt in to Caido auto-push")
	}
}

func TestMaybeAutoPushCaidoForwardsRawExchange(t *testing.T) {
	t.Setenv("CAIDO_URL", "")
	t.Setenv("CAIDO_PAT", "test-pat")

	d, err := New(testConfig(testJob()), &fullAutoExec{}, nil, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	var calls int
	var records []json.RawMessage
	var gotURL, gotPAT string
	d.ui.CaidoPush = func(_ context.Context, findings []json.RawMessage, target, pat string) (int, error) {
		calls++
		records = append(records, findings...)
		gotURL, gotPAT = target, pat
		return len(findings), nil
	}

	res := &probe.Result{
		Findings: []probe.Finding{
			{Kind: FindingTargetRejectedName, Confidence: probe.ConfidenceLow, Detail: "diagnostic"},
			{Kind: "gadget_reflected", Confidence: probe.ConfidenceHigh, Detail: "canary reflected in Location header"},
		},
		Responses: []probe.Response{{Seq: 2, Status: 301}},
		Exchanges: []probe.Exchange{{Seq: 2, Raw: "GET /?_omni_cb=abc HTTP/1.1\r\nHost: lab.test\r\n\r\n"}},
	}
	on := true
	job := testJob()
	job.AutoCaidoPush = &on
	d.maybeAutoPushCaido(context.Background(), &job, res)
	if calls != 1 {
		t.Fatalf("push calls = %d, want 1", calls)
	}
	if gotURL != "http://127.0.0.1:8080/graphql" || gotPAT != "test-pat" {
		t.Fatalf("push endpoint = %q, PAT = %q", gotURL, gotPAT)
	}
	if len(records) != 1 {
		t.Fatalf("pushed records = %d, want 1", len(records))
	}
	line := string(records[0])
	var pushed map[string]json.RawMessage
	if err := json.Unmarshal(records[0], &pushed); err != nil {
		t.Fatal(err)
	}
	var topFindings []probe.Finding
	if err := json.Unmarshal(pushed["findings"], &topFindings); err != nil {
		t.Fatal(err)
	}
	if len(topFindings) != 1 || topFindings[0].Kind != "gadget_reflected" {
		t.Fatalf("top-level findings = %+v, want only the confirmed gadget", topFindings)
	}
	if !strings.Contains(line, "_omni_cb=abc") {
		t.Fatalf("raw exchange was not forwarded for replay: %s", line)
	}

	// Opt-in is per job and only high-confidence confirmed verdicts are sent.
	off := false
	job.AutoCaidoPush = &off
	d.maybeAutoPushCaido(context.Background(), &job, res)
	res.Findings = []probe.Finding{{Kind: "gadget_reflected", Confidence: probe.ConfidenceMedium}}
	job.AutoCaidoPush = &on
	d.maybeAutoPushCaido(context.Background(), &job, res)
	if calls != 1 {
		t.Fatalf("push calls = %d, want 1 after opt-out and low confidence", calls)
	}
}

// FindingTargetRejectedName is spelled out here so the test does not rely on a
// probe-internal constant being exported across packages.
const FindingTargetRejectedName = "target_rejected"
