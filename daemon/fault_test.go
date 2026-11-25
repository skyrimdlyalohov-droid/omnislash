package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/skyrimdlyalohov-droid/omnislash"
	"github.com/skyrimdlyalohov-droid/omnislash/probe"
)

// faultExec fails every probe with a local correctness error while still
// returning the partial result a real runner would have collected.
type faultExec struct {
	err error
}

func (f faultExec) Run(context.Context, probe.Target, probe.Probe, string) (*probe.Result, error) {
	res := &probe.Result{
		Probe:       "smuggle-chain",
		Attribution: probe.Attribution{Verified: false},
		Responses:   []probe.Response{{Seq: 1, Status: 403, Body: `"No"`}},
	}
	return res, f.err
}

func TestEngineFaultIsNeverTrainable(t *testing.T) {
	for _, label := range []OutcomeLabel{OutcomeEngineFault, OutcomeProxyFailed} {
		if label.Trainable() {
			t.Fatalf("%s must not be trainable", label)
		}
	}
	for _, slug := range []string{"engine-fault", "engine_fault", "engine fault"} {
		label, ok := ParseOutcomeLabel(slug)
		if !ok || label != OutcomeEngineFault {
			t.Fatalf("outcome alias %q = %v, %v", slug, label, ok)
		}
	}
}

func TestDeceptionUncertainIsEngineFaultInJSONL(t *testing.T) {
	job := testJob()
	job.Attempts = 1
	cfg := testConfig(job)
	audit := &bytes.Buffer{}
	d, err := New(cfg, faultExec{err: fmt.Errorf("%w: semantic analyzer crashed", omnislash.ErrDeceptionUncertain)}, nil, audit)
	if err != nil {
		t.Fatal(err)
	}

	out := d.RunOnce(context.Background())
	if len(out) != 1 || out[0].Success {
		t.Fatalf("outcomes = %+v, want one failed attempt", out)
	}
	if !strings.Contains(audit.String(), `"outcome":"Engine Fault"`) {
		t.Fatalf("audit does not classify the fault as Engine Fault: %s", audit.String())
	}
	if !strings.Contains(audit.String(), `"deception_uncertain":true`) {
		t.Fatalf("audit does not mark deception_uncertain: %s", audit.String())
	}

	var rec Record
	if err := json.Unmarshal([]byte(strings.TrimSpace(audit.String())), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Outcome != string(OutcomeEngineFault) || !rec.DeceptionUncertain {
		t.Fatalf("record = %+v", rec)
	}
}

type parserExec struct {
	state string
}

func (p parserExec) Run(context.Context, probe.Target, probe.Probe, string) (*probe.Result, error) {
	return &probe.Result{
		Probe:            "smuggle",
		ParserDivergence: p.state,
		Responses:        []probe.Response{{Seq: 1, Status: 200, Body: "ok"}},
	}, nil
}

func TestParserDivergenceAndDesyncFindingAreAudited(t *testing.T) {
	job := testJob()
	job.Attempts = 1
	cfg := testConfig(job)
	audit := &bytes.Buffer{}
	d, err := New(cfg, parserExec{state: string(probe.FEClosedBEWaiting)}, nil, audit)
	if err != nil {
		t.Fatal(err)
	}

	if out := d.RunOnce(context.Background()); len(out) != 1 {
		t.Fatalf("outcomes = %+v, want one attempt", out)
	}

	var rec Record
	if err := json.Unmarshal([]byte(strings.TrimSpace(audit.String())), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.ParserDivergence != string(probe.FEClosedBEWaiting) {
		t.Fatalf("parser_divergence = %q", rec.ParserDivergence)
	}
	found := false
	for _, f := range rec.Findings {
		if f.Kind == "desync_confirmed" && f.Confidence == probe.ConfidenceHigh {
			found = true
		}
	}
	if !found {
		t.Fatalf("findings = %+v, want high-confidence desync_confirmed", rec.Findings)
	}
}

func TestParserEngineFaultIsNotTrainable(t *testing.T) {
	job := testJob()
	job.Attempts = 1
	cfg := testConfig(job)
	audit := &bytes.Buffer{}
	d, err := New(cfg, parserExec{state: string(probe.EngineFault)}, nil, audit)
	if err != nil {
		t.Fatal(err)
	}

	d.RunOnce(context.Background())
	if !strings.Contains(audit.String(), `"outcome":"Engine Fault"`) {
		t.Fatalf("parser engine fault was not classified: %s", audit.String())
	}
}

func TestRecoveredPanicIsEngineFaultInJSONL(t *testing.T) {
	job := testJob()
	job.Attempts = 1
	cfg := testConfig(job)
	audit := &bytes.Buffer{}
	d, err := New(cfg, faultExec{err: fmt.Errorf("%w: probe panic", omnislash.ErrPrecisionLost)}, nil, audit)
	if err != nil {
		t.Fatal(err)
	}

	out := d.RunOnce(context.Background())
	if len(out) != 1 || out[0].Success {
		t.Fatalf("outcomes = %+v, want one failed attempt", out)
	}
	if !strings.Contains(audit.String(), `"outcome":"Engine Fault"`) {
		t.Fatalf("audit does not classify the recovered panic as Engine Fault: %s", audit.String())
	}
	if strings.Contains(audit.String(), `"deception_uncertain":true`) {
		t.Fatalf("panic was mislabeled as deception uncertainty: %s", audit.String())
	}
}
