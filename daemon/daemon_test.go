package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skyrimdlyalohov-droid/omnislash"
	"github.com/skyrimdlyalohov-droid/omnislash/probe"
)

type fakeExec struct {
	mu      sync.Mutex
	calls   int
	failFor int // number of leading calls that return no marker
	tls     []string
}

func (f *fakeExec) Run(ctx context.Context, target probe.Target, p probe.Probe, tlsMode string) (*probe.Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.calls++
	n := f.calls
	f.tls = append(f.tls, tlsMode)
	f.mu.Unlock()

	body := `"No"`
	if n > f.failFor {
		body = `"Unrecognized method GPOST"`
	}
	return &probe.Result{
		Probe:       p.Name(),
		Target:      target.Addr,
		Duration:    5 * time.Millisecond,
		Attribution: probe.Attribution{Verified: false},
		Responses:   []probe.Response{{Seq: 1, Status: 403, Body: body}},
	}, nil
}

func testConfig(jobs ...JobConfig) *Config {
	return &Config{
		OmnislashConfig: "transport.json",
		Jobs:            jobs,
	}
}

func testJob() JobConfig {
	return JobConfig{
		Name:            "lab-clte-gpost",
		Target:          TargetConfig{Addr: "lab.test:443", Host: "lab.test", Path: "/"},
		Probe:           "smuggle-chain",
		SuccessContains: "Unrecognized method GPOST",
		Attempts:        3,
		RetryDelay:      omnislash.Duration(time.Millisecond),
	}
}

func TestRunOnceRetriesUntilMarker(t *testing.T) {
	cfg := testConfig(testJob())
	audit := &bytes.Buffer{}
	exec := &fakeExec{failFor: 2}
	d, err := New(cfg, exec, nil, audit)
	if err != nil {
		t.Fatal(err)
	}
	out := d.RunOnce(context.Background())
	if len(out) != 1 || !out[0].Success {
		t.Fatalf("outcomes = %+v, want one success", out)
	}
	if exec.calls != 3 {
		t.Fatalf("calls = %d, want 3 (two misses then a hit)", exec.calls)
	}
	lines := strings.Split(strings.TrimSpace(audit.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("audit lines = %d, want 3: %s", len(lines), audit.String())
	}
	var rec Record
	if err := json.Unmarshal([]byte(lines[2]), &rec); err != nil {
		t.Fatal(err)
	}
	if !rec.Success || rec.Attempt != 3 || rec.Statuses[0] != 403 {
		t.Fatalf("last record = %+v", rec)
	}
	if !strings.Contains(rec.Result.Responses[0].Body, "GPOST") {
		t.Fatal("audit record lost the evidence body")
	}
}

func TestRunOnceWithoutMarkerSucceedsOnCompletion(t *testing.T) {
	job := testJob()
	job.SuccessContains = ""
	cfg := testConfig(job)
	d, err := New(cfg, &fakeExec{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	out := d.RunOnce(context.Background())
	if len(out) != 1 || !out[0].Success {
		t.Fatalf("outcomes = %+v, want success by completion", out)
	}
}

func TestRunJobRejectsUnknown(t *testing.T) {
	d, err := New(testConfig(testJob()), &fakeExec{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.RunJob(context.Background(), "nope"); err == nil {
		t.Fatal("expected an error for an unknown job")
	}
}

func TestRunExitsOnSuccess(t *testing.T) {
	job := testJob()
	job.Attempts = 1
	job.UntilSuccess = true
	job.Interval = omnislash.Duration(5 * time.Millisecond)
	cfg := testConfig(job)
	cfg.PollInterval = omnislash.Duration(5 * time.Millisecond)
	cfg.ExitOnSuccess = true
	d, err := New(cfg, &fakeExec{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("daemon did not stop after success")
	}
	states := d.Status()
	if len(states) != 1 || states[0].Successes != 1 {
		t.Fatalf("states = %+v", states)
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want string
	}{
		{
			name: "no jobs",
			cfg:  Config{OmnislashConfig: "transport.json"},
			want: "at least one job",
		},
		{
			name: "duplicate",
			cfg:  Config{OmnislashConfig: "transport.json", Jobs: []JobConfig{testJob(), testJob()}},
			want: "duplicate job",
		},
		{
			name: "bad probe",
			cfg: Config{OmnislashConfig: "transport.json", Jobs: []JobConfig{{
				Name: "x", Target: TargetConfig{Addr: "a:1"}, Probe: "sqlmap",
			}}},
			want: "unsupported probe",
		},
		{
			name: "h2race without h2",
			cfg: Config{OmnislashConfig: "transport.json", Jobs: []JobConfig{{
				Name: "x", Target: TargetConfig{Addr: "a:1"}, Probe: "h2race",
			}}},
			want: "requires tls=h2",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestBuildProbeTypes(t *testing.T) {
	cases := []struct {
		probe string
		want  string
	}{
		{"smuggle-chain", "smuggling/cl.te-chain"},
		{"smuggle", "smuggling/cl.te"},
		{"race", "race/single-packet"},
		{"h2race", "race/h2-last-frame"},
	}
	for _, tc := range cases {
		j := JobConfig{Name: "x", Target: TargetConfig{Addr: "a:1"}, Probe: tc.probe}
		p, err := buildProbe(&j)
		if err != nil {
			t.Fatal(err)
		}
		if p.Name() != tc.want {
			t.Fatalf("%s probe name = %q, want %q", tc.probe, p.Name(), tc.want)
		}
	}
}

func TestJobSucceededIgnoresHeadersCase(t *testing.T) {
	j := &JobConfig{SuccessContains: "unrecognized method gpost"}
	res := &probe.Result{Responses: []probe.Response{{
		Status: 403, Headers: []probe.Header{{Key: "X-Error", Value: "Unrecognized method GPOST"}},
	}}}
	if !jobSucceeded(j, res, nil) {
		t.Fatal("marker in a header must count")
	}
	if jobSucceeded(j, nil, errors.New("dial failed")) {
		t.Fatal("an error must never count as success")
	}
}
