package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/skyrimdlyalohov-droid/omnislash/probe"
)

func TestLearningPolicyDefaultsAndDecay(t *testing.T) {
	p := LearningPolicy{}.withDefaults()
	if p.Epsilon < 0.10 || p.Epsilon > 0.15 {
		t.Fatalf("default epsilon = %v, want the 10-15%% band", p.Epsilon)
	}
	if got := p.epsilonAt(0); got != p.Epsilon {
		t.Fatalf("epsilon at 0 = %v, want %v", got, p.Epsilon)
	}
	middle := p.epsilonAt(100)
	if !(middle < p.Epsilon && middle > p.EpsilonMin) {
		t.Fatalf("epsilon at 100 = %v, want between %v and %v", middle, p.Epsilon, p.EpsilonMin)
	}
	if got := p.epsilonAt(100000); got != p.EpsilonMin {
		t.Fatalf("epsilon floor = %v, want %v", got, p.EpsilonMin)
	}
	if cfg := testConfig(testJob()); cfg.Validate() != nil {
		t.Fatalf("default learning policy failed validation: %v", cfg.Validate())
	}
	cfg := testConfig(testJob())
	cfg.LearningPolicy.EpsilonDecay = 2
	if err := cfg.Validate(); err == nil {
		t.Fatal("epsilon_decay > 1 was accepted")
	}
	cfg.LearningPolicy.EpsilonDecay = 0.995
	cfg.LearningPolicy.Epsilon = 0.01
	cfg.LearningPolicy.EpsilonMin = 0.02
	if err := cfg.Validate(); err == nil {
		t.Fatal("epsilon_min > epsilon was accepted")
	}
}

func TestEpsilonRollIsSharedAcrossRankingStages(t *testing.T) {
	cfg := testConfig()
	cfg.LearningPolicy.Epsilon = 1
	cfg.LearningPolicy.EpsilonMin = 1
	cfg.LearningPolicy.EpsilonDecay = 1
	d := &Daemon{
		cfg:       *cfg,
		learning:  NewExperienceStore(""),
		rollFn:    func() float64 { return 0.01 },
		shuffleFn: func(n int, swap func(i, j int)) { swap(0, n-1) },
	}
	roll := d.exploration()
	if !roll.explore {
		t.Fatal("roll below epsilon did not explore")
	}
	job := &JobConfig{
		Target:          TargetConfig{Addr: "lab.test:443", Host: "lab.test"},
		TLS:             "h2",
		Probe:           "differential-fuzz",
		DeclaredLengths: []int{3, 4, 5},
		Mutations:       []string{"ctl_nul", "te_obfuscation", "space_pad"},
	}
	got := d.applyLearningWithRoll(job, roll)
	if got.Mutations[0] != "space_pad" || got.DeclaredLengths[0] != 5 {
		t.Fatalf("exploration did not bypass both stages: mutations=%v lengths=%v", got.Mutations, got.DeclaredLengths)
	}
	exploited := d.applyLearning(job)
	if exploited.Mutations[0] != "ctl_nul" || exploited.DeclaredLengths[0] != 3 {
		t.Fatalf("exploitation changed the declared order: mutations=%v lengths=%v", exploited.Mutations, exploited.DeclaredLengths)
	}
}

func TestExecuteTakesOneEpsilonRollPerAttempt(t *testing.T) {
	cfg := testConfig(testJob())
	cfg.LearningPolicy.Epsilon = 1
	cfg.LearningPolicy.EpsilonMin = 1
	cfg.LearningPolicy.EpsilonDecay = 1
	audit := &bytes.Buffer{}
	d, err := New(cfg, &fakeExec{failFor: 2}, nil, audit)
	if err != nil {
		t.Fatal(err)
	}
	rolls := 0
	d.rollFn = func() float64 { rolls++; return 0.01 }
	out := d.RunOnce(context.Background())
	if !out[0].Success {
		t.Fatalf("outcome = %+v, want success", out)
	}
	if rolls != 3 {
		t.Fatalf("epsilon rolls = %d, want one per attempt (3)", rolls)
	}
	if got := d.observations.Load(); got != 3 {
		t.Fatalf("observations = %d, want 3", got)
	}
	for _, line := range bytes.Split(bytes.TrimSpace(audit.Bytes()), []byte("\n")) {
		var rec Record
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Fatal(err)
		}
		if !rec.Explore {
			t.Fatalf("attempt %d was not marked as exploration", rec.Attempt)
		}
		if rec.Outcome != string(OutcomeTargetResponse) {
			t.Fatalf("attempt %d outcome = %q, want target response", rec.Attempt, rec.Outcome)
		}
	}
}

func TestOutcomeClassificationSeparatesFailuresFromResponses(t *testing.T) {
	cases := []struct {
		name string
		res  *probe.Result
		err  error
		want OutcomeLabel
	}{
		{
			name: "proxy failure",
			err:  errors.New("dial tcp: no usable proxy"),
			want: OutcomeProxyFailed,
		},
		{
			name: "waf block",
			res: &probe.Result{Responses: []probe.Response{{
				Status:  403,
				Headers: []probe.Header{{Key: "cf-ray", Value: "abc"}},
				Body:    "blocked",
			}}},
			want: OutcomeWAFBlocked,
		},
		{
			name: "target parser rejection",
			res: &probe.Result{Responses: []probe.Response{{
				Status: 400, Body: `{"error":"Invalid request"}`,
			}}},
			want: OutcomeTargetRejected,
		},
		{
			name: "target response",
			res: &probe.Result{Responses: []probe.Response{{
				Status: 200, Body: "ok",
			}}},
			want: OutcomeTargetResponse,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyOutcome(tc.res, tc.err); got != tc.want {
				t.Fatalf("outcome = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestExperienceStoreNeverTrainsOnProxyFailures(t *testing.T) {
	s := NewExperienceStore("")
	base := ExperienceKey{Host: "lab.test", TLS: "h1", Probe: "smuggle"}
	key := base
	key.Variant = "cl.te"
	s.Observe(Record{Target: "lab.test:443", Probe: "smuggle", TLS: "h1",
		Learning: LearningMeta{Host: "lab.test", Variant: "cl.te"},
		Outcome:  string(OutcomeProxyFailed), Error: "proxy dial failed"})
	st, ok := s.statFor(key)
	if !ok {
		t.Fatal("proxy failure did not create an outcome counter")
	}
	if st.Attempts != 0 || st.Successes != 0 || st.ProxyFailures != 1 {
		t.Fatalf("proxy failure was trained on: attempts=%d successes=%d proxy_failures=%d",
			st.Attempts, st.Successes, st.ProxyFailures)
	}

	s.Observe(Record{Target: "lab.test:443", Probe: "smuggle", TLS: "h1",
		Learning: LearningMeta{Host: "lab.test", Variant: "cl.te"},
		Outcome:  string(OutcomeWAFBlocked), Success: true})
	s.Observe(Record{Target: "lab.test:443", Probe: "smuggle", TLS: "h1",
		Learning: LearningMeta{Host: "lab.test", Variant: "cl.te"},
		Outcome:  string(OutcomeTargetRejected), Success: true})
	s.Observe(Record{Target: "lab.test:443", Probe: "smuggle", TLS: "h1",
		Learning: LearningMeta{Host: "lab.test", Variant: "cl.te"},
		Outcome:  string(OutcomeTargetResponse), Success: true})
	st, _ = s.statFor(key)
	if st.Attempts != 3 || st.Successes != 1 {
		t.Fatalf("counters = attempts %d successes %d, want 3/1", st.Attempts, st.Successes)
	}
	if st.WAFBlocks != 1 || st.TargetRejects != 1 || st.TargetResponses != 1 {
		t.Fatalf("outcome classes = %+v", st)
	}
}
