package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func learningRecord(host, tls, probe, variant, mutation string, success bool) Record {
	return Record{
		Time:    time.Unix(1700000000, 0),
		Target:  host + ":443",
		Probe:   probe,
		TLS:     tls,
		Success: success,
		Learning: LearningMeta{
			Host:     host,
			Variant:  variant,
			Mutation: mutation,
		},
	}
}

func TestExperienceStoreLoadsAuditAndRanks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	records := []Record{
		learningRecord("lab.test", "h1", "smuggle-chain", "cl.te", "", false),
		learningRecord("lab.test", "h1", "smuggle-chain", "te.cl", "", true),
	}
	for _, rec := range records {
		b, err := json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(append(b, '\n')); err != nil {
			t.Fatal(err)
		}
	}
	_ = f.Close()

	s := NewExperienceStore(path)
	if err := s.Load(); err != nil {
		t.Fatal(err)
	}
	base := ExperienceKey{Host: "lab.test", TLS: "h1", Probe: "smuggle-chain"}
	got := s.Rank(base, []string{"cl.te", "te.cl"})
	if got[0] != "te.cl" {
		t.Fatalf("rank = %v, want te.cl first", got)
	}
	if len(s.Summary()) < 2 {
		t.Fatalf("summary cells = %d, want at least 2", len(s.Summary()))
	}
	foundGlobal := false
	for _, st := range s.Summary() {
		if st.Key.Host == "*" && st.Successes == 1 {
			foundGlobal = true
		}
	}
	if !foundGlobal {
		t.Fatalf("summary lost the host-independent prior: %+v", s.Summary())
	}
}

func TestExperienceGlobalPriorAppliesToNewHost(t *testing.T) {
	s := NewExperienceStore("")
	s.Observe(learningRecord("old-lab.test", "h1", "smuggle-chain", "te.cl", "", true))
	base := ExperienceKey{Host: "new-lab.test", TLS: "h1", Probe: "smuggle-chain"}
	got := s.Rank(base, []string{"cl.te", "te.cl"})
	if got[0] != "te.cl" {
		t.Fatalf("rank on a new host = %v, want te.cl from the global prior", got)
	}
}

func TestExperienceSeedStaysVisibleAndRanks(t *testing.T) {
	s := NewExperienceStore("")
	s.Seed([]ExperienceSeed{{
		Host:       "*",
		TLS:        "h2",
		Probe:      "h2-cl",
		TechStack:  "h2",
		Mutation:   "cl=0",
		Attempts:   3,
		Successes:  2,
		Provenance: "solution-derived",
		Source:     "playbook:h2-cl-resources-redirect",
	}})
	base := ExperienceKey{Host: "new-lab.test", TLS: "h2", Probe: "h2-cl", TechStack: "h2"}
	query := base
	query.Mutation = "cl=0"
	got := s.RankMutations(base, []string{"cl=1", "cl=0"})
	if got[0] != "cl=0" {
		t.Fatalf("rank = %v, want seeded candidate first", got)
	}
	st, ok := s.statFor(query)
	if !ok {
		t.Fatal("global seed not found for a new host")
	}
	if st.Attempts != 0 || st.Successes != 0 {
		t.Fatalf("seed was recorded as observed evidence: attempts=%d successes=%d", st.Attempts, st.Successes)
	}
	if st.SeedAttempts != 3 || st.SeedSuccesses != 2 {
		t.Fatalf("seed counters = %d/%d, want 3/2", st.SeedAttempts, st.SeedSuccesses)
	}
	if len(st.SeedSources) != 1 || st.SeedSources[0] != "solution-derived:playbook:h2-cl-resources-redirect" {
		t.Fatalf("seed sources = %v", st.SeedSources)
	}
}

func TestApplyLearningPrefersSuccessfulVariant(t *testing.T) {
	d := &Daemon{learning: NewExperienceStore("")}
	d.learning.Observe(learningRecord("lab.test", "h1", "smuggle-chain", "cl.te", "", false))
	d.learning.Observe(learningRecord("lab.test", "h1", "smuggle-chain", "te.cl", "", true))

	j := &JobConfig{
		Target:  TargetConfig{Addr: "lab.test:443", Host: "lab.test"},
		TLS:     "h1",
		Probe:   "smuggle-chain",
		Variant: "auto",
	}
	got := d.applyLearning(j)
	if got.Variant != "te.cl" {
		t.Fatalf("variant = %q, want te.cl", got.Variant)
	}
	if j.Variant != "auto" {
		t.Fatalf("original job was mutated: variant = %q", j.Variant)
	}
}

func TestApplyLearningRanksMutations(t *testing.T) {
	d := &Daemon{learning: NewExperienceStore("")}
	d.learning.Observe(learningRecord("lab.test", "h1", "differential-fuzz", "", "ctl_nul", false))
	d.learning.Observe(learningRecord("lab.test", "h1", "differential-fuzz", "", "te_obfuscation", true))

	j := &JobConfig{
		Target:    TargetConfig{Addr: "lab.test:443", Host: "lab.test"},
		TLS:       "h1",
		Probe:     "differential-fuzz",
		Mutations: []string{"ctl_nul", "te_obfuscation"},
	}
	got := d.applyLearning(j)
	if got.Mutations[0] != "te_obfuscation" {
		t.Fatalf("mutations = %v, want te_obfuscation first", got.Mutations)
	}
}
