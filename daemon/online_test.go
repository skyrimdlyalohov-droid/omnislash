package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeOnlineWeights(t *testing.T, path string, positiveCL int) {
	t.Helper()
	// Exactly two candidate lengths: 5 and 9. One is learned as a clean
	// success, the other as a parser reject, with enough attempts to trigger
	// the exact-cell branch of the online prior.
	positive := fmt.Sprintf(`"cl:%d":{"attempts":4,"successes":4,"ema":1,"sources":["online-audit"]}`, positiveCL)
	negativeCL := 5
	if positiveCL == 5 {
		negativeCL = 9
	}
	negative := fmt.Sprintf(`"cl:%d":{"attempts":4,"successes":0,"ema":0,"sources":["online-audit"]}`, negativeCL)
	payload := fmt.Sprintf(`{"exact_weight":0.8,"min_exact_attempts":2,"global":{%s,%s},"hosts":{},"tech":{}}`, positive, negative)
	if err := os.WriteFile(path, []byte(payload), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestOnlineHotReloadReranksDeclaredLengthsWithoutRestart(t *testing.T) {
	dir := t.TempDir()
	weightsPath := filepath.Join(dir, "learned_weights.json")
	writeOnlineWeights(t, weightsPath, 9)

	cfg := testConfig(testJob())
	cfg.OnlinePaths.WeightsPath = weightsPath
	d, err := New(cfg, &fakeExec{}, nil, &strings.Builder{})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.online.reload(true); err != nil {
		t.Fatal(err)
	}

	job := &JobConfig{
		Target:          TargetConfig{Addr: "lab.test:443", Host: "lab.test", Path: "/"},
		TLS:             "h1",
		Probe:           "smuggle-chain",
		DeclaredLengths: []int{5, 9},
	}
	got := d.applyLearning(job)
	if got.DeclaredLengths[0] != 9 {
		t.Fatalf("initial ranking = %v, want cl:9 first", got.DeclaredLengths)
	}
	if job.DeclaredLengths[0] != 5 {
		t.Fatalf("original job mutated: %v", job.DeclaredLengths)
	}

	// The streaming worker rewrites weights atomically; the daemon notices by
	// mtime/size on its next 500ms poll, with no process restart.
	time.Sleep(10 * time.Millisecond)
	writeOnlineWeights(t, weightsPath, 5)
	if err := d.online.reload(false); err != nil {
		t.Fatal(err)
	}
	got = d.applyLearning(job)
	if got.DeclaredLengths[0] != 5 {
		t.Fatalf("hot-reloaded ranking = %v, want cl:5 first", got.DeclaredLengths)
	}
}

func TestOnlineRankingRefinesDaemonVariantOrder(t *testing.T) {
	d := &Daemon{
		cfg:      *testConfig(),
		learning: NewExperienceStore(""),
		online:   &onlineRuntime{},
	}
	d.learning.Observe(learningRecord("lab.test", "h1", "smuggle-chain", "cl.te", "", false))
	d.learning.Observe(learningRecord("lab.test", "h1", "smuggle-chain", "te.cl", "", true))

	job := &JobConfig{
		Target:  TargetConfig{Addr: "lab.test:443", Host: "lab.test"},
		TLS:     "h1",
		Probe:   "smuggle-chain",
		Variant: "auto",
	}
	got := d.applyLearning(job)
	if got.Variant != "te.cl" {
		t.Fatalf("variant = %q, want daemon experience te.cl", got.Variant)
	}
	if job.Variant != "auto" {
		t.Fatalf("original job mutated: variant = %q", job.Variant)
	}
}
