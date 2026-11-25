package omnislash

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestChaosPythonCrashIsNotAFalseVerdict simulates a dead semantic analyzer.
// When semantic_required is true the filter must return ErrDeceptionUncertain
// and mark the decision uncertain; it must never fall back to raw bytes and
// never produce a clean or flagged verdict.
func TestChaosPythonCrashIsNotAFalseVerdict(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "analyzer crashed", http.StatusInternalServerError)
	}))
	defer srv.Close()

	f := NewDeceptionFilter(DeceptionConfig{
		Enabled:             true,
		BaselineSamples:     2,
		MaxBodySample:       64 << 10,
		SimilarityThreshold: 0.92,
		RepeatStatus:        200,
		RepeatThreshold:     8,
		RepeatWindow:        Duration(10 * time.Second),
		LatencySpikeFactor:  4,
		NCDTarpit:           0.25,
		NCDStructural:       0.6,
		Action:              "mark",
		SemanticService:     true,
		SemanticRequired:    true,
		SemanticAddr:        srv.Listener.Addr().String(),
	}, nil)

	body := []byte(`{"admin_panel":true,"token":"REAL_VALUE"}`)
	decision, err := f.InspectResponse("honeypot.example", "/api/users", 200, body, time.Millisecond)
	if !errors.Is(err, ErrDeceptionUncertain) {
		t.Fatalf("error = %v, want ErrDeceptionUncertain", err)
	}
	if !decision.Uncertain {
		t.Fatalf("decision is not marked uncertain: %+v", decision)
	}
	if decision.Flagged {
		t.Fatalf("uncertain decision became a false positive: %+v", decision)
	}
	if decision.Kind != "" {
		t.Fatalf("uncertain decision carries a deception kind: %+v", decision)
	}
}

// TestChaosTargetCooldownRequiresDistinctProxies verifies that one proxy
// repeatedly receiving 429 cannot pause a target, and that a single 429 never
// starts a cooldown. Only a burst across independent exits does.
func TestChaosTargetCooldownRequiresDistinctProxies(t *testing.T) {
	cfg := testConfig()
	cfg.Safety.Enabled = false
	cfg.Safety.TargetCooldown.Enabled = true
	cfg.Safety.TargetCooldown.Statuses = []int{403, 429}
	cfg.Safety.TargetCooldown.Threshold = 5
	cfg.Safety.TargetCooldown.Window = Duration(60 * time.Second)
	cfg.Safety.TargetCooldown.Cooldown = Duration(2 * time.Minute)
	cfg.Safety.TargetCooldown.MinDistinctProxies = 2

	a := mustProxy(t, "socks5://127.0.0.1:18081")
	b := mustProxy(t, "socks5://127.0.0.1:18082")
	pool := newTestPool(t, cfg, a, b)
	defer pool.Close()

	now := time.Unix(1_700_000_000, 0)
	pool.now = func() time.Time { return now }

	pool.RecordTargetStatus("victim.example", a, http.StatusTooManyRequests)
	if _, cooling := pool.TargetCooling("victim.example"); cooling {
		t.Fatal("a single 429 must not cool down the target")
	}

	for i := 0; i < 4; i++ {
		pool.RecordTargetStatus("victim.example", a, http.StatusTooManyRequests)
	}
	if _, cooling := pool.TargetCooling("victim.example"); cooling {
		t.Fatal("five blocks from one proxy must not cool down the target")
	}

	pool.RecordTargetStatus("victim.example", b, http.StatusTooManyRequests)
	until, cooling := pool.TargetCooling("victim.example")
	if !cooling {
		t.Fatal("five blocks across two independent proxies did not cool down the target")
	}
	if until.Sub(now) != 2*time.Minute {
		t.Fatalf("cooldown = %s, want 2m", until.Sub(now))
	}
	if _, cooling := pool.TargetCooling("other.example"); cooling {
		t.Fatal("cooldown leaked to another target")
	}

	now = now.Add(2*time.Minute + time.Second)
	if _, cooling := pool.TargetCooling("victim.example"); cooling {
		t.Fatal("target stayed cooling after the cooldown expired")
	}
}

// TestChaosNonBlockResponseResetsTargetStreak ensures an ordinary response
// between blocks breaks the consecutive burst instead of accumulating forever.
func TestChaosNonBlockResponseResetsTargetStreak(t *testing.T) {
	cfg := testConfig()
	cfg.Safety.TargetCooldown.Enabled = true
	cfg.Safety.TargetCooldown.Threshold = 3
	cfg.Safety.TargetCooldown.Window = Duration(60 * time.Second)
	cfg.Safety.TargetCooldown.MinDistinctProxies = 2

	a := mustProxy(t, "socks5://127.0.0.1:18083")
	b := mustProxy(t, "socks5://127.0.0.1:18084")
	pool := newTestPool(t, cfg, a, b)
	defer pool.Close()

	now := time.Unix(1_700_000_000, 0)
	pool.now = func() time.Time { return now }

	pool.RecordTargetStatus("victim.example", a, http.StatusForbidden)
	pool.RecordTargetStatus("victim.example", b, http.StatusForbidden)
	pool.RecordTargetStatus("victim.example", a, http.StatusOK)
	pool.RecordTargetStatus("victim.example", a, http.StatusForbidden)
	pool.RecordTargetStatus("victim.example", b, http.StatusForbidden)
	if _, cooling := pool.TargetCooling("victim.example"); cooling {
		t.Fatal("non-block response did not reset the consecutive streak")
	}
}

// TestChaosEmptyPoolWaitsForHealthCheck verifies that the daemon path waits
// instead of failing the run when every proxy is cooling down.
func TestChaosEmptyPoolWaitsForHealthCheck(t *testing.T) {
	cfg := testConfig()
	cfg.AllowDirect = false
	cfg.Safety.TargetCooldown.Enabled = false
	first := mustProxy(t, "socks5://127.0.0.1:18085")
	pool := newTestPool(t, cfg, first)
	defer pool.Close()
	pool.Ban(first, "test", time.Hour)
	if pool.Available() != 0 {
		t.Fatalf("expected an empty available pool, got %d", pool.Available())
	}

	replacement := mustProxy(t, "socks5://127.0.0.1:18086")
	go func() {
		time.Sleep(50 * time.Millisecond)
		pool.Replace([]*Proxy{replacement})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := pool.WaitForProxy(ctx); err != nil {
		t.Fatalf("WaitForProxy: %v", err)
	}
}
