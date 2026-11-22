package omnislash

import (
	"testing"
	"time"
)

func TestPoolThompsonSelectsAvailable(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Strategy = StrategyThompson
	cfg.Health.Enabled = false
	a := mustProxy(t, "socks5://127.0.0.1:2001")
	b := mustProxy(t, "socks5://127.0.0.1:2002")
	c := mustProxy(t, "socks5://127.0.0.1:2003")
	pool := newTestPool(t, cfg, a, b, c)

	seen := map[*Proxy]bool{}
	for i := 0; i < 30; i++ {
		p, err := pool.pick(nil, "target:443")
		if err != nil {
			t.Fatal(err)
		}
		seen[p] = true
	}
	if len(seen) < 2 {
		t.Fatalf("thompson should explore multiple proxies, got %d", len(seen))
	}
}

func TestPoolThompsonRespectsExclusionAndCooldown(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Strategy = StrategyThompson
	cfg.Health.Enabled = false
	a := mustProxy(t, "socks5://127.0.0.1:2001")
	b := mustProxy(t, "socks5://127.0.0.1:2002")
	pool := newTestPool(t, cfg, a, b)

	exclude := map[*Proxy]struct{}{a: {}}
	for i := 0; i < 10; i++ {
		p, err := pool.pick(exclude, "t:443")
		if err != nil {
			t.Fatal(err)
		}
		if p != b {
			t.Fatalf("excluded proxy selected: %s", p.Label())
		}
	}

	a.setDisabled(true)
	for i := 0; i < 10; i++ {
		p, err := pool.pick(nil, "t:443")
		if err != nil {
			t.Fatal(err)
		}
		if p != b {
			t.Fatalf("cooldown proxy selected: %s", p.Label())
		}
	}
}

func TestSampleBetaRange(t *testing.T) {
	for i := 0; i < 1000; i++ {
		v := sampleBeta(2, 5)
		if v < 0 || v > 1 || v != v { // NaN check
			t.Fatalf("sampleBeta out of range: %v", v)
		}
	}
	// Higher alpha should tend to produce larger mean.
	var hi, lo float64
	n := 5000
	for i := 0; i < n; i++ {
		hi += sampleBeta(10, 2)
		lo += sampleBeta(2, 10)
	}
	if hi/float64(n) <= lo/float64(n) {
		t.Fatalf("expected high-alpha mean > low-alpha mean, got hi=%v lo=%v", hi/float64(n), lo/float64(n))
	}
}

func TestPoolThompsonLatencyPenalty(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Strategy = StrategyThompson
	cfg.Health.Enabled = false
	fast := mustProxy(t, "socks5://127.0.0.1:2101")
	slow := mustProxy(t, "socks5://127.0.0.1:2102")
	pool := newTestPool(t, cfg, fast, slow)
	fast.mu.Lock()
	fast.latency = 20 * time.Millisecond
	fast.mu.Unlock()
	slow.mu.Lock()
	slow.latency = 2 * time.Second
	slow.mu.Unlock()
	// Give both same success/failure; fast should be picked more often.
	counts := map[*Proxy]int{}
	for i := 0; i < 200; i++ {
		p, err := pool.pick(nil, "t:443")
		if err != nil {
			t.Fatal(err)
		}
		counts[p]++
	}
	if counts[fast] <= counts[slow] {
		t.Fatalf("expected fast proxy to be preferred, fast=%d slow=%d", counts[fast], counts[slow])
	}
}
