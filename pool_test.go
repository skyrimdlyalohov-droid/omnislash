package omnislash

import (
	"testing"
	"time"
)

func newTestPool(t *testing.T, cfg Config, proxies ...*Proxy) *Pool {
	t.Helper()
	pool, err := NewPool(&cfg, proxies, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	return pool
}

func TestPoolRoundRobinAndExclusion(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Health.Enabled = false
	a := mustProxy(t, "socks5://127.0.0.1:1001")
	b := mustProxy(t, "socks5://127.0.0.1:1002")
	c := mustProxy(t, "socks5://127.0.0.1:1003")
	pool := newTestPool(t, cfg, a, b, c)

	var got []*Proxy
	for i := 0; i < 4; i++ {
		p, err := pool.pick(nil, "target:443")
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, p)
	}
	want := []*Proxy{a, b, c, a}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("position %d: got %s, want %s", i, got[i].Label(), want[i].Label())
		}
	}

	exclude := map[*Proxy]struct{}{a: {}}
	p, err := pool.pick(exclude, "target:443")
	if err != nil {
		t.Fatal(err)
	}
	if p == a {
		t.Fatal("excluded proxy was selected")
	}
}

func TestPoolLeastUsed(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Strategy = StrategyLeastUsed
	a := mustProxy(t, "socks5://127.0.0.1:1001")
	b := mustProxy(t, "socks5://127.0.0.1:1002")
	pool := newTestPool(t, cfg, a, b)
	first, _ := pool.pick(nil, "")
	second, _ := pool.pick(nil, "")
	if first != a || second != b {
		t.Fatalf("unexpected least-used order: %s then %s", first.Label(), second.Label())
	}
}

func TestPoolSticky(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Strategy = StrategySticky
	cfg.StickyTTL = Duration(time.Minute)
	a := mustProxy(t, "socks5://127.0.0.1:1001")
	b := mustProxy(t, "socks5://127.0.0.1:1002")
	c := mustProxy(t, "socks5://127.0.0.1:1003")
	pool := newTestPool(t, cfg, a, b, c)
	now := time.Now()
	pool.now = func() time.Time { return now }

	p1, _ := pool.pick(nil, "one:443")
	p2, _ := pool.pick(nil, "one:443")
	if p1 != a || p2 != a {
		t.Fatalf("sticky key changed proxy: %s -> %s", p1.Label(), p2.Label())
	}
	p3, _ := pool.pick(nil, "two:443")
	if p3 == p1 {
		t.Fatalf("different key reused sticky proxy %s", p3.Label())
	}
	now = now.Add(2 * time.Minute)
	p4, _ := pool.pick(nil, "one:443")
	if p4 == p1 {
		t.Fatalf("expired sticky entry was reused: %s", p4.Label())
	}
}

func TestPoolSkipsCooldown(t *testing.T) {
	cfg := DefaultConfig()
	a := mustProxy(t, "socks5://127.0.0.1:1001")
	b := mustProxy(t, "socks5://127.0.0.1:1002")
	pool := newTestPool(t, cfg, a, b)
	now := time.Now()
	pool.now = func() time.Time { return now }
	a.setDisabled(true)
	p, err := pool.pick(nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if p != b {
		t.Fatalf("disabled proxy selected: %s", p.Label())
	}
	if pool.Available() != 1 {
		t.Fatalf("available = %d, want 1", pool.Available())
	}
}

func TestNewPoolRequiresProxies(t *testing.T) {
	cfg := DefaultConfig()
	if _, err := NewPool(&cfg, nil, testLogger()); err == nil {
		t.Fatal("expected ErrNoProxies")
	}
	cfg.AllowDirect = true
	cfg.TrustTier = TrustTierTrusted
	if _, err := NewPool(&cfg, nil, testLogger()); err != nil {
		t.Fatal(err)
	}
}
