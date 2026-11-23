package omnislash

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestProxySniperTierEligibility(t *testing.T) {
	p := mustProxy(t, "socks5://127.0.0.1:3001")
	now := time.Now()
	for i := 0; i < 5; i++ {
		p.markSuccess(now, 10*time.Millisecond)
	}
	if p.Tier() == TierSniper {
		t.Fatal("proxy without http_parsing admission must not be sniper")
	}
	p.setAdmissionMode(AdmissionModeHTTPParsing)
	if got := p.Tier(); got != TierSniper {
		t.Fatalf("tier = %s, want sniper (p90=%v iqr=%v)", got, p.P90Latency(), p.IQR())
	}
}

func TestProxySniperRejectedByHighIQR(t *testing.T) {
	p := mustProxy(t, "socks5://127.0.0.1:3002")
	p.setAdmissionMode(AdmissionModeHTTPParsing)
	now := time.Now()
	for _, d := range []time.Duration{5 * time.Millisecond, 80 * time.Millisecond, 5 * time.Millisecond, 80 * time.Millisecond, 5 * time.Millisecond} {
		p.markSuccess(now, d)
	}
	if p.IQR() < sniperIQR {
		t.Fatalf("expected high IQR, got %v", p.IQR())
	}
	if got := p.Tier(); got != TierInfantry {
		t.Fatalf("tier = %s, want infantry", got)
	}
}

func TestProxySniperRejectedByRecentBan(t *testing.T) {
	p := mustProxy(t, "socks5://127.0.0.1:3003")
	p.setAdmissionMode(AdmissionModeHTTPParsing)
	now := time.Now()
	for i := 0; i < 5; i++ {
		p.markSuccess(now, 8*time.Millisecond)
	}
	if p.Tier() != TierSniper {
		t.Fatalf("expected sniper before ban")
	}
	p.markBan(now, "429", time.Minute)
	if got := p.Tier(); got != TierInfantry {
		t.Fatalf("tier after ban = %s, want infantry", got)
	}
}

func TestPoolAcquireSniper(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Health.Enabled = false
	cfg.Strategy = StrategyRoundRobin
	inf := mustProxy(t, "socks5://127.0.0.1:3004")
	sniper := mustProxy(t, "socks5://127.0.0.1:3005")
	pool := newTestPool(t, cfg, inf, sniper)
	now := time.Now()
	sniper.setAdmissionMode(AdmissionModeHTTPParsing)
	for i := 0; i < 5; i++ {
		sniper.markSuccess(now, 10*time.Millisecond)
	}
	inf.markSuccess(now, 10*time.Millisecond)

	got, err := pool.AcquireSniper(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got != sniper {
		t.Fatalf("AcquireSniper returned %s, want sniper", got.Label())
	}
	if pool.SniperCount() != 1 {
		t.Fatalf("sniper count = %d, want 1", pool.SniperCount())
	}
	if pool.InfantryCount() != 1 {
		t.Fatalf("infantry count = %d, want 1", pool.InfantryCount())
	}

	sniper.setDisabled(true)
	if _, err := pool.AcquireSniper(context.Background()); !errors.Is(err, ErrNoSniper) {
		t.Fatalf("expected ErrNoSniper when reserve is empty, got %v", err)
	}
}

func TestProxyAdaptiveTimeoutP90(t *testing.T) {
	p := mustProxy(t, "socks5://127.0.0.1:3006")
	now := time.Now()
	for i := 0; i < 10; i++ {
		p.markSuccess(now, 100*time.Millisecond)
	}
	// p90 = 100ms => 150ms, floored to 300ms.
	if got := p.AdaptiveTimeout(); got != 300*time.Millisecond {
		t.Fatalf("adaptive timeout = %v, want 300ms", got)
	}
	for i := 0; i < 10; i++ {
		p.markSuccess(now, 400*time.Millisecond)
	}
	// p90 ~400ms => 600ms.
	if got := p.AdaptiveTimeout(); got != 600*time.Millisecond {
		t.Fatalf("adaptive timeout = %v, want 600ms", got)
	}
}
