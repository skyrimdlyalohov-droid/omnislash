package omnislash

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTunnelWarmerKeepsFourVerifiedTunnelsAndExitIdentity(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "https://")
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}

	proxy := startConnectProxy(t, "")
	cfg := DefaultConfig()
	cfg.Health.Enabled = false
	cfg.TrustTier = TrustTierTrusted // test certificate; strict verification is checked by admission/hedge tests
	pr := mustProxy(t, proxy.URL())
	pool := newTestPool(t, cfg, pr)
	dialer := NewDialer(pool, testLogger())

	w := NewTunnelWarmer(dialer, 0, 0)
	if w.max != defaultMaxWarmTunnels || w.ttl != defaultWarmTTL {
		t.Fatalf("defaults = %d tunnels / %v TTL, want %d / %v", w.max, w.ttl, defaultMaxWarmTunnels, defaultWarmTTL)
	}
	w.SetTLSConfig(&tls.Config{ServerName: host, InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer w.Close()
	w.Start(ctx, addr, host)

	waitFor(t, 3*time.Second, func() bool { return w.WarmCount(addr) >= defaultMaxWarmTunnels })
	if got := w.WarmCount(addr); got != defaultMaxWarmTunnels {
		t.Fatalf("warm tunnels = %d, want %d", got, defaultMaxWarmTunnels)
	}

	other := mustProxy(t, "http://127.0.0.1:1")
	if conn, ok := w.Take(ctx, addr, other); ok {
		_ = conn.Close()
		t.Fatal("warmer handed a tunnel opened through a different proxy")
	}
	conn, ok := w.Take(ctx, addr, pr)
	if !ok {
		t.Fatal("warmer did not return a tunnel for the pinned proxy")
	}
	defer conn.Close()
	if got, ok := ProxyOf(conn); !ok || got != pr {
		t.Fatalf("warmed tunnel lost proxy attribution: %v, %v", got, ok)
	}
	if got := w.WarmCount(addr); got != defaultMaxWarmTunnels-1 {
		t.Fatalf("warm tunnels after Take = %d, want %d", got, defaultMaxWarmTunnels-1)
	}
}

func TestTunnelWarmerExpiresTunnelsAfterStrictTTL(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "https://")
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}

	proxy := startConnectProxy(t, "")
	cfg := DefaultConfig()
	cfg.Health.Enabled = false
	cfg.TrustTier = TrustTierTrusted
	pr := mustProxy(t, proxy.URL())
	pool := newTestPool(t, cfg, pr)
	dialer := NewDialer(pool, testLogger())

	const ttl = 90 * time.Millisecond
	w := NewTunnelWarmer(dialer, 1, ttl)
	w.SetTLSConfig(&tls.Config{ServerName: host, InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer w.Close()
	w.Start(ctx, addr, host)

	waitFor(t, time.Second, func() bool { return w.WarmCount(addr) == 1 })
	time.Sleep(ttl + 40*time.Millisecond)
	if got := w.WarmCount(addr); got != 0 {
		t.Fatalf("expired tunnels still counted: %d", got)
	}
	if conn, ok := w.Take(ctx, addr, pr); ok {
		_ = conn.Close()
		t.Fatal("warmer handed a tunnel older than its TTL")
	}
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition was not met before timeout")
}
