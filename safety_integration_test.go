package omnislash

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRotatingTransportStopsAfterRepeatedBlocks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.TrustTier = TrustTierTrusted
	cfg.AllowDirect = true
	cfg.Scope.Enabled = false
	cfg.HTTP.MaxRetries = 0
	cfg.Safety = SafetyConfig{
		Enabled:      true,
		StopStatuses: []int{http.StatusForbidden},
		Threshold:    2,
		Window:       Duration(time.Minute),
		Cooldown:     Duration(time.Minute),
	}
	pool, err := NewPool(&cfg, nil, nil)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer pool.Close()
	tr := NewRotatingTransport(pool, NewDialer(pool, nil), cfg.HTTP, nil)
	defer tr.Close()

	for i := 0; i < 2; i++ {
		req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatalf("request %d: %v", i+1, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("request %d: status %d", i+1, resp.StatusCode)
		}
	}

	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tr.RoundTrip(req); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("third request should be refused by the breaker, got %v", err)
	}
}

func TestGatewayRefusesOpenCircuit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TrustTier = TrustTierTrusted
	cfg.AllowDirect = true
	cfg.Scope.Enabled = false
	cfg.Safety = SafetyConfig{
		Enabled:      true,
		StopStatuses: []int{http.StatusForbidden},
		Threshold:    1,
		Window:       Duration(time.Minute),
		Cooldown:     Duration(time.Minute),
	}
	pool, err := NewPool(&cfg, nil, nil)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer pool.Close()
	pool.TripSafety("test")
	if err := pool.Allow(); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("Allow after Trip = %v, want ErrCircuitOpen", err)
	}
}

func TestGatewayForwardsHTTPAndTripsCircuit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	cfg := DefaultConfig()
	cfg.TrustTier = TrustTierTrusted
	cfg.AllowDirect = true
	cfg.Scope.Enabled = false
	cfg.Audit = AuditConfig{Enabled: true, Path: auditPath}
	cfg.Safety = SafetyConfig{
		Enabled:      true,
		StopStatuses: []int{http.StatusForbidden},
		Threshold:    2,
		Window:       Duration(time.Minute),
		Cooldown:     Duration(time.Minute),
	}
	pool, err := NewPool(&cfg, nil, nil)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	gw, err := NewGateway("127.0.0.1:0", NewDialer(pool, nil), "", nil)
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- gw.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = gw.Close()
		<-done
		pool.Close()
	})

	proxyURL, err := url.Parse("http://" + gw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{
		Proxy:             http.ProxyURL(proxyURL),
		DisableKeepAlives: true,
	}}
	t.Cleanup(client.CloseIdleConnections)

	for i := 0; i < 2; i++ {
		resp, err := client.Get(srv.URL)
		if err != nil {
			t.Fatalf("request %d: %v", i+1, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("request %d: status %d", i+1, resp.StatusCode)
		}
	}

	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("third request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("third request should be refused with 503, got %d", resp.StatusCode)
	}

	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	var sawBlock, sawOpen bool
	for _, line := range splitLines(data) {
		if len(line) == 0 {
			continue
		}
		var ev AuditEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Fatalf("invalid audit line %q: %v", line, err)
		}
		if ev.Kind == "http" && ev.Status == http.StatusForbidden {
			sawBlock = true
		}
		if ev.Kind == "http" && ev.Reason == "circuit_open" {
			sawOpen = true
		}
	}
	if !sawBlock || !sawOpen {
		t.Fatalf("audit log missing block/circuit events (block=%v open=%v)", sawBlock, sawOpen)
	}
}

func TestGatewayGlobalRateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.TrustTier = TrustTierTrusted
	cfg.AllowDirect = true
	cfg.Scope.Enabled = false
	cfg.RateLimit = RateLimitConfig{GlobalRPS: 4, GlobalBurst: 1}
	pool, err := NewPool(&cfg, nil, nil)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	gw, err := NewGateway("127.0.0.1:0", NewDialer(pool, nil), "", nil)
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- gw.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = gw.Close()
		<-done
		pool.Close()
	})

	proxyURL, err := url.Parse("http://" + gw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{
		Proxy:             http.ProxyURL(proxyURL),
		DisableKeepAlives: true,
	}}
	t.Cleanup(client.CloseIdleConnections)

	start := time.Now()
	for i := 0; i < 5; i++ {
		resp, err := client.Get(srv.URL)
		if err != nil {
			t.Fatalf("request %d: %v", i+1, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status %d", i+1, resp.StatusCode)
		}
	}
	if elapsed := time.Since(start); elapsed < 800*time.Millisecond {
		t.Fatalf("5 requests at 4 rps finished in %s; global limiter was bypassed", elapsed)
	}
}
