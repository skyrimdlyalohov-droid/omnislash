package omnislash

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDeceptionFilterFlagsSynthetic200Baseline(t *testing.T) {
	cfg := DeceptionConfig{
		Enabled:             true,
		BaselineSamples:     2,
		MaxBodySample:       64 << 10,
		SimilarityThreshold: 0.85,
		RepeatStatus:        200,
		RepeatThreshold:     8,
		LatencySpikeFactor:  4,
		QuarantineSecrets:   true,
		Action:              "cooldown",
	}
	f := NewDeceptionFilter(cfg, nil)

	// Simulated tarpit: nonexistent paths return 200 with admin/token content.
	tarpit := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"admin_panel":true,"endpoints":["/api/v1/users","/api/v1/admin"],"token":"SECRET_TOKEN_ABC12345"}`))
	}))
	defer tarpit.Close()

	_, err := f.CalibrateBaseline(context.Background(), tarpit.URL, "/api/v1", func(ctx context.Context, target string) (*http.Response, time.Duration, error) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		resp, err := tarpit.Client().Do(req)
		return resp, 10 * time.Millisecond, err
	})
	if err != nil {
		t.Fatalf("calibrate: %v", err)
	}
	d, ok := f.IsFlagged("127.0.0.1", "/api/v1")
	if !ok || !d.Flagged {
		t.Fatalf("expected tarpit to be flagged, got ok=%v d=%+v", ok, d)
	}
	if d.Kind != DeceptionSynthetic200 {
		t.Fatalf("kind = %s, want %s", d.Kind, DeceptionSynthetic200)
	}
}

func TestDeceptionFilterQuarantinesSecrets(t *testing.T) {
	f := NewDeceptionFilter(DeceptionConfig{Enabled: true, QuarantineSecrets: true, Action: "mark", BaselineSamples: 2, MaxBodySample: 64 << 10, SimilarityThreshold: 0.92, RepeatStatus: 200, RepeatThreshold: 8, LatencySpikeFactor: 4}, nil)
	body := []byte(`{"token":"api_key=ABCD1234EFGH5678","endpoint":"/api/internal/debug"}`)
	d, _ := f.InspectResponse("example.com", "/api/v1/users", 200, body, 50*time.Millisecond)
	_ = d
	q := f.Quarantined()
	if len(q) == 0 {
		t.Fatalf("expected quarantined secrets/paths, got none")
	}
	for _, s := range q {
		if s.Verified {
			t.Fatalf("quarantined item should be unverified: %+v", s)
		}
	}
}

func TestDeceptionFilterRepeatAnomaly(t *testing.T) {
	f := NewDeceptionFilter(DeceptionConfig{Enabled: true, QuarantineSecrets: true, Action: "cooldown", BaselineSamples: 2, MaxBodySample: 64 << 10, SimilarityThreshold: 0.92, RepeatStatus: 200, RepeatThreshold: 3, LatencySpikeFactor: 4}, nil)
	body := []byte(`{"admin panel":true,"endpoints":["/api/v1/a","/api/v1/b","/api/v1/c","/api/v1/d"]}`)
	var d DeceptionDecision
	for i := 0; i < 4; i++ {
		d, _ = f.InspectResponse("example.com", "/api/v1/items", 200, body, 30*time.Millisecond)
	}
	if !d.Flagged {
		d2, ok := f.IsFlagged("example.com", "/api/v1")
		if !ok || !d2.Flagged {
			t.Fatalf("expected repeat anomaly to be flagged, got d=%+v ok=%v d2=%+v", d, ok, d2)
		}
	}
}

func TestDeceptionFilterShouldBlockByAction(t *testing.T) {
	f := NewDeceptionFilter(DeceptionConfig{Enabled: true, Action: "mark", BaselineSamples: 2, MaxBodySample: 64 << 10, SimilarityThreshold: 0.92, RepeatStatus: 200, RepeatThreshold: 3, LatencySpikeFactor: 4}, nil)
	f.flag(DeceptionDecision{Flagged: true, Kind: DeceptionSynthetic200, Host: "example.com", Prefix: "/api"})
	if _, block := f.ShouldBlock("example.com", "/api/v1"); block {
		t.Fatalf("mark action should not block")
	}
	f2 := NewDeceptionFilter(DeceptionConfig{Enabled: true, Action: "cooldown", BaselineSamples: 2, MaxBodySample: 64 << 10, SimilarityThreshold: 0.92, RepeatStatus: 200, RepeatThreshold: 3, LatencySpikeFactor: 4}, nil)
	f2.flag(DeceptionDecision{Flagged: true, Kind: DeceptionSynthetic200, Host: "example.com", Prefix: "/api"})
	if _, block := f2.ShouldBlock("example.com", "/api/v1"); !block {
		t.Fatalf("cooldown action should block")
	}
}

func TestInspectHTTPResponsePreservesBody(t *testing.T) {
	f := NewDeceptionFilter(DeceptionConfig{Enabled: true, Action: "mark", QuarantineSecrets: true, BaselineSamples: 2, MaxBodySample: 64 << 10, SimilarityThreshold: 0.92, RepeatStatus: 200, RepeatThreshold: 8, LatencySpikeFactor: 4}, nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("hello-body"))
	}))
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/ok", nil)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Request = req
	if _, err := f.InspectHTTPResponse(resp, 10*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 64)
	n, _ := resp.Body.Read(b)
	_ = resp.Body.Close()
	if string(b[:n]) != "hello-body" {
		t.Fatalf("body = %q", string(b[:n]))
	}
}

func TestRotatingTransportBlocksFlaggedDeception(t *testing.T) {
	proxy := startConnectProxy(t, "")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	cfg := testConfig()
	cfg.Safety.Deception.Enabled = true
	cfg.Safety.Deception.Action = "cooldown"
	cfg.HTTP.MaxRetries = 0
	pool := newTestPool(t, cfg, mustProxy(t, proxy.URL()))
	// Pre-flag host as deception/tarpit to simulate prior calibration/detection.
	pool.Deception().flag(DeceptionDecision{Flagged: true, Kind: DeceptionSynthetic200, Host: "127.0.0.1", Prefix: "/", Reason: "synthetic tarpit"})
	d := NewDialer(pool, testLogger())
	tr := NewRotatingTransport(pool, d, cfg.HTTP, testLogger())
	defer tr.Close()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	_, err := client.Get(srv.URL)
	if err == nil {
		t.Fatal("expected deception error, got nil")
	}
	if !strings.Contains(err.Error(), "deception/tarpit") {
		t.Fatalf("error = %v, want deception/tarpit", err)
	}
}
