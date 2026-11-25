package omnislash

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeSemanticService returns stable canonical skeletons. The JSON skeleton is
// identical for two different token values; the HTML skeleton is structurally
// different. This is exactly the contract the Python service provides.
func fakeSemanticService(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/skeleton" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var req semanticRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		skeleton := `{"type":"object","keys":{"admin_panel":"bool","token":"str"}}`
		if strings.Contains(req.Body, "<html") {
			skeleton = `{"type":"html","tags":["html","body","h1"]}`
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(semanticResponse{Status: "ok", Skeleton: skeleton})
	}))
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}

func TestSemanticClientIsLoopbackOnly(t *testing.T) {
	if _, err := NewSemanticClient("example.com:8000"); err == nil {
		t.Fatal("remote semantic service address was accepted")
	}
	addr := fakeSemanticService(t)
	c, err := NewSemanticClient(addr)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Skeleton([]byte(`{"token":"secret_VALUE_12345678"}`), "application/json")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "secret_VALUE") {
		t.Fatalf("skeleton leaked a dynamic value: %s", got)
	}
}

func TestNCDUsesCanonicalSkeletonInsteadOfRawValues(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"admin_panel":true,"token":"BASELINE_VALUE_ABC123"}`)
	}))
	defer target.Close()

	cfg := DeceptionConfig{
		Enabled:             true,
		BaselineSamples:     2,
		MaxBodySample:       64 << 10,
		SimilarityThreshold: 0.99,
		RepeatStatus:        200,
		RepeatThreshold:     100,
		NCDStructural:       0.2,
		NCDTarpit:           0.25,
		SemanticService:     true,
		SemanticAddr:        fakeSemanticService(t),
	}
	f := NewDeceptionFilter(cfg, nil)
	_, err := f.CalibrateBaseline(context.Background(), target.URL, "/api", func(ctx context.Context, rawURL string) (*http.Response, time.Duration, error) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		resp, err := target.Client().Do(req)
		return resp, time.Millisecond, err
	})
	if err != nil {
		t.Fatal(err)
	}
	base, ok := f.baselines[baselineKey("127.0.0.1", "/api")]
	if !ok || base.Skeleton == "" {
		t.Fatalf("baseline skeleton was not stored: %+v", base)
	}

	// Same structure, different dynamic values: raw NCD would be high, but the
	// canonical skeleton is identical, so this is not a structural anomaly.
	jsonBody := []byte(`{"admin_panel":true,"token":"REAL_VALUE_ZZZ987654"}`)
	d, _ := f.InspectResponseWithContentType("127.0.0.1", "/api/users", 200,
		jsonBody, "application/json", time.Millisecond)
	if d.Flagged {
		t.Fatalf("canonical-equal body was flagged: %+v", d)
	}

	// A genuinely different skeleton must still be flagged above the configured
	// threshold (0.2), not the old hard-coded 0.6.
	htmlBody := []byte(`<html><body><h1>admin panel</h1></body></html>`)
	d, _ = f.InspectResponseWithContentType("127.0.0.1", "/api/users", 200,
		htmlBody, "text/html", time.Millisecond)
	if !d.Flagged || !strings.Contains(d.Reason, "skeleton NCD") {
		t.Fatalf("structural shift was not flagged via skeleton NCD: %+v", d)
	}
}

func TestRepeatStateUsesTimeWindow(t *testing.T) {
	f := NewDeceptionFilter(DeceptionConfig{
		Enabled:             true,
		RepeatStatus:        200,
		RepeatThreshold:     2,
		RepeatWindow:        Duration(200 * time.Millisecond),
		NCDTarpit:           0.25,
		NCDStructural:       0.6,
		MaxBodySample:       64 << 10,
		BaselineSamples:     2,
		Action:              "cooldown",
		SimilarityThreshold: 0.92,
	}, nil)
	t0 := time.Now()
	current := t0
	f.now = func() time.Time { return current }
	body := []byte(`{"endpoints":["/api/a","/api/b","/api/c","/api/d"]}`)

	if d, _ := f.InspectResponse("window.example", "/api/items", 200, body, time.Millisecond); d.Flagged {
		t.Fatalf("first response was flagged: %+v", d)
	}
	current = t0.Add(300 * time.Millisecond)
	if d, _ := f.InspectResponse("window.example", "/api/items", 200, body, time.Millisecond); d.Flagged {
		t.Fatalf("response after repeat window was flagged: %+v", d)
	}
	if d, _ := f.InspectResponse("window.example", "/api/items", 200, body, time.Millisecond); !d.Flagged {
		t.Fatal("two responses inside the window were not flagged")
	}
}

func TestIdenticalBodiesAreNotDynamicTarpit(t *testing.T) {
	f := NewDeceptionFilter(DeceptionConfig{
		Enabled:             true,
		RepeatStatus:        200,
		RepeatThreshold:     100,
		RepeatWindow:        Duration(10 * time.Second),
		NCDTarpit:           0.25,
		NCDStructural:       0.6,
		MaxBodySample:       64 << 10,
		BaselineSamples:     2,
		SimilarityThreshold: 0.92,
		Action:              "cooldown",
	}, nil)
	body := []byte(`{"admin_panel":true,"endpoints":["/api/a","/api/b"]}`)
	for i := 0; i < 5; i++ {
		if d, _ := f.InspectResponse("stable.example", "/api/items", 200, body, time.Millisecond); d.Flagged {
			t.Fatalf("identical legitimate body #%d was flagged as tarpit: %+v", i, d)
		}
	}
}

func TestMarkBansTargetWithoutTrippingProxyCircuit(t *testing.T) {
	cfg := testConfig()
	cfg.Safety.Enabled = true
	cfg.Safety.Deception.Enabled = true
	cfg.Safety.Deception.Action = "mark"
	cfg.Safety.Deception.SemanticService = false
	proxy := startConnectProxy(t, "")
	pool := newTestPool(t, cfg, mustProxy(t, proxy.URL()))
	pr := pool.Proxies()[0]

	pool.HandleDeception(pr, DeceptionDecision{
		Flagged: true,
		Kind:    DeceptionTarpit,
		Host:    "honeypot.example",
		Prefix:  "/api",
		Reason:  "test",
	})
	if err := pool.Allow(); err != nil {
		t.Fatalf("mark tripped the pool circuit: %v", err)
	}
	if !pr.available(pool.now()) {
		t.Fatal("mark cooled down an innocent proxy")
	}
	if _, block := pool.Deception().ShouldBlock("honeypot.example", "/api/v1"); !block {
		t.Fatal("mark did not ban the target for this session")
	}
}

func TestTransportCalibratesBeforeFirstProbe(t *testing.T) {
	var baseline, real atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "nonexistent_") {
			baseline.Add(1)
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, "not found")
			return
		}
		real.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer srv.Close()

	cfg := testConfig()
	cfg.Safety.Deception.Enabled = true
	cfg.Safety.Deception.SemanticService = false
	proxy := startConnectProxy(t, "")
	pool := newTestPool(t, cfg, mustProxy(t, proxy.URL()))
	tr := NewRotatingTransport(pool, NewDialer(pool, testLogger()), cfg.HTTP, testLogger())
	defer tr.Close()

	resp, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Get(srv.URL + "/api/real")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if got := real.Load(); got != 1 {
		t.Fatalf("real requests = %d, want 1", got)
	}
	if got := baseline.Load(); got < int32(cfg.Safety.Deception.BaselineSamples) {
		t.Fatalf("baseline requests = %d, want at least %d before the probe", got, cfg.Safety.Deception.BaselineSamples)
	}
}
