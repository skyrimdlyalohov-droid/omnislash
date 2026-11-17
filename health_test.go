package omnislash

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHealthCheckerSuccessAndFailure(t *testing.T) {
	proxy := startConnectProxy(t, "")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.Health.Enabled = true
	cfg.Health.Timeout = Duration(2 * time.Second)
	cfg.Health.Concurrency = 2
	cfg.Health.ProbeURL = srv.URL
	cfg.DialTimeout = Duration(2 * time.Second)
	cfg.HandshakeTimeout = Duration(2 * time.Second)
	cfg.Cooldown.Initial = Duration(time.Second)
	cfg.Cooldown.Max = Duration(time.Minute)
	pool := newTestPool(t, cfg, mustProxy(t, proxy.URL()))
	checker, err := NewHealthChecker(pool, NewDialer(pool, testLogger()), testLogger())
	if err != nil {
		t.Fatal(err)
	}

	summary := checker.CheckAll(context.Background())
	if summary.Checked != 1 || summary.Healthy != 1 || summary.Failed != 0 {
		t.Fatalf("unexpected summary: %+v", summary)
	}
	st := pool.Stats().Proxies[0]
	if !st.Alive || !st.Checked || st.LastChecked == nil {
		t.Fatalf("unexpected stats: %+v", st)
	}

	srv.Close()
	summary = checker.CheckAll(context.Background())
	if summary.Failed != 1 {
		t.Fatalf("unexpected failure summary: %+v", summary)
	}
	st = pool.Stats().Proxies[0]
	if st.Alive || !st.InCooldown || st.LastError == "" {
		t.Fatalf("proxy was not retired after failed probe: %+v", st)
	}
}

func TestPrepareBody(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "http://example.com/", nil)
	factory, retry, err := prepareBody(req, 1024)
	if err != nil || !retry || factory != nil {
		t.Fatalf("nil body: factory=%t retry=%v err=%v", factory != nil, retry, err)
	}

	req, _ = http.NewRequest(http.MethodPost, "http://example.com/", strings.NewReader("abc"))
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("abc")), nil }
	factory, retry, err = prepareBody(req, 1024)
	if err != nil || !retry || factory == nil {
		t.Fatalf("getbody: factory=%t retry=%v err=%v", factory != nil, retry, err)
	}

	req, _ = http.NewRequest(http.MethodPost, "http://example.com/", strings.NewReader("hello"))
	factory, retry, err = prepareBody(req, 1024)
	if err != nil || !retry || factory == nil {
		t.Fatalf("body buffer: factory=%t retry=%v err=%v", factory != nil, retry, err)
	}
	body, _ := factory()
	b, _ := io.ReadAll(body)
	if string(b) != "hello" {
		t.Fatalf("factory body = %q", b)
	}

	req, _ = http.NewRequest(http.MethodPost, "http://example.com/", struct{ io.Reader }{strings.NewReader(strings.Repeat("x", 2048))})
	factory, retry, err = prepareBody(req, 1024)
	if err != nil || retry || factory != nil {
		t.Fatalf("too large: factory=%t retry=%v err=%v", factory != nil, retry, err)
	}
}
