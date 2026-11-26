package omnislash

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestStrictTierRejectsSensitiveHeadersBeforeDial(t *testing.T) {
	proxy := startConnectProxy(t, "")
	cfg := DefaultConfig()
	cfg.Health.Enabled = false
	cfg.TrustTier = TrustTierStrict
	pool := newTestPool(t, cfg, mustProxy(t, proxy.URL()))
	dialer := NewDialer(pool, testLogger())
	rt := NewRotatingTransport(pool, dialer, cfg.HTTP, testLogger())
	defer rt.Close()

	for _, name := range []string{"Cookie", "Authorization", "X-Api-Key", "cookie"} {
		req, err := http.NewRequest(http.MethodGet, "https://api.avito.ru/", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set(name, "session-secret")
		_, err = rt.RoundTrip(req)
		if !errors.Is(err, ErrSensitiveHeaderBlocked) {
			t.Fatalf("header %q: got %v, want ErrSensitiveHeaderBlocked", name, err)
		}
	}
	if got := proxy.connects.Load(); got != 0 {
		t.Fatalf("strict tier opened %d CONNECT tunnels with credentials", got)
	}
}

func TestTrustedTierAllowsSensitiveHeaders(t *testing.T) {
	var seen atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") == "session-secret" {
			seen.Store(true)
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	proxy := startConnectProxy(t, "")
	cfg := DefaultConfig()
	cfg.Health.Enabled = false
	cfg.TrustTier = TrustTierTrusted
	pool := newTestPool(t, cfg, mustProxy(t, proxy.URL()))
	dialer := NewDialer(pool, testLogger())
	rt := NewRotatingTransport(pool, dialer, cfg.HTTP, testLogger())
	defer rt.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Cookie", "session-secret")
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("trusted transport: %v", err)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatal(err)
	}
	if !seen.Load() {
		t.Fatal("trusted tier dropped the Cookie header")
	}
	if proxy.connects.Load() == 0 {
		t.Fatal("trusted request did not leave through the proxy")
	}
}

func TestStrictTierGatewayRejectsSensitiveHeaders(t *testing.T) {
	proxy := startConnectProxy(t, "")
	cfg := DefaultConfig()
	cfg.Health.Enabled = false
	cfg.TrustTier = TrustTierStrict
	pool := newTestPool(t, cfg, mustProxy(t, proxy.URL()))
	dialer := NewDialer(pool, testLogger())
	gw, err := NewGateway("127.0.0.1:0", dialer, "", testLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer gw.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = gw.Serve(ctx) }()

	// A forward proxy receives absolute-form HTTP targets on a raw socket.
	conn, err := net.Dial("tcp", gw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, err = fmt.Fprintf(conn, "GET http://api.avito.ru/probe HTTP/1.1\r\nHost: api.avito.ru\r\nX-Api-Key: secret\r\nConnection: close\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if got := proxy.connects.Load(); got != 0 {
		t.Fatalf("gateway dialed %d tunnels with credentials", got)
	}
}
