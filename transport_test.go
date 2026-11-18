package omnislash

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRotatingTransportRotatesConnections(t *testing.T) {
	p1 := startConnectProxy(t, "")
	p2 := startConnectProxy(t, "")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	cfg := testConfig()
	cfg.HTTP.MaxRetries = 0
	pool := newTestPool(t, cfg, mustProxy(t, p1.URL()), mustProxy(t, p2.URL()))
	d := NewDialer(pool, testLogger())
	tr := NewRotatingTransport(pool, d, cfg.HTTP, testLogger())
	defer tr.Close()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}

	for i := 0; i < 4; i++ {
		resp, err := client.Get(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d", resp.StatusCode)
		}
	}
	if p1.connects.Load() == 0 || p2.connects.Load() == 0 {
		t.Fatalf("both proxies should be used: p1=%d p2=%d", p1.connects.Load(), p2.connects.Load())
	}
}

func TestRotatingTransportRetriesBannedStatus(t *testing.T) {
	p1 := startConnectProxy(t, "")
	p2 := startConnectProxy(t, "")
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	cfg := testConfig()
	cfg.HTTP.MaxRetries = 1
	cfg.HTTP.BanStatuses = []int{http.StatusTooManyRequests}
	cfg.HTTP.BanCooldown = Duration(time.Minute)
	pool := newTestPool(t, cfg, mustProxy(t, p1.URL()), mustProxy(t, p2.URL()))
	d := NewDialer(pool, testLogger())
	tr := NewRotatingTransport(pool, d, cfg.HTTP, testLogger())
	defer tr.Close()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}

	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
	var bans uint64
	for _, ps := range pool.Stats().Proxies {
		bans += ps.Bans
	}
	if bans != 1 {
		t.Fatalf("bans = %d, want 1", bans)
	}
	if p1.connects.Load()+p2.connects.Load() < 2 {
		t.Fatalf("retry did not open a second proxy connection: p1=%d p2=%d", p1.connects.Load(), p2.connects.Load())
	}
}

func TestGatewayPassesBytes(t *testing.T) {
	proxyAddr := startSocks5Proxy(t, "", "")
	echoAddr := startEchoServer(t)
	cfg := testConfig()
	pool := newTestPool(t, cfg, mustProxy(t, "socks5://"+proxyAddr))
	d := NewDialer(pool, testLogger())
	gw, err := NewGateway("127.0.0.1:0", d, "", testLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer gw.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- gw.Serve(ctx) }()

	conn, err := net.Dial("tcp", gw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, "CONNECT "+echoAddr+" HTTP/1.1\r\nHost: "+echoAddr+"\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	tp := textproto.NewReader(br)
	line, err := tp.ReadLine()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, " 200 ") {
		t.Fatalf("gateway status: %q", line)
	}
	if _, err := tp.ReadMIMEHeader(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "hello"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hello" {
		t.Fatalf("echo = %q", buf)
	}
	_ = conn.Close()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("gateway did not stop")
	}
}

func TestGatewayToken(t *testing.T) {
	proxyAddr := startSocks5Proxy(t, "", "")
	echoAddr := startEchoServer(t)
	cfg := testConfig()
	pool := newTestPool(t, cfg, mustProxy(t, "socks5://"+proxyAddr))
	d := NewDialer(pool, testLogger())
	gw, err := NewGateway("127.0.0.1:0", d, "secret", testLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer gw.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = gw.Serve(ctx) }()

	conn, err := net.Dial("tcp", gw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(conn, "CONNECT "+echoAddr+" HTTP/1.1\r\nHost: "+echoAddr+"\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, "407") {
		t.Fatalf("expected 407 without token, got %q", line)
	}
}

func startTestGateway(t *testing.T, cfg Config, proxies ...*Proxy) *Gateway {
	t.Helper()
	pool := newTestPool(t, cfg, proxies...)
	gw, err := NewGateway("127.0.0.1:0", NewDialer(pool, testLogger()), "", testLogger())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gw.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = gw.Serve(ctx) }()
	return gw
}

func connectStatus(t *testing.T, gw *Gateway, target string) string {
	t.Helper()
	conn, err := net.Dial("tcp", gw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	return line
}

func TestGatewayScopeRejectionIs403(t *testing.T) {
	cfg := testConfig()
	cfg.Scope = ScopeConfig{Enabled: true, AllowHosts: []string{"allowed.example"}, AllowPorts: []int{443}}
	proxy := startConnectProxy(t, "")
	gw := startTestGateway(t, cfg, mustProxy(t, proxy.URL()))

	if line := connectStatus(t, gw, "blocked.example:443"); !strings.Contains(line, " 403 ") {
		t.Fatalf("out-of-scope CONNECT = %q, want 403", line)
	}
}

func TestGatewayUpstreamFailureIs502(t *testing.T) {
	cfg := testConfig()
	cfg.MaxDialAttempts = 1
	cfg.DialTimeout = Duration(200 * time.Millisecond)
	cfg.Scope = ScopeConfig{Enabled: true, AllowHosts: []string{"93.184.216.34"}, AllowPorts: []int{443}}
	dead := mustProxy(t, "http://127.0.0.1:1")
	gw := startTestGateway(t, cfg, dead)

	if line := connectStatus(t, gw, "93.184.216.34:443"); !strings.Contains(line, " 502 ") {
		t.Fatalf("dead upstream CONNECT = %q, want 502", line)
	}
}
