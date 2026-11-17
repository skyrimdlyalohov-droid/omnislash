package omnislash

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testConfig() Config {
	cfg := DefaultConfig()
	cfg.Health.Enabled = false
	cfg.DialTimeout = Duration(2 * time.Second)
	cfg.HandshakeTimeout = Duration(2 * time.Second)
	cfg.MaxDialAttempts = 2
	cfg.Cooldown.Initial = Duration(time.Second)
	cfg.Cooldown.Max = Duration(time.Minute)
	return cfg
}

func dialEcho(t *testing.T, d *Dialer, target string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "ping"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo = %q", buf)
	}
}

func TestDialerSOCKS5(t *testing.T) {
	proxyAddr := startSocks5Proxy(t, "", "")
	echoAddr := startEchoServer(t)
	cfg := testConfig()
	pool := newTestPool(t, cfg, mustProxy(t, "socks5://"+proxyAddr))
	d := NewDialer(pool, testLogger())
	dialEcho(t, d, echoAddr)
	if st := pool.Stats().Proxies[0]; st.Successes == 0 || st.Uses == 0 {
		t.Fatalf("unexpected stats: %+v", st)
	}
}

func TestDialerSOCKS5AuthAndDomain(t *testing.T) {
	proxyAddr := startSocks5Proxy(t, "user", "pass")
	echoAddr := startEchoServer(t)
	_, port, err := splitHostPort(echoAddr)
	if err != nil {
		t.Fatal(err)
	}
	cfg := testConfig()
	proxyURL := fmt.Sprintf("socks5://user:pass@%s", proxyAddr)
	pool := newTestPool(t, cfg, mustProxy(t, proxyURL))
	d := NewDialer(pool, testLogger())
	dialEcho(t, d, fmt.Sprintf("localhost:%d", port))
}

func TestDialerHTTPConnectAndAuth(t *testing.T) {
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass"))
	proxy := startConnectProxy(t, auth)
	echoAddr := startEchoServer(t)
	cfg := testConfig()
	pool := newTestPool(t, cfg, mustProxy(t, "http://user:pass@"+proxy.addr))
	d := NewDialer(pool, testLogger())
	dialEcho(t, d, echoAddr)
	if proxy.connects.Load() != 1 {
		t.Fatalf("proxy connects = %d", proxy.connects.Load())
	}
}

func TestDialerRotatesAfterDeadProxy(t *testing.T) {
	proxyAddr := startSocks5Proxy(t, "", "")
	echoAddr := startEchoServer(t)
	cfg := testConfig()
	dead := mustProxy(t, "socks5://"+freeAddr(t))
	good := mustProxy(t, "socks5://"+proxyAddr)
	pool := newTestPool(t, cfg, dead, good)
	d := NewDialer(pool, testLogger())
	dialEcho(t, d, echoAddr)

	stats := pool.Stats()
	if !stats.Proxies[0].InCooldown || stats.Proxies[0].Failures == 0 {
		t.Fatalf("dead proxy was not retired: %+v", stats.Proxies[0])
	}
	if stats.Proxies[1].Successes == 0 {
		t.Fatalf("good proxy was not used: %+v", stats.Proxies[1])
	}
}

func TestProxyOfAndManualBan(t *testing.T) {
	proxyAddr := startSocks5Proxy(t, "", "")
	echoAddr := startEchoServer(t)
	cfg := testConfig()
	proxy := mustProxy(t, "socks5://"+proxyAddr)
	pool := newTestPool(t, cfg, proxy)
	d := NewDialer(pool, testLogger())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := d.DialContext(ctx, "tcp", echoAddr)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := ProxyOf(conn)
	if !ok || got != proxy {
		t.Fatalf("ProxyOf = %v, %v; want %s", got, ok, proxy.Label())
	}
	_ = conn.Close()

	pool.Ban(proxy, "target returned 403", time.Minute)
	st := pool.Stats().Proxies[0]
	if st.Bans != 1 || !st.InCooldown || st.Available {
		t.Fatalf("manual ban not applied: %+v", st)
	}
}

func TestDialerNoDirectFallback(t *testing.T) {
	cfg := testConfig()
	cfg.MaxDialAttempts = 1
	pool := newTestPool(t, cfg, mustProxy(t, "socks5://"+freeAddr(t)))
	d := NewDialer(pool, testLogger())
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if conn, err := d.DialContext(ctx, "tcp", "127.0.0.1:1"); err == nil {
		_ = conn.Close()
		t.Fatal("expected dial error")
	}
}

func TestDialTLS(t *testing.T) {
	proxyAddr := startSocks5Proxy(t, "", "")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()
	cfg := testConfig()
	pool := newTestPool(t, cfg, mustProxy(t, "socks5://"+proxyAddr))
	d := NewDialer(pool, testLogger())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	host := strings.TrimPrefix(srv.URL, "https://")
	conn, err := d.DialTLSContext(ctx, "tcp", host, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host)
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}
