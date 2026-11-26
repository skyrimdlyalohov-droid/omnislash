package omnislash

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// startSNIRecordingTLSServer records the ServerName from the ClientHello. The
// dial address is a literal 127.0.0.1:port while the TLS identity is a domain;
// only the latter may appear here when resolve_locally pins the CONNECT.
func startSNIRecordingTLSServer(t *testing.T) (*httptest.Server, func() string) {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	var mu sync.Mutex
	var serverName string
	srv.TLS = &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		mu.Lock()
		serverName = hello.ServerName
		mu.Unlock()
		return nil, nil
	}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, func() string {
		mu.Lock()
		defer mu.Unlock()
		return serverName
	}
}

func TestDialTLSUsesScopeOriginalHostWhenAddrIsPinnedIP(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Health.Enabled = false
	cfg.Scope = ScopeConfig{
		Enabled:        true,
		AllowHosts:     []string{"api.avito.ru"},
		AllowPrivate:   true,
		ResolveLocally: true,
	}
	pool := newTestPool(t, cfg, mustProxy(t, startConnectProxy(t, "").URL()))
	scope, err := NewScope(cfg.Scope)
	if err != nil {
		t.Fatal(err)
	}
	scope.lookup = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}
	pool.scope = scope

	srv, recorded := startSNIRecordingTLSServer(t)
	addr := strings.TrimPrefix(srv.URL, "https://")
	pinned, err := scope.CheckTarget(context.Background(), "api.avito.ru:"+strings.Split(addr, ":")[1])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(pinned, "127.0.0.1:") {
		t.Fatalf("scope did not pin CONNECT to IP: %q", pinned)
	}

	dialer := NewDialer(pool, testLogger())
	session, err := dialer.NewSession(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	// No ServerName supplied: the session must recover api.avito.ru from the
	// scope pin instead of putting the resolved IP into ClientHello.
	conn, err := session.DialTLSContext(context.Background(), "tcp", pinned, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("TLS with scope-pinned IP: %v", err)
	}
	defer conn.Close()
	if got := recorded(); got != "api.avito.ru" {
		t.Fatalf("ClientHello SNI = %q, want api.avito.ru", got)
	}
}

func TestDialTLSKeepsOriginalSNIForPinnedIP(t *testing.T) {
	for _, tc := range []struct {
		name         string
		fingerprints []string
	}{
		{name: "utls"},
		{name: "stdlib", fingerprints: []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Health.Enabled = false
			if tc.fingerprints != nil {
				cfg.TLSFingerprints = tc.fingerprints
			}
			proxy := startConnectProxy(t, "")
			pool := newTestPool(t, cfg, mustProxy(t, proxy.URL()))
			dialer := NewDialer(pool, testLogger())
			srv, sni := startSNIRecordingTLSServer(t)
			addr := strings.TrimPrefix(srv.URL, "https://")

			session, err := dialer.NewSession(time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			conn, err := session.DialTLSContext(context.Background(), "tcp", addr, &tls.Config{
				ServerName:         "api.avito.ru",
				InsecureSkipVerify: true, // SNI is asserted directly; trust is tested by admission/hedge.
				NextProtos:         []string{"http/1.1"},
			})
			if err != nil {
				t.Fatalf("TLS through pinned IP: %v", err)
			}
			defer conn.Close()

			if got := sni(); got != "api.avito.ru" {
				t.Fatalf("ClientHello SNI = %q, want original domain api.avito.ru", got)
			}
			if got, ok := ProxyOf(conn); !ok || got != session.Proxy() {
				t.Fatalf("ProxyOf = %v, %v; want pinned proxy", got, ok)
			}
			if got := proxy.connects.Load(); got != 1 {
				t.Fatalf("CONNECT count = %d, want 1 (no direct dial)", got)
			}
		})
	}
}
