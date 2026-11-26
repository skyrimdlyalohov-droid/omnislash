package omnislash

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// startDelayedConnectProxy accepts TCP immediately but stalls the CONNECT
// handshake. It models a slow primary exit without relying on the public
// internet or on an artificial TLS server delay.
func startDelayedConnectProxy(t *testing.T, delay time.Duration) *fakeConnectProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeConnectProxy{ln: ln, addr: ln.Addr().String()}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				time.Sleep(delay)
				p.handle(c)
			}(conn)
		}
	}()
	return p
}

func newTLSServerForHedge(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func hedgedTLSForTest(t *testing.T, addr string, cert *x509.Certificate) *tls.Config {
	t.Helper()
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		ServerName: host,
		RootCAs:    certPoolFor(cert),
		NextProtos: []string{"http/1.1"},
	}
}

func TestHedgedDialRespectsGlobalRPS(t *testing.T) {
	cases := []struct {
		name       string
		burst      int
		wantBackup bool
	}{
		{name: "no spare token disables hedge", burst: 1},
		{name: "spare token launches backup", burst: 2, wantBackup: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newTLSServerForHedge(t)
			addr := strings.TrimPrefix(srv.URL, "https://")
			slow := startDelayedConnectProxy(t, 700*time.Millisecond)
			fast := startConnectProxy(t, "")

			cfg := DefaultConfig()
			cfg.Health.Enabled = false
			cfg.TrustTier = TrustTierStrict
			cfg.RateLimit.GlobalRPS = 2
			cfg.RateLimit.GlobalBurst = tc.burst
			cfg.UTLSHandshakeTimeout = Duration(3 * time.Second)
			primary := mustProxy(t, slow.URL())
			backup := mustProxy(t, fast.URL())
			pool := newTestPool(t, cfg, primary, backup)
			dialer := NewDialer(pool, testLogger())

			start := time.Now()
			conn, err := dialer.HedgedDialContext(context.Background(), primary, "tcp", addr, hedgedTLSForTest(t, addr, srv.Certificate()))
			elapsed := time.Since(start)
			if err != nil {
				t.Fatalf("hedged dial: %v", err)
			}
			defer conn.Close()

			if got, ok := ProxyOf(conn); !ok {
				t.Fatal("hedged connection has no proxy attribution")
			} else if got != primary && got != backup {
				t.Fatalf("hedged connection used unknown proxy %s", got.Label())
			}
			if tc.wantBackup {
				if fast.connects.Load() == 0 {
					t.Fatal("backup was not launched although a global token was available")
				}
				if elapsed > 600*time.Millisecond {
					t.Fatalf("slow primary won despite a fast backup: %v", elapsed)
				}
			} else {
				if fast.connects.Load() != 0 {
					t.Fatal("backup spent a token when no spare token was available")
				}
				if elapsed < 650*time.Millisecond {
					t.Fatalf("backup ran without a token: dial finished in %v", elapsed)
				}
			}
		})
	}
}

func TestHedgedDialRejectsUnverifiedCertificateInStrictTier(t *testing.T) {
	srv := newTLSServerForHedge(t)
	addr := strings.TrimPrefix(srv.URL, "https://")
	proxy := startConnectProxy(t, "")

	cfg := DefaultConfig()
	cfg.Health.Enabled = false
	cfg.TrustTier = TrustTierStrict
	pool := newTestPool(t, cfg, mustProxy(t, proxy.URL()))
	dialer := NewDialer(pool, testLogger())

	// No RootCAs and verification forced on: an unknown self-signed target
	// certificate must never win the race.
	tlsCfg := &tls.Config{ServerName: strings.Split(addr, ":")[0], NextProtos: []string{"http/1.1"}}
	conn, err := dialer.HedgedDialContext(context.Background(), pool.Proxies()[0], "tcp", addr, tlsCfg)
	if err == nil {
		_ = conn.Close()
		t.Fatal("strict hedged dial accepted an unverified certificate")
	}
}
