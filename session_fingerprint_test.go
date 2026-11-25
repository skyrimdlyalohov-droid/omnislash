package omnislash

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// helloRecordingListener captures the raw TLS ClientHello bytes that arrive at
// the target through the CONNECT proxy. It lets a test prove both rotation and
// that the handshake reached the target instead of leaking a direct dial.
type helloRecordingListener struct {
	net.Listener
	mu     sync.Mutex
	hellos [][]byte
}

func (l *helloRecordingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &helloRecordingConn{Conn: c, owner: l}, nil
}

func (l *helloRecordingListener) add(sample []byte) {
	l.mu.Lock()
	l.hellos = append(l.hellos, sample)
	l.mu.Unlock()
}

func (l *helloRecordingListener) samples() [][]byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([][]byte(nil), l.hellos...)
}

type helloRecordingConn struct {
	net.Conn
	owner *helloRecordingListener

	mu   sync.Mutex
	buf  []byte
	done bool
}

func (c *helloRecordingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.mu.Lock()
		if !c.done {
			c.buf = append(c.buf, p[:n]...)
			if len(c.buf) >= 128 {
				c.done = true
				c.owner.add(append([]byte(nil), c.buf[:128]...))
			}
		}
		c.mu.Unlock()
	}
	return n, err
}

func startRecordedTLSServer(t *testing.T) (*httptest.Server, *helloRecordingListener) {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	recorder := &helloRecordingListener{Listener: srv.Listener}
	srv.Listener = recorder
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, recorder
}

func TestSessionFingerprintRotatesThroughPinnedProxy(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Health.Enabled = false
	proxy := startConnectProxy(t, "")
	pool := newTestPool(t, cfg, mustProxy(t, proxy.URL()))
	dialer := NewDialer(pool, testLogger())
	srv, recorder := startRecordedTLSServer(t)
	addr := strings.TrimPrefix(srv.URL, "https://")

	var previous string
	for i, want := range DefaultFingerprints {
		session, err := dialer.NewSession(time.Minute)
		if err != nil {
			t.Fatalf("session %d: %v", i, err)
		}
		got := session.Fingerprint()
		if got != want {
			t.Fatalf("session %d fingerprint = %q, want %q", i, got, want)
		}
		if got == previous {
			t.Fatalf("session %d reused profile %q", i, got)
		}
		previous = got

		conn, err := session.DialTLSContext(context.Background(), "tcp", addr,
			&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
		if err != nil {
			t.Fatalf("session %d utls handshake: %v", i, err)
		}
		if p, ok := ProxyOf(conn); !ok || p != session.Proxy() {
			t.Fatalf("session %d did not keep the pinned proxy (got %v, session %v)", i, p, session.Proxy())
		}
		if proxy.connects.Load() != int64(i+1) {
			t.Fatalf("CONNECT count = %d, want %d", proxy.connects.Load(), i+1)
		}
		_ = conn.Close()
		session.Close()
	}

	samples := recorder.samples()
	if len(samples) != len(DefaultFingerprints) {
		t.Fatalf("target saw %d ClientHellos, want %d", len(samples), len(DefaultFingerprints))
	}
	for i := 1; i < len(samples); i++ {
		if string(samples[0]) == string(samples[i]) {
			t.Fatalf("profile %d sent an identical ClientHello to profile 0", i)
		}
	}
}

func TestSessionFingerprintDisabledStillUsesProxy(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Health.Enabled = false
	cfg.TLSFingerprints = []string{} // explicit opt-out
	proxy := startConnectProxy(t, "")
	pool := newTestPool(t, cfg, mustProxy(t, proxy.URL()))
	dialer := NewDialer(pool, testLogger())
	srv, recorder := startRecordedTLSServer(t)

	session, err := dialer.NewSession(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if session.Fingerprint() != "" {
		t.Fatalf("fingerprinting disabled but session pinned %q", session.Fingerprint())
	}
	conn, err := session.DialTLSContext(context.Background(), "tcp",
		strings.TrimPrefix(srv.URL, "https://"),
		&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if p, ok := ProxyOf(conn); !ok || p != session.Proxy() {
		t.Fatal("stdlib TLS connection lost proxy attribution")
	}
	if len(recorder.samples()) != 1 {
		t.Fatalf("target saw %d ClientHellos, want 1", len(recorder.samples()))
	}
}

func TestSessionFingerprintNeverFallsBackToDirectEgress(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Health.Enabled = false
	dead := startEchoTunnelProxy(t, nil, false, true)
	pool := newTestPool(t, cfg, mustProxy(t, dead.URL()))
	dialer := NewDialer(pool, testLogger())
	srv, recorder := startRecordedTLSServer(t)

	session, err := dialer.NewSession(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := session.DialTLSContext(context.Background(), "tcp",
		strings.TrimPrefix(srv.URL, "https://"),
		&tls.Config{InsecureSkipVerify: true})
	if err == nil {
		_ = conn.Close()
		t.Fatal("dead proxy was silently bypassed by the utls layer")
	}
	if len(recorder.samples()) != 0 {
		t.Fatal("target received a ClientHello from a direct dial")
	}
}

func TestConfigRejectsUnknownFingerprint(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TLSFingerprints = []string{"safari_ios_99"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("unknown ClientHello profile was accepted")
	}
}
