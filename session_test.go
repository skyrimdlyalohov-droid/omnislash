package omnislash

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

func TestSessionPinsOneProxyForExperiment(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Health.Enabled = false
	cfg.Strategy = StrategyRoundRobin
	a := startConnectProxy(t, "")
	b := startConnectProxy(t, "")
	pool := newTestPool(t, cfg, mustProxy(t, a.URL()), mustProxy(t, b.URL()))
	dialer := NewDialer(pool, testLogger())
	echo := startEchoServer(t)

	first, err := dialer.NewSession(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	second, err := dialer.NewSession(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if first.Proxy() == second.Proxy() {
		t.Fatal("independent experiments received the same proxy")
	}

	for i := 0; i < 2; i++ {
		conn, err := first.DialContext(context.Background(), "tcp", echo)
		if err != nil {
			t.Fatal(err)
		}
		got, ok := ProxyOf(conn)
		if !ok || got != first.Proxy() {
			t.Fatalf("dial %d did not use the pinned proxy", i)
		}
		if _, err := io.WriteString(conn, "ping"); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
	}
}

func TestSessionFailsClosedAfterExpiry(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Health.Enabled = false
	proxy := startConnectProxy(t, "")
	pool := newTestPool(t, cfg, mustProxy(t, proxy.URL()))
	dialer := NewDialer(pool, testLogger())
	s, err := dialer.NewSession(10 * time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return time.Now().Add(time.Hour) }
	if _, err := s.DialContext(context.Background(), "tcp", startEchoServer(t)); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("expired session error = %v, want ErrSessionExpired", err)
	}
}

func TestSessionDoesNotRotateOnFailure(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Health.Enabled = false
	cfg.MaxDialAttempts = 5
	dead := startEchoTunnelProxy(t, nil, false, true)
	echo := startEchoServer(t)
	pool := newTestPool(t, cfg, mustProxy(t, dead.URL()))
	dialer := NewDialer(pool, testLogger())
	s, err := dialer.NewSession(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := s.DialContext(context.Background(), "tcp", echo)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := conn.Write([]byte("probe")); err == nil {
		buf := make([]byte, 5)
		if _, err = io.ReadFull(conn, buf); err == nil {
			t.Fatal("session quietly used another path after the pinned proxy died")
		}
	}
	_ = conn.Close()
}

func TestSessionRejectsZeroTTL(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Health.Enabled = false
	pool := newTestPool(t, cfg, mustProxy(t, "http://127.0.0.1:1"))
	dialer := NewDialer(pool, testLogger())
	if _, err := dialer.NewSession(0); err == nil {
		t.Fatal("zero session ttl was accepted")
	}
}

func TestSessionPinsDirectEgressWhenAllowed(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TrustTier = TrustTierTrusted
	cfg.AllowDirect = true
	cfg.Health.Enabled = false
	cfg.Scope.Enabled = false
	pool := newTestPool(t, cfg)
	dialer := NewDialer(pool, testLogger())
	echo := startEchoServer(t)

	s, err := dialer.NewSession(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if s.Proxy() != nil {
		t.Fatalf("direct session pinned proxy %v", s.Proxy())
	}
	conn, err := s.DialContext(context.Background(), "tcp", echo)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, ok := ProxyOf(conn); ok {
		t.Fatal("direct connection must not claim a proxy attribution")
	}
}

func TestSessionDialRejectsClosedPool(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Health.Enabled = false
	pool := newTestPool(t, cfg, mustProxy(t, "http://127.0.0.1:1"))
	dialer := NewDialer(pool, testLogger())
	s, err := dialer.NewSession(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	pool.Close()
	if _, err := s.DialContext(context.Background(), "tcp", "127.0.0.1:1"); !errors.Is(err, ErrPoolClosed) {
		t.Fatalf("closed pool error = %v", err)
	}
}
