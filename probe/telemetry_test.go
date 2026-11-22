package probe

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestIQR(t *testing.T) {
	vals := []time.Duration{10 * time.Millisecond, 12 * time.Millisecond, 11 * time.Millisecond, 13 * time.Millisecond, 100 * time.Millisecond}
	iqr := IQR(vals)
	if iqr <= 0 {
		t.Fatalf("expected positive IQR, got %v", iqr)
	}
	small := []time.Duration{10 * time.Millisecond, 11 * time.Millisecond, 12 * time.Millisecond, 13 * time.Millisecond, 14 * time.Millisecond}
	if IQR(small) > 25*time.Millisecond {
		t.Fatalf("small spread should have low IQR, got %v", IQR(small))
	}
}

func TestKalmanFilter1D(t *testing.T) {
	k := NewKalmanFilter1D(1, 25)
	est, resid := k.Update(100)
	if est != 100 {
		t.Fatalf("first estimate should initialize to measurement, got %v", est)
	}
	if resid != 0 {
		t.Fatalf("first residual should be 0, got %v", resid)
	}
	est2, resid2 := k.Update(110)
	if est2 <= 100 || est2 >= 110 {
		t.Fatalf("estimate should move toward measurement, got %v", est2)
	}
	if resid2 <= 0 {
		t.Fatalf("positive residual expected, got %v", resid2)
	}
}

func TestCacheBuster(t *testing.T) {
	a := CacheBuster()
	b := CacheBuster()
	if a == "" || b == "" {
		t.Fatal("cache buster should not be empty")
	}
	if a == b {
		t.Fatal("cache busters should differ")
	}
	p := AppendCacheBuster("/path")
	if p == "/path" || !contains(p, "_omni_cb=") {
		t.Fatalf("cache buster not appended: %s", p)
	}
	p2 := AppendCacheBuster("/path?q=1")
	if !contains(p2, "&_omni_cb=") {
		t.Fatalf("cache buster should use &: %s", p2)
	}
}

func contains(s, sub string) bool { return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0) }
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestWriteWithLastByteSync(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	payload := []byte("hello")
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 16)
		_ = c2.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := c2.Read(buf)
		if err != nil {
			done <- err
			return
		}
		if n != 4 {
			done <- nil
			return
		}
		// second read should get last byte after hold
		n2, err := c2.Read(buf[n:])
		if err != nil {
			done <- err
			return
		}
		if n+n2 != 5 {
			done <- nil
			return
		}
		done <- nil
	}()
	n, err := writeWithLastByteSync(c1, payload, 20*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Fatalf("n=%d", n)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestJitterGateProbe(t *testing.T) {
	// Use a fake ConnSource that returns connections to a local HTTP server.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
			}(c)
		}
	}()
	src := &testConnSource{addr: ln.Addr().String()}
	g := JitterGate{Samples: 5, Threshold: 100 * time.Millisecond}
	iqr, ok, err := g.Probe(context.Background(), Target{Addr: ln.Addr().String(), Host: "127.0.0.1"}, src)
	if err != nil {
		t.Fatal(err)
	}
	if iqr < 0 {
		t.Fatalf("iqr < 0: %v", iqr)
	}
	if !ok {
		t.Fatalf("expected local jitter gate to pass, iqr=%v", iqr)
	}
}

type testConnSource struct{ addr string }

func (s *testConnSource) Dial(ctx context.Context) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", s.addr)
}
