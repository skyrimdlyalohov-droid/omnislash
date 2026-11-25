package probe

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// replyConn is a minimal connection that answers the baseline request with a
// complete HTTP/1.1 response. The multi-connection probes close it before the
// next stage, so no real server is needed to reproduce the dial failure.
type replyConn struct {
	mu   sync.Mutex
	data []byte
}

func (c *replyConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.data) == 0 {
		return 0, errors.New("reply exhausted")
	}
	n := copy(p, c.data)
	c.data = c.data[n:]
	return n, nil
}
func (c *replyConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *replyConn) Close() error                     { return nil }
func (c *replyConn) SetDeadline(time.Time) error      { return nil }
func (c *replyConn) SetReadDeadline(time.Time) error  { return nil }
func (c *replyConn) SetWriteDeadline(time.Time) error { return nil }
func (c *replyConn) LocalAddr() net.Addr              { return nil }
func (c *replyConn) RemoteAddr() net.Addr             { return nil }

type failAfterFirstSource struct{ n int }

func (s *failAfterFirstSource) Dial(context.Context) (net.Conn, error) {
	s.n++
	if s.n == 1 {
		return &replyConn{data: []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")}, nil
	}
	return nil, errors.New("dial failed: exit unavailable")
}

func testTarget() Target { return Target{Addr: "example.com:80", Host: "example.com"} }

// A failed second dial must surface as the dial error. Before the nil guard in
// the deferred close, conn was nil at that point and the panic was recorded as
// ErrPrecisionLost, hiding the real transport failure as an engine fault.
func TestSmuggleMultiDialFailureReturnsDialError(t *testing.T) {
	p := &SmugglingProbe{Variant: VariantCLTE, Timeout: time.Second, Idle: 10 * time.Millisecond}
	_, err := p.ExecuteMulti(context.Background(), testTarget(), &failAfterFirstSource{})
	if err == nil || !strings.Contains(err.Error(), "dial failed: exit unavailable") {
		t.Fatalf("error = %v, want the real dial failure", err)
	}
}

func TestSmuggleChainDialFailureReturnsDialError(t *testing.T) {
	p := &SmuggleChainProbe{Variant: VariantCLTE, Timeout: time.Second, Idle: 10 * time.Millisecond}
	_, err := p.ExecuteMulti(context.Background(), testTarget(), &failAfterFirstSource{})
	if err == nil || !strings.Contains(err.Error(), "dial failed: exit unavailable") {
		t.Fatalf("error = %v, want the real dial failure", err)
	}
}
