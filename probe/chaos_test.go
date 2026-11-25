package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skyrimdlyalohov-droid/omnislash"
	"github.com/skyrimdlyalohov-droid/omnislash/util"
)

// panicH2Probe writes a malformed HTTP/2 frame through the probe's audited
// writer and then panics, exactly where a parser bug on hostile input would.
// Runner must contain the panic, preserve the payload in panic_audit.log and
// return ErrPrecisionLost instead of a target verdict.
type panicH2Probe struct{}

func (panicH2Probe) Name() string { return "chaos/malformed-h2" }

func (panicH2Probe) Execute(ctx context.Context, target Target, conn net.Conn) (*Result, error) {
	payload := []byte{
		0x00, 0x00, 0x0c, // length 12
		0x00, 0x00, 0x00, 0x00, 0x00, // HEADERS on stream 0
		0xff, 0xff, 0xff, 0xff, 0xff, // invalid frame payload
	}
	e := newExec(ctx, "chaos/malformed-h2", target, conn, time.Second, 0, 0)
	defer e.finish()
	if err := e.write(payload); err != nil {
		return e.finish(), err
	}
	panic("malformed H2 frame: invalid stream id")
}

func chaosDialer(t *testing.T) *omnislash.Dialer {
	t.Helper()
	cfg := omnislash.DefaultConfig()
	cfg.TrustTier = omnislash.TrustTierTrusted
	cfg.AllowDirect = true
	cfg.Health.Enabled = false
	cfg.Scope.Enabled = false
	pool, err := omnislash.NewPool(&cfg, nil, nil)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	t.Cleanup(pool.Close)
	return omnislash.NewDialer(pool, nil)
}

func startBlackhole(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(io.Discard, conn)
			}()
		}
	}()
	return ln.Addr().String()
}

func TestChaosMalformedH2FramePanicIsContained(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "panic_audit.log")
	t.Setenv("OMNISLASH_PANIC_AUDIT", auditPath)

	runner := NewRunner(chaosDialer(t))
	target := Target{Addr: startBlackhole(t), Host: "127.0.0.1", Path: "/"}
	_, err := runner.Run(context.Background(), target, panicH2Probe{})
	if !errors.Is(err, util.ErrPrecisionLost) {
		t.Fatalf("error = %v, want ErrPrecisionLost", err)
	}
	if !errors.Is(err, omnislash.ErrPrecisionLost) {
		t.Fatalf("root sentinel does not match: %v", err)
	}

	raw, readErr := os.ReadFile(auditPath)
	if readErr != nil {
		t.Fatalf("panic audit was not written: %v", readErr)
	}
	lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
	if len(lines) == 0 {
		t.Fatal("panic audit is empty")
	}
	var record struct {
		Panic      string `json:"panic"`
		Stack      string `json:"stack"`
		PayloadHex string `json:"payload_hex"`
	}
	if err := json.Unmarshal(lines[len(lines)-1], &record); err != nil {
		t.Fatalf("panic audit is not JSONL: %v\n%s", err, raw)
	}
	if !strings.Contains(record.Panic, "malformed H2 frame") {
		t.Fatalf("panic reason lost: %q", record.Panic)
	}
	if record.Stack == "" {
		t.Fatal("panic audit has no stack")
	}
	if record.PayloadHex == "" {
		t.Fatal("panic audit has no payload hex dump")
	}
}

func TestChaosPoolDoesNotLeakBytesBetweenRequests(t *testing.T) {
	marker := []byte("SMUGGLED-SECRET-H2-FRAME")
	for i := 0; i < 128; i++ {
		buf := AcquireBuffer()
		full := buf[:cap(buf)]
		if len(full) != BufferSize {
			t.Fatalf("buffer size = %d, want %d", len(full), BufferSize)
		}
		for j, b := range full {
			if b != 0 {
				t.Fatalf("iteration %d: byte %d leaked as %#x", i, j, b)
			}
		}
		copy(full, marker)
		ReleaseBuffer(full)
	}

	// copyN uses the same pool internally. A response copied through it must
	// not leave the source bytes available to the next acquisition.
	src := strings.NewReader("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
	var dst bytes.Buffer
	if _, err := copyN(&dst, src, int64(src.Len())); err != nil {
		t.Fatalf("copyN: %v", err)
	}
	buf := AcquireBuffer()
	defer ReleaseBuffer(buf)
	for i, b := range buf[:cap(buf)] {
		if b != 0 {
			t.Fatalf("copyN left byte %d as %#x in the pool", i, b)
		}
	}
}

// deadlineConn records the deadline installed by guardedConn.
type deadlineConn struct {
	net.Conn
	mu       sync.Mutex
	deadline time.Time
}

func (c *deadlineConn) Read([]byte) (int, error) { return 0, fakeTimeout{} }
func (c *deadlineConn) Close() error             { return nil }
func (c *deadlineConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return nil
}
func (c *deadlineConn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }
func (c *deadlineConn) getDeadline() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.deadline
}

type fakeTimeout struct{}

func (fakeTimeout) Error() string   { return "i/o timeout" }
func (fakeTimeout) Timeout() bool   { return true }
func (fakeTimeout) Temporary() bool { return true }

func TestChaosRaceReadTimeoutIsFixed(t *testing.T) {
	conn := &deadlineConn{}
	guarded := newGuardedConn(conn, 1<<20, RaceReadTimeout, true)
	start := time.Now()
	// A dynamic caller deadline must not stretch the fixed race window.
	if err := guarded.SetReadDeadline(time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	_, err := guarded.Read(make([]byte, 1))
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("error = %v, want ErrTimeout", err)
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("timeout lost net.Error contract: %v", err)
	}
	deadline := conn.getDeadline()
	if deadline.IsZero() {
		t.Fatal("no read deadline was installed")
	}
	got := deadline.Sub(start)
	if got < RaceReadTimeout-200*time.Millisecond || got > RaceReadTimeout+200*time.Millisecond {
		t.Fatalf("race deadline = %s, want ~%s", got, RaceReadTimeout)
	}
}

func TestChaosResponseLimitIsAnErrorNotTruncation(t *testing.T) {
	conn := &scriptedConn{data: []byte("12345")}
	guarded := newGuardedConn(conn, 4, time.Second, false)
	first := make([]byte, 4)
	if _, err := io.ReadFull(guarded, first); err != nil {
		t.Fatalf("first read: %v", err)
	}
	if string(first) != "1234" {
		t.Fatalf("first read = %q", first)
	}
	_, err := guarded.Read(make([]byte, 1))
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("error = %v, want ErrResponseTooLarge", err)
	}
}

type scriptedConn struct {
	net.Conn
	mu   sync.Mutex
	data []byte
}

func (c *scriptedConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, c.data)
	c.data = c.data[n:]
	return n, nil
}
func (c *scriptedConn) Close() error                    { return nil }
func (c *scriptedConn) SetReadDeadline(time.Time) error { return nil }
func (c *scriptedConn) SetDeadline(time.Time) error     { return nil }
func (c *scriptedConn) String() string                  { return fmt.Sprintf("scripted(%d)", len(c.data)) }
