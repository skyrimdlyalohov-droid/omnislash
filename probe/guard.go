package probe

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/skyrimdlyalohov-droid/omnislash"
)

var (
	// ErrResponseTooLarge is returned when the peer exceeds the configured
	// response bound. The response is rejected instead of being handed to the
	// parser as a truncated body.
	ErrResponseTooLarge = omnislash.ErrResponseTooLarge

	// ErrTimeout is the sentinel for a read deadline. errors.Is works, and the
	// concrete value also satisfies net.Error so existing probe logic still
	// treats a timeout as evidence rather than a transport failure.
	ErrTimeout = omnislash.ErrTimeout
)

// probeTimeoutError preserves net.Error while allowing errors.Is(err,
// probe.ErrTimeout). Probes use net.Error to distinguish "the peer was silent
// inside the window" from "the connection broke".
type probeTimeoutError struct {
	err error
}

func (e *probeTimeoutError) Error() string   { return fmt.Sprintf("%s: %v", ErrTimeout, e.err) }
func (e *probeTimeoutError) Unwrap() error   { return e.err }
func (e *probeTimeoutError) Timeout() bool   { return true }
func (e *probeTimeoutError) Temporary() bool { return true }
func (e *probeTimeoutError) Is(target error) bool {
	return target == ErrTimeout
}

// guardedConn enforces the two I/O invariants of the runner:
//
//   - the total number of response bytes is bounded; exceeding the bound is an
//     error, never a silently truncated body;
//   - on Race probes every read uses a fixed deadline that cannot be changed by
//     a per-job dynamic setting, so burst timing is not distorted between runs.
//
// It deliberately preserves NetConn() and ConnectionState(), because probes
// need proxy attribution and TLS ALPN checks after wrapping.
type guardedConn struct {
	net.Conn

	mu           sync.Mutex
	maxRead      int64
	read         int64
	readTimeout  time.Duration
	fixedTimeout bool
	readDeadline time.Time
}

func newGuardedConn(conn net.Conn, maxRead int64, timeout time.Duration, fixed bool) net.Conn {
	if conn == nil {
		return nil
	}
	return &guardedConn{
		Conn:         conn,
		maxRead:      maxRead,
		readTimeout:  timeout,
		fixedTimeout: fixed,
	}
}

func (c *guardedConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.mu.Lock()
	if c.maxRead > 0 {
		remaining := c.maxRead - c.read
		if remaining <= 0 {
			c.mu.Unlock()
			// The body may be exactly at the bound. Probe one byte so an exact
			// EOF is still EOF, while any extra byte is a hard limit error.
			var one [1]byte
			n, err := c.Conn.Read(one[:])
			if n > 0 {
				return 0, fmt.Errorf("%w: limit %d bytes", ErrResponseTooLarge, c.maxRead)
			}
			return 0, err
		}
		if int64(len(p)) > remaining {
			p = p[:remaining]
		}
	}
	if c.readTimeout > 0 {
		deadline := time.Now().Add(c.readTimeout)
		// A race probe uses the fixed timeout unconditionally. Other probes
		// may request a shorter deadline; a longer one is capped by the runner.
		if !c.fixedTimeout && !c.readDeadline.IsZero() && c.readDeadline.Before(deadline) {
			deadline = c.readDeadline
		}
		_ = c.Conn.SetReadDeadline(deadline)
	}
	c.mu.Unlock()

	n, err := c.Conn.Read(p)
	if n > 0 {
		c.mu.Lock()
		c.read += int64(n)
		c.mu.Unlock()
	}
	if err == nil {
		return n, nil
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return n, &probeTimeoutError{err: err}
	}
	return n, err
}

func (c *guardedConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.mu.Unlock()
	return c.Conn.SetReadDeadline(t)
}

func (c *guardedConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.mu.Unlock()
	return c.Conn.SetDeadline(t)
}

// NetConn lets omnislash.ProxyOf and TCP option helpers unwrap this guard.
func (c *guardedConn) NetConn() net.Conn { return c.Conn }

// Unwrap is the conventional generic unwrap hook.
func (c *guardedConn) Unwrap() net.Conn { return c.Conn }

// ConnectionState preserves the ALPN/version view required by H2 probes. A
// non-TLS connection reports the zero state, which fails the h2 check instead
// of silently downgrading the probe.
func (c *guardedConn) ConnectionState() tls.ConnectionState {
	state, _ := omnislash.TLSState(c.Conn)
	return state
}
