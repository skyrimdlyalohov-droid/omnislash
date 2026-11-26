package omnislash

import (
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"sync"
	"time"
)

// ErrProxyTransport marks a failure that happened before a target response
// existed. Such a failure is evidence about the exit node, never about the
// technique under test, and is safe to retry through a different proxy.
var ErrProxyTransport = errors.New("omnislash: proxy transport failure")

type proxyTransportError struct{ err error }

func (e *proxyTransportError) Error() string { return e.err.Error() }
func (e *proxyTransportError) Unwrap() error { return e.err }

func (e *proxyTransportError) Is(target error) bool { return target == ErrProxyTransport }

// markProxyTransport keeps the original text for diagnostics while making the
// failure machine-detectable through errors.Is.
func markProxyTransport(err error) error {
	if err == nil {
		return nil
	}
	var tagged *proxyTransportError
	if errors.As(err, &tagged) {
		return err
	}
	return &proxyTransportError{err: err}
}

// IsProxyTransportError reports whether err describes a broken exit path:
// CONNECT/SOCKS5 handshake failures, resets, EOF before a target response,
// dial timeouts or an exhausted pool. A target that answers 403/429 is never
// in this category: it must be classified as a target outcome instead.
func IsProxyTransportError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrProxyTransport) || errors.Is(err, ErrNoProxyAvailable) || errors.Is(err, ErrNoSniper) {
		return true
	}
	msg := strings.ToLower(err.Error())
	for _, marker := range []string{
		"dial proxy",
		"proxy connect failed",
		"connect status",
		"connect headers",
		"write connect",
		"socks5",
		"no usable proxy",
		"create session",
		"all attempts failed",
		"i/o timeout",
		"connection reset by peer",
		"connection refused",
		"broken pipe",
		"network is unreachable",
		"host is unreachable",
	} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	// A tunnel that dies before any byte from the target is a proxy failure.
	// Callers that already parsed a response must not use this classifier as a
	// reason to retry (see probe.Runner.Run).
	return strings.Contains(msg, "eof")
}

// ttfbConn enforces a hard first-byte deadline on a connection that has just
// completed a handshake. After that byte arrives the caller's own read
// deadlines take over, so long-lived streaming probes are unaffected.
type ttfbConn struct {
	net.Conn
	timeout  time.Duration
	fallback time.Time

	mu      sync.Mutex
	pending bool
}

func newTTFBConn(c net.Conn, timeout time.Duration) net.Conn {
	return newTTFBConnWithFallback(c, timeout, time.Time{})
}

// newTTFBConnWithFallback restores deadline after the first byte. Callers with
// a total operation budget (for example admission) pass it here so the second
// read cannot become unbounded once the TTFB deadline is cleared.
func newTTFBConnWithFallback(c net.Conn, timeout time.Duration, fallback time.Time) net.Conn {
	if c == nil || timeout <= 0 {
		return c
	}
	return &ttfbConn{Conn: c, timeout: timeout, fallback: fallback, pending: true}
}

func (c *ttfbConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if c.pending {
		_ = c.SetReadDeadline(time.Now().Add(c.timeout))
	}
	c.mu.Unlock()

	n, err := c.Conn.Read(p)

	c.mu.Lock()
	if c.pending {
		c.pending = false
		_ = c.SetReadDeadline(c.fallback)
	}
	c.mu.Unlock()
	return n, err
}

// NetConn lets ProxyOf and probe guards unwrap to the underlying connection.
func (c *ttfbConn) NetConn() net.Conn { return c.Conn }

// ConnectionState forwards the TLS state through the TTFB guard. Without it a
// fingerprinted session reports an empty ALPN to H2 probes, so an actually
// h2-negotiated connection is misclassified as a plain TLS connection.
func (c *ttfbConn) ConnectionState() tls.ConnectionState {
	state, _ := TLSState(c.Conn)
	return state
}
