// Package probe implements byte-exact attack probes on top of omnislash
// connections.
//
// One rule governs the whole package: omnislash owns the socket, libraries own
// the logic. A Probe never dials, never resolves a hostname, never creates an
// http.Client and never lets net/http decide where a request ends. It receives
// an already dialed net.Conn - normally from a pinned Session - writes request
// bytes with conn.Write and reads responses through its own bufio.Reader.
//
// That is what keeps two properties of the transport intact:
//
//   - one experiment runs on one exit IP, because no probe can open a second
//     connection behind the caller's back;
//   - the bytes on the wire are exactly the bytes the probe built, because no
//     probe hands the payload to a request writer that normalizes framing.
//
// Libraries are used where they add real value: projectdiscovery/rawhttp
// renders request lines and headers (including duplicate and malformed ones)
// into bytes, golang.org/x/net/http2 encodes HTTP/2 frames, and the probes
// implement the timing logic themselves.
package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"time"

	"github.com/skyrimdlyalohov-droid/omnislash"
)

// connectionState normalises crypto/tls and uTLS state across the transport
// wrappers, so H2 probes see the negotiated ALPN on fingerprinted sessions too.
func connectionState(conn net.Conn) (tls.ConnectionState, bool) {
	return omnislash.TLSState(conn)
}

// Probe is one attack module. Execute must use only the provided conn: no
// dialing, no pools, no background connections.
type Probe interface {
	// Name is a stable identifier used in logs and Result.
	Name() string
	// Execute runs the probe against target over an already established
	// connection. It must not close conn unless it opened anything itself.
	Execute(ctx context.Context, target Target, conn net.Conn) (*Result, error)
}

// Target describes the request target. Addr is the address that was dialed and
// is used for the Host header when Host is empty.
type Target struct {
	Addr string
	Host string
	Path string
}

// HostHeader returns the value for the Host header.
func (t Target) HostHeader() string {
	if t.Host != "" {
		return t.Host
	}
	return t.Addr
}

// RequestPath returns the path to put on the request line.
func (t Target) RequestPath() string {
	if t.Path == "" {
		return "/"
	}
	return t.Path
}

// Result is one probe execution. It always carries the exact bytes written and
// the exact bytes read, so a verdict can be checked by hand instead of trusted.
type Result struct {
	Probe       string        `json:"probe"`
	Target      string        `json:"target"`
	StartedAt   time.Time     `json:"started_at"`
	Duration    time.Duration `json:"duration_ns"`
	Attribution Attribution   `json:"attribution"`
	Exchanges   []Exchange    `json:"exchanges,omitempty"`
	Responses   []Response    `json:"responses,omitempty"`
	Findings    []Finding     `json:"findings,omitempty"`
	// Payloads holds each request of a burst verbatim. Exchanges shows what was
	// actually written to the socket (a burst is one or two writes), Payloads
	// shows the individual requests inside it.
	Payloads []string `json:"payloads,omitempty"`
	Burst    *Burst   `json:"burst,omitempty"`
	// Mutation is the grammar mutation responsible for the last exchange in a
	// differential-fuzz run. It lets the daemon learn which mutation worked
	// without re-parsing the raw request from the audit log.
	Mutation string `json:"mutation,omitempty"`
	// ParserDivergence is the FSM verdict for the last exchange. It is copied
	// into the daemon's JSONL record as "parser_divergence".
	ParserDivergence string `json:"parser_divergence,omitempty"`
	// TimingDivergence carries a timing-only verdict from paired TTFB samples.
	// The daemon promotes it only when no stronger byte-level verdict exists.
	TimingDivergence string `json:"timing_divergence,omitempty"`
}

// Burst describes how a batch of requests was emitted. A single-packet attack
// is one write containing every request, or all final bytes in one write after
// the prefixes were parked.
type Burst struct {
	Requests int     `json:"requests"`
	Bytes    int     `json:"bytes"`
	Writes   int     `json:"writes"`
	Mode     string  `json:"mode"`
	HoldMS   float64 `json:"hold_ms,omitempty"`
}

// Attribution answers "which exit IP produced this result". Verified is true
// when the connection was opened by omnislash and the proxy handle was found;
// in that case Proxy is the proxy label and ExitIP is the validated egress
// address when one is known.
type Attribution struct {
	Proxy    string `json:"proxy,omitempty"`
	ExitIP   string `json:"exit_ip,omitempty"`
	Verified bool   `json:"verified"`
}

// Exchange is one write. Raw is the exact byte sequence handed to conn.Write.
type Exchange struct {
	Seq     int           `json:"seq"`
	At      time.Duration `json:"at_ns"`
	Raw     string        `json:"raw"`
	Bytes   int           `json:"bytes"`
	WriteMS float64       `json:"write_ms"`
}

// Response is one parsed response plus the raw bytes it occupied. Framing says
// how the reader decided where the message ended, which matters when the two
// sides disagree about Content-Length and Transfer-Encoding.
type Response struct {
	Seq       int           `json:"seq"`
	At        time.Duration `json:"at_ns"`
	Version   string        `json:"version,omitempty"`
	Status    int           `json:"status"`
	Reason    string        `json:"reason,omitempty"`
	Headers   []Header      `json:"headers,omitempty"`
	Body      string        `json:"body,omitempty"`
	Raw       string        `json:"raw"`
	Framing   string        `json:"framing"`
	Truncated bool          `json:"truncated,omitempty"`
}

// Header keeps order and repetition, which net/http.Header cannot represent.
type Header struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Finding is a heuristic verdict with an explicit confidence level. The probe
// never upgrades a heuristic to a certainty: the raw exchange is the evidence.
type Finding struct {
	Kind       string `json:"kind"`
	Confidence string `json:"confidence"` // low, medium, high
	Detail     string `json:"detail"`
	Response   int    `json:"response_seq,omitempty"`
}

// Confidence levels.
const (
	ConfidenceLow    = "low"
	ConfidenceMedium = "medium"
	ConfidenceHigh   = "high"
)

// ErrNotImplemented marks a module that is part of the architecture but has no
// implementation yet. It is returned instead of a silently empty result.
var ErrNotImplemented = errors.New("probe: not implemented")

const (
	defaultTimeout   = 10 * time.Second
	defaultMaxHeader = 64 << 10
	defaultMaxBody   = 1 << 20
)

func orDuration(d, fallback time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return fallback
}

func orInt64(v, fallback int64) int64 {
	if v > 0 {
		return v
	}
	return fallback
}

// newResult seeds a Result with attribution taken from conn. The attribution
// is the reason probes receive a net.Conn instead of an address: the proxy is
// already attached to the socket by omnislash.
func newResult(name string, target Target, conn net.Conn) *Result {
	return &Result{
		Probe:       name,
		Target:      target.Addr,
		StartedAt:   time.Now(),
		Attribution: attributionOf(conn),
	}
}

// attributionOf resolves the proxy behind conn. ProxyOf unwraps TLS so a
// connection returned by Session.DialTLSContext is attributed correctly.
func attributionOf(conn net.Conn) Attribution {
	pr, ok := omnislash.ProxyOf(conn)
	if !ok || pr == nil {
		return Attribution{}
	}
	return Attribution{Proxy: pr.Label(), ExitIP: pr.EgressIP(), Verified: true}
}

func (r *Result) addWrite(seq int, raw []byte, at time.Duration, took time.Duration) {
	r.Exchanges = append(r.Exchanges, Exchange{
		Seq:     seq,
		At:      at,
		Raw:     string(raw),
		Bytes:   len(raw),
		WriteMS: float64(took.Microseconds()) / 1000,
	})
}

// headerValues returns every value for key, case-insensitively.
func (r *Response) headerValues(key string) []string {
	var out []string
	for _, h := range r.Headers {
		if equalFold(h.Key, key) {
			out = append(out, h.Value)
		}
	}
	return out
}

func (r *Response) hasHeader(key, value string) bool {
	for _, v := range r.headerValues(key) {
		if equalFold(v, value) {
			return true
		}
	}
	return false
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
