package probe

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

// gadgetMock is an in-process HTTP/1.1 peer on net.Pipe. It never dials and
// never touches a real interface: the probe only writes bytes to the conn it
// was given.
type gadgetMock struct {
	trigger  string
	status   int
	requests atomic.Int32
}

type gadgetRequest struct {
	path    string
	headers map[string]string
}

// readGadgetRequest parses one HTTP/1.1 request from a loopback peer. It is
// shared by every in-process mock so the tests cannot disagree about framing.
func readGadgetRequest(conn net.Conn) (gadgetRequest, error) {
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		return gadgetRequest{}, err
	}
	parts := strings.Fields(strings.TrimRight(line, "\r\n"))
	path := "/"
	if len(parts) > 1 {
		path = parts[1]
	}
	headers := make(map[string]string)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return gadgetRequest{}, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		key, value, ok := strings.Cut(line, ":")
		if ok {
			headers[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
		}
	}
	drainGadgetBody(br, headers)
	return gadgetRequest{path: path, headers: headers}, nil
}

// drainGadgetBody consumes the framed body with the same buffered reader so a
// loopback peer never leaves the probe's single Write blocked on net.Pipe.
func drainGadgetBody(br *bufio.Reader, headers map[string]string) {
	if raw, ok := headers["content-length"]; ok {
		if n, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil && n > 0 {
			_, _ = io.ReadFull(br, make([]byte, n))
		}
		return
	}
	if te := strings.ToLower(headers["transfer-encoding"]); strings.Contains(te, "chunked") {
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			sizeField := strings.TrimSpace(strings.SplitN(line, ";", 2)[0])
			n, err := strconv.ParseInt(sizeField, 16, 64)
			if err != nil || n < 0 {
				return
			}
			if n == 0 {
				for {
					trailer, err := br.ReadString('\n')
					if err != nil || strings.TrimRight(trailer, "\r\n") == "" {
						return
					}
				}
			}
			if _, err := io.ReadFull(br, make([]byte, n+2)); err != nil { // chunk data + CRLF
				return
			}
		}
	}
}

func (m *gadgetMock) serve(conn net.Conn) {
	defer conn.Close()
	req, err := readGadgetRequest(conn)
	if err != nil {
		return
	}
	m.requests.Add(1)
	if m.status != 0 {
		writeGadgetResponse(conn, m.status, nil, "blocked")
		return
	}
	if canary, ok := req.headers[strings.ToLower(m.trigger)]; ok && canary != "" {
		writeGadgetResponse(conn, 301, map[string]string{
			"Location": "https://redirect.test/landing",
			"X-Echo":   canary,
		}, `{"ok":false}`)
		return
	}
	n := m.requests.Load()
	writeGadgetResponse(conn, 200, nil,
		fmt.Sprintf(`{"admin_panel":true,"token":"T%d","ts":%d,"items":[{"name":"a"}]}`, n, n))
}

func writeGadgetResponse(conn net.Conn, status int, extra map[string]string, body string) {
	var out strings.Builder
	fmt.Fprintf(&out, "HTTP/1.1 %d OK\r\nContent-Type: application/json\r\n", status)
	for key, value := range extra {
		fmt.Fprintf(&out, "%s: %s\r\n", key, value)
	}
	fmt.Fprintf(&out, "Content-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
	_, _ = conn.Write([]byte(out.String()))
}

// gadgetPeer is any in-process HTTP/1.1 mock. It keeps the pipe source shared
// by chained, standalone and rejection tests without duplicating transport.
type gadgetPeer interface{ serve(net.Conn) }

type pipeGadgetSource struct {
	mock gadgetPeer
}

func (s *pipeGadgetSource) Dial(context.Context) (net.Conn, error) {
	client, server := net.Pipe()
	go s.mock.serve(server)
	return client, nil
}

func TestGadgetProbeBisectsBatchToOneHeader(t *testing.T) {
	mock := &gadgetMock{trigger: "X-Rewrite-URL"}
	source := &pipeGadgetSource{mock: mock}
	headers := []string{
		"X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-For", "X-Real-IP",
		"X-Original-URL", "X-Rewrite-URL", "X-Host", "Accept-Language",
	}
	probe := &GadgetProbe{
		Headers:     headers,
		BatchSize:   4,
		MaxRequests: 24,
	}
	result, err := probe.ExecuteMulti(context.Background(), Target{Addr: "lab.test:80", Host: "lab.test"}, source)
	if err != nil {
		t.Fatal(err)
	}
	var confirmed bool
	for _, f := range result.Findings {
		if f.Kind == "unkeyed_header" {
			confirmed = true
			if f.Confidence != ConfidenceHigh || !strings.Contains(f.Detail, "X-Rewrite-URL") {
				t.Fatalf("finding = %+v, want high-confidence X-Rewrite-URL", f)
			}
			if f.Response <= 0 {
				t.Fatal("finding has no response sequence for the raw exchange")
			}
		}
	}
	if !confirmed {
		t.Fatalf("batch was not narrowed to one header: %+v", result.Findings)
	}
	if len(result.Exchanges) == 0 || len(result.Exchanges) >= len(headers) {
		t.Fatalf("group search sent %d requests for %d headers; expected fewer", len(result.Exchanges), len(headers))
	}
	for _, exchange := range result.Exchanges {
		if !strings.HasPrefix(exchange.Raw, "GET ") {
			t.Fatalf("gadget request is not GET: %q", exchange.Raw)
		}
		if strings.Contains(exchange.Raw, "User-Agent:") {
			t.Fatalf("probe added a scanner signature: %q", exchange.Raw)
		}
	}
}

func TestGadgetProbeSTOPRules(t *testing.T) {
	cases := []struct {
		name         string
		status       int
		wantRequests int
	}{
		{"rate limit", 429, 1},
		{"unavailable", 503, 1},
		{"repeated forbidden", 403, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mock := &gadgetMock{status: tc.status}
			probe := &GadgetProbe{
				Headers:     DefaultGadgetHeaders,
				BatchSize:   4,
				MaxRequests: 16,
			}
			result, err := probe.ExecuteMulti(context.Background(), Target{Addr: "lab.test:80", Host: "lab.test"}, &pipeGadgetSource{mock: mock})
			if err != nil {
				t.Fatal(err)
			}
			if got := int(mock.requests.Load()); got != tc.wantRequests {
				t.Fatalf("requests = %d, want %d", got, tc.wantRequests)
			}
			var stopped bool
			for _, f := range result.Findings {
				if f.Kind == "gadget_stop" {
					stopped = true
				}
				if f.Kind == "unkeyed_header" {
					t.Fatal("blocked response was mistaken for a gadget")
				}
			}
			if !stopped {
				t.Fatalf("no STOP finding: %+v", result.Findings)
			}
		})
	}
}

func TestGadgetProbeIgnoresDynamicValues(t *testing.T) {
	mock := &gadgetMock{}
	probe := &GadgetProbe{
		Headers:     []string{"X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-IP", "Via"},
		BatchSize:   4,
		MaxRequests: 8,
	}
	result, err := probe.ExecuteMulti(context.Background(), Target{Addr: "lab.test:80", Host: "lab.test"}, &pipeGadgetSource{mock: mock})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range result.Findings {
		if f.Kind != "gadget_no_signal" {
			t.Fatalf("dynamic values produced a false finding: %+v", f)
		}
	}
}

func TestGadgetCanariesAreRandomPerCall(t *testing.T) {
	probe := &GadgetProbe{}
	first, err := probe.canary()
	if err != nil {
		t.Fatal(err)
	}
	second, err := probe.canary()
	if err != nil {
		t.Fatal(err)
	}
	if first == second || len(first) != 24 || strings.Contains(first, "omni") {
		t.Fatalf("canaries are not fresh random hex values: %q, %q", first, second)
	}
}
