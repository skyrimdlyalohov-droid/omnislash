package probe

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	rawhttp "github.com/projectdiscovery/rawhttp/client"
)

// requestSpec is the input to the wire renderer. Only the fields that must be
// byte-exact are exposed: method, path, ordered headers (with duplicates) and
// the body. Nothing here can add, sort or merge a header.
type requestSpec struct {
	Method  string
	Path    string
	Version rawhttp.Version
	Headers []rawhttp.Header
	Body    []byte
}

// render turns a spec into exact request bytes using projectdiscovery/rawhttp,
// which preserves header order, casing and duplicates. The bytes are returned
// to the caller; rawhttp never gets the socket.
func render(spec requestSpec) ([]byte, error) {
	var buf bytes.Buffer
	c := rawhttp.NewClient(&buf)
	version := spec.Version
	if version.Major == 0 {
		version = rawhttp.HTTP_1_1
	}
	req := &rawhttp.Request{
		Method:                 spec.Method,
		Path:                   spec.Path,
		Version:                version,
		Headers:                spec.Headers,
		AutomaticContentLength: false,
		AutomaticHost:          false,
	}
	if spec.Body != nil {
		req.Body = bytes.NewReader(spec.Body)
	}
	if err := c.WriteRequest(req); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// exec owns one connection for the duration of a probe: it writes bytes, reads
// framed responses and records both sides of the exchange.
type exec struct {
	res       *Result
	ctx       context.Context
	conn      net.Conn
	br        *bufio.Reader
	start     time.Time
	seq       int
	timeout   time.Duration
	maxHeader int64
	maxBody   int64
	sink      *payloadSink
}

func newExec(ctx context.Context, name string, target Target, conn net.Conn, timeout time.Duration, maxHeader, maxBody int64) *exec {
	start := time.Now()
	return &exec{
		res:       newResult(name, target, conn),
		ctx:       ctx,
		conn:      conn,
		br:        bufio.NewReaderSize(conn, 16<<10),
		start:     start,
		timeout:   orDuration(timeout, defaultTimeout),
		maxHeader: orInt64(maxHeader, defaultMaxHeader),
		maxBody:   orInt64(maxBody, defaultMaxBody),
		sink:      payloadSinkFrom(ctx),
	}
}

// deadline combines the probe timeout with the caller's context deadline.
func (e *exec) deadline() time.Time {
	d := time.Now().Add(e.timeout)
	if dl, ok := e.ctx.Deadline(); ok && dl.Before(d) {
		return dl
	}
	return d
}

// attach replaces the socket under a running exec. The result, sequence
// counters and start time are kept, so a multi-connection run is recorded as
// one experiment instead of unrelated results.
func (e *exec) attach(conn net.Conn) {
	e.conn = conn
	e.br = bufio.NewReaderSize(conn, 16<<10)
}

// write sends payload in exactly one conn.Write call and records the bytes.
func (e *exec) write(payload []byte) error {
	if err := e.ctx.Err(); err != nil {
		return err
	}
	at := time.Since(e.start)
	_ = e.conn.SetWriteDeadline(e.deadline())
	t0 := time.Now()
	n, err := e.conn.Write(payload)
	took := time.Since(t0)
	if n > 0 {
		e.seq++
		e.res.addWrite(e.seq, payload[:n], at, took)
		e.sink.record(payload[:n])
	}
	if err != nil {
		return err
	}
	if n != len(payload) {
		return io.ErrShortWrite
	}
	return nil
}

// read reads one response. A timeout is returned as a net.Error and means "no
// response within the deadline", which is itself evidence for some probes.
func (e *exec) read() (*Response, error) {
	_ = e.conn.SetReadDeadline(e.deadline())
	at := time.Since(e.start)
	resp, err := readResponse(e.br, at, e.maxHeader, e.maxBody)
	if resp != nil {
		resp.Seq = len(e.res.Responses) + 1
		e.res.Responses = append(e.res.Responses, *resp)
	}
	return resp, err
}

// readUntilIdle reads responses until the peer goes quiet for idle.
func (e *exec) readUntilIdle(idle time.Duration) []*Response {
	if idle <= 0 {
		idle = 250 * time.Millisecond
	}
	var out []*Response
	for {
		_ = e.conn.SetReadDeadline(time.Now().Add(idle))
		at := time.Since(e.start)
		resp, err := readResponse(e.br, at, e.maxHeader, e.maxBody)
		if resp != nil {
			resp.Seq = len(e.res.Responses) + 1
			e.res.Responses = append(e.res.Responses, *resp)
			out = append(out, resp)
			continue
		}
		if err != nil && isTimeout(err) {
			return out
		}
		return out
	}
}

func (e *exec) finish() *Result {
	e.res.Duration = time.Since(e.start)
	return e.res
}

func (e *exec) addFinding(f Finding) {
	e.res.Findings = append(e.res.Findings, f)
}

// readResponse parses one HTTP/1.x response from br and keeps the exact bytes
// it consumed. Framing is resolved here, not by net/http, so a desynchronized
// stream is visible instead of silently normalized.
func readResponse(br *bufio.Reader, at time.Duration, maxHeader, maxBody int64) (*Response, error) {
	var raw bytes.Buffer
	line, err := readLine(br, &raw, maxHeader)
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(strings.TrimRight(line, "\r\n"))
	if len(fields) < 2 {
		return nil, fmt.Errorf("probe: malformed status line %q", line)
	}
	status, convErr := strconv.Atoi(fields[1])
	if convErr != nil {
		return nil, fmt.Errorf("probe: malformed status code %q", fields[1])
	}
	resp := &Response{
		At:      at,
		Version: fields[0],
		Status:  status,
		Reason:  strings.Join(fields[2:], " "),
	}
	for {
		line, err = readLine(br, &raw, maxHeader)
		if err != nil {
			return resp, err
		}
		if line == "\r\n" || line == "\n" {
			break
		}
		key, value, ok := strings.Cut(strings.TrimRight(line, "\r\n"), ":")
		if !ok {
			continue
		}
		resp.Headers = append(resp.Headers, Header{Key: key, Value: strings.TrimLeft(value, " \t")})
	}

	chunked := false
	for _, te := range resp.headerValues("Transfer-Encoding") {
		if strings.Contains(strings.ToLower(te), "chunked") {
			chunked = true
		}
	}
	contentLength := int64(-1)
	if cl := resp.headerValues("Content-Length"); len(cl) > 0 {
		if n, err := strconv.ParseInt(strings.TrimSpace(cl[0]), 10, 64); err == nil {
			contentLength = n
		}
	}

	var body bytes.Buffer
	switch {
	case chunked:
		resp.Framing = "chunked"
		truncated, err := readChunked(br, &raw, &body, maxBody)
		resp.Truncated = truncated
		if err != nil {
			return resp, err
		}
	case contentLength >= 0:
		resp.Framing = "content-length"
		n := contentLength
		if n > maxBody {
			n = maxBody
			resp.Truncated = true
		}
		if n > 0 {
			if _, err := copyN(io.MultiWriter(&raw, &body), br, n); err != nil {
				return resp, err
			}
		}
	case status == 204 || status == 304 || (status >= 100 && status < 200):
		resp.Framing = "none"
	default:
		resp.Framing = "close"
		n, err := copyN(io.MultiWriter(&raw, &body), br, maxBody)
		_ = n
		if err != nil && err != io.EOF {
			return resp, err
		}
		if err == nil {
			resp.Truncated = true
		}
	}
	resp.Body = body.String()
	resp.Raw = raw.String()
	return resp, nil
}

// readChunked reads a chunked body and keeps the wire form in raw while
// accumulating the decoded body separately.
func readChunked(br *bufio.Reader, raw, body *bytes.Buffer, maxBody int64) (bool, error) {
	var total int64
	for {
		line, err := readLine(br, raw, defaultMaxHeader)
		if err != nil {
			return false, err
		}
		sizeText := strings.TrimSpace(line)
		if i := strings.IndexByte(sizeText, ';'); i >= 0 {
			sizeText = sizeText[:i]
		}
		size, err := strconv.ParseInt(strings.TrimSpace(sizeText), 16, 64)
		if err != nil {
			return false, fmt.Errorf("probe: malformed chunk size %q", line)
		}
		if size == 0 {
			for {
				trailer, err := readLine(br, raw, defaultMaxHeader)
				if err != nil {
					return false, err
				}
				if trailer == "\r\n" || trailer == "\n" {
					return false, nil
				}
			}
		}
		if total+size > maxBody {
			// Consume the rest of the chunk so the stream stays aligned, but do
			// not grow the body beyond the limit.
			if _, err := copyN(io.Discard, br, size+2); err != nil {
				return true, err
			}
			return true, nil
		}
		if _, err := copyN(io.MultiWriter(raw, body), br, size); err != nil {
			return false, err
		}
		total += size
		if _, err := copyN(raw, br, 2); err != nil {
			return false, err
		}
	}
}

// readLine reads a single CRLF-terminated line, copying it into raw and
// bounding the buffered header section.
func readLine(br *bufio.Reader, raw *bytes.Buffer, max int64) (string, error) {
	var line bytes.Buffer
	for {
		b, err := br.ReadByte()
		if err != nil {
			return "", err
		}
		line.WriteByte(b)
		raw.WriteByte(b)
		if b == '\n' {
			return line.String(), nil
		}
		if int64(line.Len()) > max {
			return "", fmt.Errorf("probe: line exceeds %d bytes", max)
		}
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return err != nil && errors.As(err, &ne) && ne.Timeout()
}
