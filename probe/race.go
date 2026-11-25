package probe

import (
	"context"
	"fmt"
	"net"
	"time"

	rawhttp "github.com/projectdiscovery/rawhttp/client"
)

// RaceWriteMode selects how the burst is emitted. The goal is that every
// request reaches the target in the same scheduling window, so the vulnerable
// check-then-act sequence overlaps.
type RaceWriteMode string

const (
	// RaceSingleWrite concatenates all requests and issues one conn.Write. On a
	// TLS connection this is the only reliable mode: one Write becomes one or
	// more TLS records without application-level gaps.
	RaceSingleWrite RaceWriteMode = "single_write"
	// RaceWritev uses net.Buffers, which becomes one writev syscall on a TCP
	// connection. Not applicable to TLS, where it degrades to several records.
	RaceWritev RaceWriteMode = "writev"
	// RaceLastByte parks every request except its final byte, waits Hold, then
	// writes all final bytes in one call. This is the last-byte
	// synchronization technique.
	RaceLastByte RaceWriteMode = "last_byte"
)

// RaceProbe implements the H1 single-packet attack: N requests are emitted in
// one write (or with synchronized final bytes) over one connection, so they
// share one exit IP and one scheduling window.
//
// Detection is left to the caller's success criteria: the probe reports how
// many success responses arrived and how tight the response window was. A
// finding is emitted when more than one "single use" request succeeded.
type RaceProbe struct {
	// Count is the number of requests in the burst. Default 20, max 100.
	Count int
	// Method and Path default to POST /.
	Method string
	Path   string
	Body   []byte
	// Headers are added verbatim before the generated ones.
	Headers []rawhttp.Header

	Mode RaceWriteMode
	// Hold is the pause between parking prefixes and sending final bytes.
	Hold    time.Duration
	Timeout time.Duration
	// Idle bounds the wait for responses after the burst.
	Idle time.Duration

	// SingleUse declares that the target action must succeed at most once. Only
	// then is more than one success a race finding. Without it the probe reports
	// the evidence (statuses per request) and no verdict: N successful GETs are
	// not a vulnerability.
	SingleUse bool
	// SuccessCodes decides what counts as a successful request.
	SuccessCodes []int

	MaxHeader int64
	MaxBody   int64
}

func (p *RaceProbe) Name() string { return "race/single-packet" }

// Execute builds the burst, writes it with the selected synchronization mode
// and reads the responses. Requests are never split across connections: that
// would spread them over different exit IPs and defeat the attack.
func (p *RaceProbe) Execute(ctx context.Context, target Target, conn net.Conn) (*Result, error) {
	count := p.Count
	if count <= 0 {
		count = 20
	}
	if count > 100 {
		return nil, fmt.Errorf("probe: race count %d exceeds the 100 request limit", count)
	}
	method := p.Method
	if method == "" {
		method = "POST"
	}
	body := p.Body
	if body == nil {
		body = []byte("x=1")
	}
	e := newExec(ctx, p.Name(), target, conn, p.Timeout, p.MaxHeader, p.MaxBody)
	nonce := newNonce()

	payloads := make([][]byte, 0, count)
	headers := make([]rawhttp.Header, 0, len(p.Headers)+5)
	headers = append(headers, p.Headers...)
	headers = append(headers,
		rawhttp.Header{Key: "Host", Value: target.HostHeader()},
		rawhttp.Header{Key: "User-Agent", Value: "omnislash-probe/1"},
		rawhttp.Header{Key: "Content-Length", Value: fmt.Sprintf("%d", len(body))},
		rawhttp.Header{Key: "Connection", Value: "keep-alive"},
	)
	for i := 0; i < count; i++ {
		h := make([]rawhttp.Header, len(headers), len(headers)+1)
		copy(h, headers)
		h = append(h, rawhttp.Header{Key: "X-Omnislash-Race", Value: fmt.Sprintf("%s-%d", nonce, i)})
		raw, err := render(requestSpec{
			Method:  method,
			Path:    target.RequestPath(),
			Headers: h,
			Body:    body,
		})
		if err != nil {
			return e.finish(), fmt.Errorf("probe: render race request %d: %w", i, err)
		}
		payloads = append(payloads, raw)
		e.res.Payloads = append(e.res.Payloads, string(raw))
	}

	if err := sendBurst(e, payloads, p.Mode, orDuration(p.Hold, 100*time.Millisecond)); err != nil {
		return e.finish(), fmt.Errorf("probe: send burst: %w", err)
	}

	responses := e.readUntilIdle(orDuration(p.Idle, time.Second))
	success := 0
	for _, r := range responses {
		if p.isSuccess(r.Status) {
			success++
		}
	}
	if !p.SingleUse {
		// No claim about the endpoint: the operator did not say that a second
		// success is a violation, so only the raw exchanges are reported.
		return e.finish(), nil
	}
	if success > 1 {
		e.addFinding(Finding{
			Kind:       "race_success",
			Confidence: ConfidenceHigh,
			Detail:     fmt.Sprintf("%d of %d synchronized requests succeeded; a single-use action was executed more than once", success, count),
		})
	} else if success == 1 {
		e.addFinding(Finding{
			Kind:       "race_success",
			Confidence: ConfidenceLow,
			Detail:     "only one request succeeded; the burst did not win the race on this attempt",
		})
	}
	return e.finish(), nil
}

func (p *RaceProbe) isSuccess(status int) bool {
	return successStatus(p.SuccessCodes, status)
}

// successStatus reports whether status counts as a successful request.
func successStatus(codes []int, status int) bool {
	if len(codes) == 0 {
		codes = []int{200, 201, 202, 204}
	}
	for _, c := range codes {
		if status == c {
			return true
		}
	}
	return false
}

// sendBurst emits payloads according to mode and records how it did so.
func sendBurst(e *exec, payloads [][]byte, mode RaceWriteMode, hold time.Duration) error {
	if len(payloads) == 0 {
		return fmt.Errorf("probe: empty burst")
	}
	if mode == "" {
		mode = RaceSingleWrite
	}
	enableNoDelay(e.conn)

	total := 0
	for _, p := range payloads {
		total += len(p)
	}
	burst := &Burst{Requests: len(payloads), Bytes: total, HoldMS: float64(hold.Microseconds()) / 1000}
	e.res.Burst = burst

	switch mode {
	case RaceWritev:
		if isTLS(e.conn) {
			// A writev on a TLS conn turns into one record per buffer, which
			// reintroduces the gap the attack is trying to remove.
			return sendCombined(e, payloads, "writev->single_write(tls)")
		}
		bufs := net.Buffers(payloads)
		at := time.Since(e.start)
		_ = e.conn.SetWriteDeadline(e.deadline())
		t0 := time.Now()
		if _, err := bufs.WriteTo(e.conn); err != nil {
			return err
		}
		burst.Writes = 1
		burst.Mode = string(RaceWritev)
		e.seq++
		e.res.addWrite(e.seq, join(payloads), at, time.Since(t0))
		return nil
	case RaceLastByte:
		prefixes := make([][]byte, len(payloads))
		finals := make([]byte, len(payloads))
		for i, p := range payloads {
			if len(p) == 0 {
				return fmt.Errorf("probe: empty request %d", i)
			}
			prefixes[i] = p[:len(p)-1]
			finals[i] = p[len(p)-1]
		}
		if err := e.write(join(prefixes)); err != nil {
			return err
		}
		timer := time.NewTimer(hold)
		select {
		case <-e.ctx.Done():
			timer.Stop()
			return e.ctx.Err()
		case <-timer.C:
		}
		if err := e.write(finals); err != nil {
			return err
		}
		burst.Writes = 2
		burst.Mode = string(RaceLastByte)
		return nil
	default:
		return sendCombined(e, payloads, string(RaceSingleWrite))
	}
}

func sendCombined(e *exec, payloads [][]byte, mode string) error {
	combined := join(payloads)
	if err := e.write(combined); err != nil {
		return err
	}
	e.res.Burst.Writes = 1
	e.res.Burst.Mode = mode
	return nil
}

func join(payloads [][]byte) []byte {
	n := 0
	for _, p := range payloads {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range payloads {
		out = append(out, p...)
	}
	return out
}

func isTLS(conn net.Conn) bool {
	_, ok := connectionState(conn)
	return ok
}

// enableNoDelay removes Nagle buffering on the TCP segment under a possible TLS
// wrapper, so the burst leaves in as few segments as the kernel allows.
func enableNoDelay(conn net.Conn) {
	for {
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.SetNoDelay(true)
			return
		}
		if tc, ok := conn.(interface{ NetConn() net.Conn }); ok {
			conn = tc.NetConn()
			continue
		}
		return
	}
}
