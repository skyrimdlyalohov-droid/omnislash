package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// H2RaceProbe implements last-frame synchronization over HTTP/2: all HEADERS
// frames are sent first, every stream is left open, and then all final DATA
// frames carrying END_STREAM are written in one burst. A target that evaluates
// a request on END_STREAM sees the whole batch in one scheduling window.
//
// The connection must already be an h2-negotiated TLS connection. The probe
// writes frames directly with x/net/http2 and never uses http.Client, so the
// requests cannot be split across connections or reordered by a transport.
type H2RaceProbe struct {
	Count   int
	Method  string
	Path    string
	Body    []byte
	Headers []hpack.HeaderField

	// Hold is the pause between headers and the final DATA burst.
	Hold    time.Duration
	Timeout time.Duration
	Idle    time.Duration

	// SingleUse declares that the action must succeed at most once. Without it
	// the probe reports statuses and bodies but makes no verdict.
	SingleUse    bool
	SuccessCodes []int
	MaxBody      int64
}

func (p *H2RaceProbe) Name() string { return "race/h2-last-frame" }

// Execute sends the synchronized batch and collects response statuses.
func (p *H2RaceProbe) Execute(ctx context.Context, target Target, conn net.Conn) (*Result, error) {
	tc, ok := conn.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("probe: h2 race requires a TLS connection")
	}
	if proto := tc.ConnectionState().NegotiatedProtocol; proto != "h2" {
		return nil, fmt.Errorf("probe: h2 race requires ALPN h2, got %q", proto)
	}
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
	e := newExec(ctx, p.Name(), target, conn, p.Timeout, defaultMaxHeader, p.MaxBody)
	e.res.Burst = &Burst{Requests: count, Mode: "h2-last-frame", HoldMS: float64(orDuration(p.Hold, 100*time.Millisecond).Microseconds()) / 1000}

	blockFragments := make([][]byte, 0, count)
	var hb bytes.Buffer
	henc := hpack.NewEncoder(&hb)
	for i := 0; i < count; i++ {
		hb.Reset()
		fields := []hpack.HeaderField{
			{Name: ":method", Value: method},
			{Name: ":scheme", Value: "https"},
			{Name: ":authority", Value: target.HostHeader()},
			{Name: ":path", Value: target.RequestPath()},
			{Name: "content-length", Value: strconv.Itoa(len(body))},
			{Name: "x-omnislash-race", Value: fmt.Sprintf("%s-%d", newNonce(), i)},
		}
		fields = append(fields, p.Headers...)
		for _, f := range fields {
			if err := henc.WriteField(f); err != nil {
				return e.finish(), fmt.Errorf("probe: encode headers: %w", err)
			}
		}
		block := make([]byte, hb.Len())
		copy(block, hb.Bytes())
		blockFragments = append(blockFragments, block)
	}

	// Preface + SETTINGS + all HEADERS (END_HEADERS, no END_STREAM) in one write.
	var out bytes.Buffer
	out.WriteString(http2.ClientPreface)
	writer := http2.NewFramer(&out, nil)
	if err := writer.WriteSettings(); err != nil {
		return e.finish(), fmt.Errorf("probe: settings: %w", err)
	}
	for i, block := range blockFragments {
		streamID := uint32(2*i + 1)
		if err := writer.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      streamID,
			BlockFragment: block,
			EndHeaders:    true,
			EndStream:     false,
		}); err != nil {
			return e.finish(), fmt.Errorf("probe: headers for stream %d: %w", streamID, err)
		}
	}
	if err := e.write(out.Bytes()); err != nil {
		return e.finish(), fmt.Errorf("probe: write headers: %w", err)
	}

	timer := time.NewTimer(orDuration(p.Hold, 100*time.Millisecond))
	select {
	case <-ctx.Done():
		timer.Stop()
		return e.finish(), ctx.Err()
	case <-timer.C:
	}

	// All final DATA frames with END_STREAM in one write.
	var finals bytes.Buffer
	dfw := http2.NewFramer(&finals, nil)
	for i := 0; i < count; i++ {
		streamID := uint32(2*i + 1)
		if err := dfw.WriteData(streamID, true, body); err != nil {
			return e.finish(), fmt.Errorf("probe: data for stream %d: %w", streamID, err)
		}
	}
	if err := e.write(finals.Bytes()); err != nil {
		return e.finish(), fmt.Errorf("probe: write final frames: %w", err)
	}
	e.res.Burst.Writes = 2
	e.res.Burst.Bytes = out.Len() + finals.Len()

	statuses, bodies, err := p.readFrames(e, tc, count, orDuration(p.Idle, time.Second))
	if err != nil && !isTimeout(err) {
		return e.finish(), err
	}
	success := 0
	for i, status := range statuses {
		resp := Response{Seq: len(e.res.Responses) + 1, Status: status, Framing: "h2", Version: "HTTP/2"}
		if i < len(bodies) {
			resp.Body = string(bodies[i])
		}
		e.res.Responses = append(e.res.Responses, resp)
		if successStatus(p.SuccessCodes, status) {
			success++
		}
	}
	if p.SingleUse && success > 1 {
		e.addFinding(Finding{
			Kind:       "race_success",
			Confidence: ConfidenceHigh,
			Detail:     fmt.Sprintf("%d of %d last-frame-synchronized requests succeeded", success, count),
		})
	}
	return e.finish(), nil
}

// readFrames collects response headers and DATA bodies until count responses
// arrive or the idle deadline expires. It also answers SETTINGS and PING so a
// real server does not consider the peer stalled.
func (p *H2RaceProbe) readFrames(e *exec, conn net.Conn, count int, idle time.Duration) ([]int, [][]byte, error) {
	fr := http2.NewFramer(conn, conn)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	var statuses []int
	var bodies [][]byte
	bodyByStream := make(map[uint32][]byte)
	seen := 0
	for seen < count {
		_ = conn.SetReadDeadline(time.Now().Add(idle))
		frame, err := fr.ReadFrame()
		if err != nil {
			return statuses, bodies, err
		}
		switch f := frame.(type) {
		case *http2.MetaHeadersFrame:
			if !f.StreamEnded() {
				continue
			}
			status := 0
			for _, field := range f.Fields {
				if field.Name == ":status" {
					status, _ = strconv.Atoi(field.Value)
				}
			}
			statuses = append(statuses, status)
			bodies = append(bodies, bodyByStream[f.StreamID])
			seen++
		case *http2.DataFrame:
			if data := f.Data(); len(data) > 0 {
				max := orInt64(p.MaxBody, defaultMaxBody)
				cur := bodyByStream[f.StreamID]
				if int64(len(cur)+len(data)) <= max {
					bodyByStream[f.StreamID] = append(cur, data...)
				}
			}
		case *http2.SettingsFrame:
			if !f.IsAck() {
				var ack bytes.Buffer
				if err := http2.NewFramer(&ack, nil).WriteSettingsAck(); err == nil {
					_ = e.write(ack.Bytes())
				}
			}
		case *http2.PingFrame:
			if !f.IsAck() {
				var ack bytes.Buffer
				if err := http2.NewFramer(&ack, nil).WritePing(true, f.Data); err == nil {
					_ = e.write(ack.Bytes())
				}
			}
		}
	}
	return statuses, bodies, nil
}
