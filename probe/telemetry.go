package probe

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	mrand "math/rand/v2"
	"net"
	"sort"
	"time"
)

// JitterGate measures round-trip/TTFB jitter over a ConnSource. A proxy is
// rejected when IQR > threshold (default 25ms).
type JitterGate struct {
	Samples   int
	Threshold time.Duration
}

func (g JitterGate) threshold() time.Duration {
	if g.Threshold > 0 {
		return g.Threshold
	}
	return 25 * time.Millisecond
}

func (g JitterGate) samples() int {
	if g.Samples > 0 {
		return g.Samples
	}
	return 5
}

// Probe measures jitter by making small HTTP/1.1 requests through fresh
// connections from the same pinned session/source.
func (g JitterGate) Probe(ctx context.Context, target Target, source ConnSource) (time.Duration, bool, error) {
	n := g.samples()
	vals := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		if err := ctx.Err(); err != nil {
			return 0, false, err
		}
		d, err := measureTTFBOnce(ctx, target, source)
		if err != nil {
			return 0, false, err
		}
		vals = append(vals, d)
	}
	iqr := IQR(vals)
	return iqr, iqr <= g.threshold(), nil
}

func measureTTFBOnce(ctx context.Context, target Target, source ConnSource) (time.Duration, error) {
	conn, err := source.Dial(ctx)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	if err := setNoDelay(conn, true); err != nil {
		// best-effort
	}
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: omnislash-probe/1\r\nAccept: */*\r\nConnection: close\r\n\r\n", target.RequestPath(), target.HostHeader())
	deadline := time.Now().Add(5 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write([]byte(req)); err != nil {
		return 0, err
	}
	br := bufio.NewReaderSize(conn, 4096)
	start := time.Now()
	_, err = br.Peek(1)
	if err != nil {
		return 0, err
	}
	return time.Since(start), nil
}

// IQR returns interquartile range of durations.
func IQR(vals []time.Duration) time.Duration {
	if len(vals) < 2 {
		return 0
	}
	sorted := append([]time.Duration(nil), vals...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	q1 := quantileDuration(sorted, 0.25)
	q3 := quantileDuration(sorted, 0.75)
	if q3 < q1 {
		return 0
	}
	return q3 - q1
}

func quantileDuration(sorted []time.Duration, q float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	if len(sorted) == 1 {
		return sorted[0]
	}
	pos := q * float64(len(sorted)-1)
	lo := int(math.Floor(pos))
	hi := int(math.Ceil(pos))
	if lo == hi {
		return sorted[lo]
	}
	frac := pos - float64(lo)
	return time.Duration(float64(sorted[lo]) + frac*float64(sorted[hi]-sorted[lo]))
}

// KalmanFilter1D is a simple 1D Kalman filter for latency residuals/TTFB.
type KalmanFilter1D struct {
	Q float64 // process variance
	R float64 // measurement variance
	X float64 // state estimate
	P float64 // estimate covariance
	K float64 // gain
	initialized bool
}

func NewKalmanFilter1D(q, r float64) *KalmanFilter1D {
	if q <= 0 {
		q = 1
	}
	if r <= 0 {
		r = 25
	}
	return &KalmanFilter1D{Q: q, R: r, P: 1}
}

// Update feeds measurement z and returns filtered estimate and residual (z-xPred).
func (k *KalmanFilter1D) Update(z float64) (estimate float64, residual float64) {
	if k == nil {
		return z, 0
	}
	if !k.initialized {
		k.X = z
		k.initialized = true
		k.P = k.R
		return k.X, 0
	}
	// predict
	xPred := k.X
	pPred := k.P + k.Q
	// update
	k.K = pPred / (pPred + k.R)
	residual = z - xPred
	k.X = xPred + k.K*residual
	k.P = (1 - k.K) * pPred
	return k.X, residual
}

// CacheBuster returns a unique query parameter value.
func CacheBuster() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err == nil {
		return hex.EncodeToString(b[:])
	}
	return fmt.Sprintf("%x", mrand.Uint64())
}

// AppendCacheBuster adds ?_omni_cb=<rand> or &_omni_cb=<rand>.
func AppendCacheBuster(path string) string {
	cb := CacheBuster()
	if path == "" {
		path = "/"
	}
	sep := "?"
	if containsByte(path, '?') {
		sep = "&"
	}
	return path + sep + "_omni_cb=" + cb
}

func containsByte(s string, c byte) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return true
		}
	}
	return false
}

// PairOrder returns true when order should be [Clean, Mutated], false for [Mutated, Clean].
func PairOrder() bool {
	return mrand.IntN(2) == 0
}

func setNoDelay(conn net.Conn, on bool) error {
	type noDelayer interface{ SetNoDelay(bool) error }
	if nd, ok := conn.(noDelayer); ok {
		return nd.SetNoDelay(on)
	}
	return nil
}

// writeWithLastByteSync sends all but last byte, waits hold, then sends last byte.
// It returns total bytes written and timing of last-byte write.
func writeWithLastByteSync(conn net.Conn, payload []byte, hold time.Duration) (int, error) {
	if len(payload) == 0 {
		return 0, nil
	}
	if hold <= 0 || len(payload) == 1 {
		return conn.Write(payload)
	}
	n1, err := conn.Write(payload[:len(payload)-1])
	if err != nil {
		return n1, err
	}
	time.Sleep(hold)
	n2, err := conn.Write(payload[len(payload)-1:])
	return n1 + n2, err
}

// readTTFB writes request (with last-byte sync) and measures time to first response byte.
func readTTFB(ctx context.Context, conn net.Conn, req []byte, hold time.Duration, timeout time.Duration) (ttfb time.Duration, resp *Response, err error) {
	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	// last-byte sync: timer starts before releasing final byte
	if len(req) > 1 && hold > 0 {
		if _, err = conn.Write(req[:len(req)-1]); err != nil {
			return 0, nil, err
		}
		time.Sleep(hold)
		t0 := time.Now()
		if _, err = conn.Write(req[len(req)-1:]); err != nil {
			return 0, nil, err
		}
		br := bufio.NewReaderSize(conn, 16<<10)
		_, err = br.Peek(1)
		ttfb = time.Since(t0)
		if err != nil {
			return ttfb, nil, err
		}
		at := ttfb
		resp, err = readResponse(br, at, defaultMaxHeader, defaultMaxBody)
		return ttfb, resp, err
	}
	t0 := time.Now()
	if _, err = conn.Write(req); err != nil {
		return 0, nil, err
	}
	br := bufio.NewReaderSize(conn, 16<<10)
	_, err = br.Peek(1)
	ttfb = time.Since(t0)
	if err != nil {
		return ttfb, nil, err
	}
	resp, err = readResponse(br, ttfb, defaultMaxHeader, defaultMaxBody)
	return ttfb, resp, err
}
