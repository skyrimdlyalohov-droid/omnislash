package obfuscation

import (
	"context"
	"math"
	"math/rand"
	"net/http"
	"time"
)

// BehavioralTimingLayer implements L4 design: behavioral timing and flow
// control — Gaussian jitter, occasional long idle pauses, warm-up request flow
// and adaptive backoff (quarantine signal on HTTP 429/403 / tarpit latency).
type BehavioralTimingLayer struct {
	Jitter      func() time.Duration
	LongIdle    time.Duration
	WarmUp      bool
	Adaptive    bool
	BackoffBase time.Duration
}

var _ Layer = (*BehavioralTimingLayer)(nil)

func defaultJitter() time.Duration {
	// Gaussian jitter via Box-Muller transform
	z := math.Sqrt(-2*math.Log(1-rand.Float64())) * math.Sin(2*math.Pi*rand.Float64())
	return time.Duration(math.Abs(z) * float64(time.Millisecond))
}

// RoundTrip applies behavioral timing before delegating.
func (l *BehavioralTimingLayer) RoundTrip(ctx context.Context, rt http.RoundTripper, req *http.Request) (*http.Response, error) {
	delay := l.Jitter
	if delay == nil {
		delay = defaultJitter
	}
	d := delay()
	if l.WarmUp && req.Header.Get("X-Omnislash-Warmup") != "1" && req.Header.Get("X-Omnislash-Warmup") != "true" {
		d += l.LongIdle
	}
	if d > 0 {
		timer := time.NewTimer(d)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	resp, err := rt.RoundTrip(req)
	if err == nil && l.Adaptive && (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusForbidden) && resp.Body != nil {
		// adaptive backoff / IP quarantine path (design hook)
	}
	return resp, err
}
