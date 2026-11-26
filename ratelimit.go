package omnislash

import (
	"context"
	"math"
	"sync"
	"time"
)

// tokenBucket is a small per-proxy rate limiter. It intentionally has no
// burst larger than the configured value and never allows more than one token
// per wait iteration.
type tokenBucket struct {
	mu     sync.Mutex
	rps    float64
	burst  float64
	tokens float64
	last   time.Time
}

func newTokenBucket(rps float64, burst int) *tokenBucket {
	if burst < 1 {
		burst = 1
	}
	return &tokenBucket{
		rps:    rps,
		burst:  float64(burst),
		tokens: float64(burst),
		last:   time.Now(),
	}
}

// tryWait spends one token only if it is immediately available. Optional
// acceleration (hedged dials, tunnel warming) uses this so a tight rate limit
// disables speculation instead of stealing capacity from real requests.
func (b *tokenBucket) tryWait() bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = math.Min(b.burst, b.tokens+elapsed*b.rps)
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (b *tokenBucket) wait(ctx context.Context) error {
	for {
		b.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(b.last).Seconds()
		if elapsed > 0 {
			b.tokens = math.Min(b.burst, b.tokens+elapsed*b.rps)
			b.last = now
		}
		if b.tokens >= 1 {
			b.tokens--
			b.mu.Unlock()
			return nil
		}
		wait := time.Duration((1 - b.tokens) / b.rps * float64(time.Second))
		if wait < time.Millisecond {
			wait = time.Millisecond
		}
		b.mu.Unlock()

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
