package omnislash

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCircuitBreakerTripsOnBlockStatuses(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	cfg := SafetyConfig{
		Enabled:      true,
		StopStatuses: []int{403, 429},
		Threshold:    2,
		Window:       Duration(time.Minute),
		Cooldown:     Duration(5 * time.Minute),
	}
	b := NewCircuitBreaker(cfg, func() time.Time { return now })

	if err := b.Allow(); err != nil {
		t.Fatalf("fresh breaker refused traffic: %v", err)
	}
	b.RecordStatus(200)
	if err := b.Allow(); err != nil {
		t.Fatalf("200 must not trip the breaker: %v", err)
	}
	b.RecordStatus(403)
	if err := b.Allow(); err != nil {
		t.Fatalf("one block below threshold must not trip: %v", err)
	}
	b.RecordStatus(429)
	if err := b.Allow(); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("breaker should be open, got %v", err)
	}

	now = now.Add(5*time.Minute + time.Second)
	if err := b.Allow(); err != nil {
		t.Fatalf("breaker should close after cooldown: %v", err)
	}
}

func TestCircuitBreakerWindowExpires(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	cfg := SafetyConfig{
		Enabled:      true,
		StopStatuses: []int{403},
		Threshold:    2,
		Window:       Duration(time.Minute),
		Cooldown:     Duration(5 * time.Minute),
	}
	b := NewCircuitBreaker(cfg, func() time.Time { return now })

	b.RecordStatus(403)
	now = now.Add(2 * time.Minute)
	b.RecordStatus(403)
	if err := b.Allow(); err != nil {
		t.Fatalf("old event should have left the window: %v", err)
	}
}

func TestCircuitBreakerMaxRequests(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	cfg := SafetyConfig{
		Enabled:      true,
		StopStatuses: []int{403},
		Threshold:    5,
		Window:       Duration(time.Minute),
		Cooldown:     Duration(time.Minute),
		MaxRequests:  2,
	}
	b := NewCircuitBreaker(cfg, func() time.Time { return now })

	b.RecordStatus(200)
	b.RecordStatus(200)
	if err := b.Allow(); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("request budget should open the breaker, got %v", err)
	}
}

func TestCircuitBreakerState(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	cfg := SafetyConfig{
		Enabled:      true,
		StopStatuses: []int{403},
		Threshold:    1,
		Window:       Duration(time.Minute),
		Cooldown:     Duration(5 * time.Minute),
	}
	b := NewCircuitBreaker(cfg, func() time.Time { return now })
	b.RecordStatus(403)
	state := b.State()
	if !state.Enabled || !state.Tripped {
		t.Fatalf("state should report a tripped breaker: %+v", state)
	}
	if state.Reason == "" || state.TrippedUntil == nil {
		t.Fatalf("state should include reason and deadline: %+v", state)
	}
}

func TestWaitGlobalHonoursContextMarker(t *testing.T) {
	p := &Pool{globalLimiter: newTokenBucket(100, 1)}
	ctx, err := p.WaitGlobal(context.Background())
	if err != nil {
		t.Fatalf("WaitGlobal: %v", err)
	}
	start := time.Now()
	if _, err := p.WaitGlobal(ctx); err != nil {
		t.Fatalf("nested WaitGlobal: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("nested WaitGlobal consumed a second rate slot: %v", elapsed)
	}
}
