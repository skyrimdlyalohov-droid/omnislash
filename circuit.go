package omnislash

import (
	"fmt"
	"sync"
	"time"
)

// CircuitState is a point-in-time view of the safety breaker.
type CircuitState struct {
	Enabled      bool       `json:"enabled"`
	Tripped      bool       `json:"tripped"`
	TrippedUntil *time.Time `json:"tripped_until,omitempty"`
	Reason       string     `json:"reason,omitempty"`
	Total        int64      `json:"total"`
	RecentBlocks int        `json:"recent_blocks"`
	Threshold    int        `json:"threshold"`
	Window       string     `json:"window"`
	Cooldown     string     `json:"cooldown"`
	MaxRequests  int64      `json:"max_requests,omitempty"`
}

// CircuitBreaker is a fail-closed global stop switch. It counts configured
// block statuses in a sliding window and refuses all traffic for Cooldown once
// Threshold is reached. It never rotates to another proxy while open.
type CircuitBreaker struct {
	cfg SafetyConfig
	now func() time.Time

	mu           sync.Mutex
	events       []time.Time
	total        int64
	trippedUntil time.Time
	reason       string
}

// NewCircuitBreaker creates a breaker. A nil now function uses time.Now.
func NewCircuitBreaker(cfg SafetyConfig, now func() time.Time) *CircuitBreaker {
	if cfg.Threshold < 1 {
		cfg.Threshold = 5
	}
	if len(cfg.StopStatuses) == 0 {
		cfg.StopStatuses = []int{403, 429, 503}
	}
	if cfg.Window <= 0 {
		cfg.Window = Duration(60 * time.Second)
	}
	if cfg.Cooldown <= 0 {
		cfg.Cooldown = Duration(10 * time.Minute)
	}
	if now == nil {
		now = time.Now
	}
	return &CircuitBreaker{cfg: cfg, now: now}
}

// Allow returns ErrCircuitOpen while the breaker is tripped or the request
// budget has been exhausted. A nil breaker is always open for business.
func (b *CircuitBreaker) Allow() error {
	if b == nil || !b.cfg.Enabled {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	if !b.trippedUntil.IsZero() && now.Before(b.trippedUntil) {
		return fmt.Errorf("%w: %s (until %s)", ErrCircuitOpen, b.reason, b.trippedUntil.Format(time.RFC3339))
	}
	if b.cfg.MaxRequests > 0 && b.total >= b.cfg.MaxRequests {
		b.tripLocked(now, fmt.Sprintf("request budget exhausted (%d)", b.cfg.MaxRequests))
		return fmt.Errorf("%w: %s", ErrCircuitOpen, b.reason)
	}
	return nil
}

// RecordStatus counts one response and trips the breaker when enough block
// statuses arrive inside the window.
func (b *CircuitBreaker) RecordStatus(status int) {
	if b == nil || !b.cfg.Enabled {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.total++
	if !containsStatus(b.cfg.StopStatuses, status) {
		return
	}
	now := b.now()
	cutoff := now.Add(-b.cfg.Window.Std())
	b.events = append(b.events, now)
	first := 0
	for first < len(b.events) && b.events[first].Before(cutoff) {
		first++
	}
	if first > 0 {
		b.events = append([]time.Time(nil), b.events[first:]...)
	}
	if len(b.events) >= b.cfg.Threshold {
		b.tripLocked(now, fmt.Sprintf("%d block statuses within %s (last HTTP %d)", len(b.events), b.cfg.Window.Std(), status))
	}
}

// Trip opens the breaker immediately. It is used for out-of-band stops such as
// a human operator or an external signal.
func (b *CircuitBreaker) Trip(reason string) {
	if b == nil || !b.cfg.Enabled {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tripLocked(b.now(), reason)
}

// Reset closes the breaker and clears the sliding window.
func (b *CircuitBreaker) Reset() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.trippedUntil = time.Time{}
	b.reason = ""
	b.events = nil
	b.total = 0
}

// State returns a snapshot for stats endpoints.
func (b *CircuitBreaker) State() CircuitState {
	if b == nil || !b.cfg.Enabled {
		return CircuitState{}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	s := CircuitState{
		Enabled:      true,
		Total:        b.total,
		RecentBlocks: len(b.events),
		Threshold:    b.cfg.Threshold,
		Window:       b.cfg.Window.Std().String(),
		Cooldown:     b.cfg.Cooldown.Std().String(),
		MaxRequests:  b.cfg.MaxRequests,
		Reason:       b.reason,
	}
	if !b.trippedUntil.IsZero() && now.Before(b.trippedUntil) {
		s.Tripped = true
		until := b.trippedUntil
		s.TrippedUntil = &until
	}
	return s
}

func (b *CircuitBreaker) tripLocked(now time.Time, reason string) {
	until := now.Add(b.cfg.Cooldown.Std())
	if until.After(b.trippedUntil) {
		b.trippedUntil = until
	}
	b.reason = reason
}

func containsStatus(statuses []int, want int) bool {
	for _, status := range statuses {
		if status == want {
			return true
		}
	}
	return false
}
