package probe

import (
	"container/list"
	"math"
	"sync"
	"time"
)

const (
	// DefaultSonarSlots bounds the number of live (host, proxy) Welford states.
	// A long-lived session can therefore accumulate at most this many slots,
	// each holding three scalars (count, mean, m2).
	DefaultSonarSlots = 256
	// SonarMinSamples is the number of baseline samples a pair must collect
	// before its Z-score is treated as evidence. Until then the tracker reports
	// Z=0 with uncalibrated=true.
	SonarMinSamples uint64 = 3
)

// SonarTracker keeps one O(1) Welford accumulator per (host, proxy) pair. A
// bounded LRU evicts cold pairs so memory stays constant even when the daemon
// walks hundreds of hosts through a rotating proxy pool.
//
// The key is deliberately host + "|" + proxy: mixing pairs in one accumulator
// is what produced the +675/-255 Z artifacts when the exit IP changed.
type SonarTracker struct {
	mu         sync.Mutex
	capacity   int
	minSamples uint64
	entries    map[string]*list.Element
	lru        *list.List // front is the most recently used slot
}

type sonarSlot struct {
	key     string
	welford Welford
}

// NewSonarTracker creates a bounded tracker. Non-positive capacity and zero
// minSamples fall back to the safe defaults.
func NewSonarTracker(capacity int, minSamples uint64) *SonarTracker {
	if capacity <= 0 {
		capacity = DefaultSonarSlots
	}
	if minSamples == 0 {
		minSamples = SonarMinSamples
	}
	return &SonarTracker{
		capacity:   capacity,
		minSamples: minSamples,
		entries:    make(map[string]*list.Element, capacity),
		lru:        list.New(),
	}
}

func sonarSlotKey(host, proxy string) string {
	return host + "|" + proxy
}

// slot returns the pair's accumulator, creating (and possibly evicting) one in
// O(1). The caller must hold t.mu.
func (t *SonarTracker) slot(host, proxy string) *sonarSlot {
	key := sonarSlotKey(host, proxy)
	if el, ok := t.entries[key]; ok {
		t.lru.MoveToFront(el)
		return el.Value.(*sonarSlot)
	}
	s := &sonarSlot{key: key}
	el := t.lru.PushFront(s)
	t.entries[key] = el
	if t.lru.Len() > t.capacity {
		if oldest := t.lru.Back(); oldest != nil {
			t.lru.Remove(oldest)
			delete(t.entries, oldest.Value.(*sonarSlot).key)
		}
	}
	return s
}

// Observe folds one latency sample into this pair's baseline only.
func (t *SonarTracker) Observe(host, proxy string, ms float64) {
	if t == nil || math.IsNaN(ms) || math.IsInf(ms, 0) || ms < 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.slot(host, proxy).welford.Observe(ms)
}

// ObserveDuration is the time.Duration form of Observe.
func (t *SonarTracker) ObserveDuration(host, proxy string, d time.Duration) {
	t.Observe(host, proxy, float64(d)/float64(time.Millisecond))
}

// ZScore compares ms against the baseline collected so far for this pair. It
// does not consume the sample. uncalibrated is true until at least minSamples
// baseline samples exist, in which case the returned Z is always zero: a first
// attempt through a new proxy must never inherit another pair's variance.
func (t *SonarTracker) ZScore(host, proxy string, ms float64, minSigmaMS float64) (float64, bool) {
	if t == nil || math.IsNaN(ms) || math.IsInf(ms, 0) || ms < 0 {
		return 0, true
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.slot(host, proxy)
	if s.welford.Count() < t.minSamples {
		return 0, true
	}
	return s.welford.ZScore(ms, minSigmaMS), false
}

// Evaluate scores ms against the existing baseline and folds it into the same
// pair's state under one lock. This is the normal streaming path: the score
// describes how surprising the attempt was before it became part of the
// baseline.
func (t *SonarTracker) Evaluate(host, proxy string, ms float64, minSigmaMS float64) (float64, bool) {
	if t == nil || math.IsNaN(ms) || math.IsInf(ms, 0) || ms < 0 {
		return 0, true
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.slot(host, proxy)
	uncalibrated := s.welford.Count() < t.minSamples
	z := 0.0
	if !uncalibrated {
		z = s.welford.ZScore(ms, minSigmaMS)
	}
	s.welford.Observe(ms)
	return z, uncalibrated
}

// Samples reports how many valid baseline samples the pair has collected.
func (t *SonarTracker) Samples(host, proxy string) uint64 {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if el, ok := t.entries[sonarSlotKey(host, proxy)]; ok {
		return el.Value.(*sonarSlot).welford.Count()
	}
	return 0
}

// Len reports the number of live slots. It is bounded by the configured
// capacity.
func (t *SonarTracker) Len() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.lru.Len()
}

// Contains reports whether a pair still has a live slot without creating or
// refreshing one. It exists for LRU tests and telemetry.
func (t *SonarTracker) Contains(host, proxy string) bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	_, ok := t.entries[sonarSlotKey(host, proxy)]
	return ok
}
