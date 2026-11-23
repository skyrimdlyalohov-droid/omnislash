package daemon

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"time"
)

// ErrRateLimited is returned by a task when the target answered with 429 or a
// safety stop status. The scheduler treats it as a congestion signal.
var ErrRateLimited = errors.New("daemon: host rate limited")

// MatrixTask is one unit of work bound to a target host.
type MatrixTask struct {
	Host string
	Run  func(ctx context.Context) error
}

// MatrixResult is the outcome of one task, including the final AIMD window.
type MatrixResult struct {
	Host     string
	Err      error
	Window   int
	Cooldown bool
}

// MatrixConfig controls the N x M dispatcher.
type MatrixConfig struct {
	PerHostMinInterval time.Duration
	Jitter             time.Duration
	BaseWindow         int
	MaxWindow          int
	GlobalConcurrency  int
	Cooldown           time.Duration
}

func (c MatrixConfig) normalized() MatrixConfig {
	if c.PerHostMinInterval <= 0 {
		c.PerHostMinInterval = 3 * time.Second
	}
	if c.Jitter < 0 {
		c.Jitter = 0
	}
	if c.Jitter == 0 {
		c.Jitter = 250 * time.Millisecond
	}
	if c.BaseWindow <= 0 {
		c.BaseWindow = 1
	}
	if c.MaxWindow <= 0 {
		c.MaxWindow = 8
	}
	if c.MaxWindow < c.BaseWindow {
		c.MaxWindow = c.BaseWindow
	}
	if c.GlobalConcurrency <= 0 {
		c.GlobalConcurrency = 8
	}
	if c.Cooldown <= 0 {
		c.Cooldown = 5 * time.Second
	}
	return c
}

// MatrixScheduler runs tasks across many targets and proxies while enforcing a
// per-host start interval and an AIMD concurrency window per host. The sum of
// per-host windows yields the global fan-out; no single host sees the total RPS.
type MatrixScheduler struct {
	cfg MatrixConfig

	mu        sync.Mutex
	windows   map[string]int
	active    map[string]int
	nextStart map[string]time.Time
	cooldown  map[string]time.Time

	sem   chan struct{}
	now   func() time.Time
	sleep func(ctx context.Context, d time.Duration) error
}

// NewMatrixScheduler creates a dispatcher. Zero values select safe defaults:
// 3s per-host interval with 250ms Gaussian jitter, window 1..8, 8 global
// workers, 5s cooldown.
func NewMatrixScheduler(cfg MatrixConfig) *MatrixScheduler {
	cfg = cfg.normalized()
	return &MatrixScheduler{
		cfg:       cfg,
		windows:   make(map[string]int),
		active:    make(map[string]int),
		nextStart: make(map[string]time.Time),
		cooldown:  make(map[string]time.Time),
		sem:       make(chan struct{}, cfg.GlobalConcurrency),
		now:       time.Now,
		sleep:     sleepCtx,
	}
}

// Window returns the current AIMD window for host.
func (s *MatrixScheduler) Window(host string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.windowLocked(host)
}

func (s *MatrixScheduler) windowLocked(host string) int {
	w := s.windows[host]
	if w <= 0 {
		w = s.cfg.BaseWindow
		s.windows[host] = w
	}
	return w
}

// Run executes every task and returns results in the same order. Tasks for one
// host are serialized by the interval/window gates; different hosts run in
// parallel up to GlobalConcurrency.
func (s *MatrixScheduler) Run(ctx context.Context, tasks []MatrixTask) []MatrixResult {
	results := make([]MatrixResult, len(tasks))
	var wg sync.WaitGroup
	wg.Add(len(tasks))
	for i := range tasks {
		i := i
		t := tasks[i]
		go func() {
			defer wg.Done()
			res := MatrixResult{Host: t.Host}
			if t.Host == "" {
				res.Err = errors.New("daemon: matrix task has empty host")
				results[i] = res
				return
			}
			select {
			case s.sem <- struct{}{}:
				defer func() { <-s.sem }()
			case <-ctx.Done():
				res.Err = ctx.Err()
				results[i] = res
				return
			}
			if err := s.acquireHost(ctx, t.Host); err != nil {
				res.Err = err
				results[i] = res
				return
			}
			var err error
			if t.Run != nil {
				err = t.Run(ctx)
			}
			window, cooling := s.releaseHost(t.Host, err)
			res.Err = err
			res.Window = window
			res.Cooldown = cooling
			results[i] = res
		}()
	}
	wg.Wait()
	return results
}

func (s *MatrixScheduler) acquireHost(ctx context.Context, host string) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		now := s.now()
		s.mu.Lock()
		if until := s.cooldown[host]; now.Before(until) {
			wait := until.Sub(now)
			s.mu.Unlock()
			if err := s.sleep(ctx, wait); err != nil {
				return err
			}
			continue
		}
		w := s.windowLocked(host)
		active := s.active[host]
		next := s.nextStart[host]
		if active < w && !now.Before(next) {
			s.active[host] = active + 1
			s.nextStart[host] = now.Add(s.interval())
			s.mu.Unlock()
			return nil
		}
		wait := 1 * time.Millisecond
		if now.Before(next) {
			wait = next.Sub(now)
		}
		s.mu.Unlock()
		if err := s.sleep(ctx, wait); err != nil {
			return err
		}
	}
}

func (s *MatrixScheduler) releaseHost(host string, err error) (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active[host] > 0 {
		s.active[host]--
	}
	w := s.windowLocked(host)
	cooling := false
	if err != nil {
		// AIMD multiplicative decrease on congestion or anomaly.
		w = w / 2
		if w < 1 {
			w = 1
		}
		s.cooldown[host] = s.now().Add(s.cfg.Cooldown)
		cooling = true
	} else {
		w++
		if w > s.cfg.MaxWindow {
			w = s.cfg.MaxWindow
		}
	}
	s.windows[host] = w
	return w, cooling
}

func (s *MatrixScheduler) interval() time.Duration {
	d := s.cfg.PerHostMinInterval
	if s.cfg.Jitter > 0 {
		// Gaussian jitter with sigma = Jitter; clamp to a sane lower bound.
		d += time.Duration(rand.NormFloat64() * float64(s.cfg.Jitter))
		if d < time.Millisecond {
			d = time.Millisecond
		}
	}
	return d
}

// IsRateLimited reports whether err is a congestion signal.
func IsRateLimited(err error) bool {
	return errors.Is(err, ErrRateLimited)
}

// MatrixError wraps a status code as a scheduler congestion signal.
type MatrixError struct {
	Status int
	Err    error
}

func (e *MatrixError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("matrix: status %d: %v", e.Status, e.Err)
	}
	return fmt.Sprintf("matrix: status %d", e.Status)
}

func (e *MatrixError) Unwrap() error {
	if e.Status == 429 || e.Status == 403 || e.Status == 503 {
		return ErrRateLimited
	}
	return e.Err
}
