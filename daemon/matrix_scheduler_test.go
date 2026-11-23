package daemon

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestMatrixSchedulerPerHostInterval(t *testing.T) {
	s := NewMatrixScheduler(MatrixConfig{
		PerHostMinInterval: 25 * time.Millisecond,
		Jitter:             time.Microsecond,
		BaseWindow:         4,
		MaxWindow:          4,
		GlobalConcurrency:  8,
		Cooldown:           5 * time.Millisecond,
	})
	var mu sync.Mutex
	var times []time.Time
	tasks := make([]MatrixTask, 4)
	for i := range tasks {
		tasks[i] = MatrixTask{Host: "a.example", Run: func(ctx context.Context) error {
			mu.Lock()
			times = append(times, time.Now())
			mu.Unlock()
			return nil
		}}
	}
	res := s.Run(context.Background(), tasks)
	for _, r := range res {
		if r.Err != nil {
			t.Fatalf("task err: %v", r.Err)
		}
	}
	if len(times) != 4 {
		t.Fatalf("runs=%d", len(times))
	}
	for i := 1; i < len(times); i++ {
		gap := times[i].Sub(times[i-1])
		if gap < 20*time.Millisecond {
			t.Fatalf("per-host gap %d = %v, want >= 20ms", i, gap)
		}
	}
}

func TestMatrixSchedulerAIMDDecreaseOnRateLimit(t *testing.T) {
	s := NewMatrixScheduler(MatrixConfig{
		PerHostMinInterval: time.Millisecond,
		BaseWindow:         4,
		MaxWindow:          8,
		GlobalConcurrency:  4,
		Cooldown:           10 * time.Millisecond,
		Jitter:             time.Microsecond,
	})
	if got := s.Window("a.example"); got != 4 {
		t.Fatalf("initial window=%d", got)
	}
	res := s.Run(context.Background(), []MatrixTask{{
		Host: "a.example",
		Run: func(ctx context.Context) error {
			return errors.Join(ErrRateLimited, &MatrixError{Status: 429})
		},
	}})
	if len(res) != 1 || res[0].Window != 2 {
		t.Fatalf("window after 429 = %+v, want 2", res)
	}
	if !res[0].Cooldown {
		t.Fatal("expected cooldown after 429")
	}
	// After cooldown, a clean run increases window additively.
	time.Sleep(15 * time.Millisecond)
	res = s.Run(context.Background(), []MatrixTask{{
		Host: "a.example",
		Run:  func(ctx context.Context) error { return nil },
	}})
	if res[0].Window != 3 {
		t.Fatalf("window after clean = %d, want 3", res[0].Window)
	}
}

func TestMatrixSchedulerParallelHosts(t *testing.T) {
	s := NewMatrixScheduler(MatrixConfig{
		PerHostMinInterval: time.Millisecond,
		BaseWindow:         2,
		MaxWindow:          2,
		GlobalConcurrency:  4,
		Cooldown:           time.Millisecond,
		Jitter:             time.Microsecond,
	})
	start := time.Now()
	tasks := []MatrixTask{
		{Host: "a", Run: func(ctx context.Context) error { time.Sleep(50 * time.Millisecond); return nil }},
		{Host: "b", Run: func(ctx context.Context) error { time.Sleep(50 * time.Millisecond); return nil }},
	}
	res := s.Run(context.Background(), tasks)
	for _, r := range res {
		if r.Err != nil {
			t.Fatal(r.Err)
		}
	}
	if elapsed := time.Since(start); elapsed > 110*time.Millisecond {
		t.Fatalf("hosts did not run in parallel: %v", elapsed)
	}
}

func TestMatrixErrorUnwrap(t *testing.T) {
	if !IsRateLimited(&MatrixError{Status: 429}) {
		t.Fatal("429 should be rate-limit signal")
	}
	if IsRateLimited(&MatrixError{Status: 500}) {
		t.Fatal("500 should not be rate-limit signal")
	}
}

func TestMatrixConfigDefaults(t *testing.T) {
	s := NewMatrixScheduler(MatrixConfig{})
	if s.cfg.PerHostMinInterval != 3*time.Second {
		t.Fatalf("per-host interval = %v, want 3s", s.cfg.PerHostMinInterval)
	}
	if s.cfg.Jitter != 250*time.Millisecond {
		t.Fatalf("jitter = %v, want 250ms", s.cfg.Jitter)
	}
	if s.cfg.BaseWindow != 1 || s.cfg.MaxWindow != 8 {
		t.Fatalf("window defaults = %d..%d, want 1..8", s.cfg.BaseWindow, s.cfg.MaxWindow)
	}
	if s.cfg.GlobalConcurrency != 8 {
		t.Fatalf("global concurrency = %d, want 8", s.cfg.GlobalConcurrency)
	}
}
