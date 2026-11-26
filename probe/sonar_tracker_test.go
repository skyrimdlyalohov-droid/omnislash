package probe

import (
	"math"
	"sync"
	"testing"
	"time"
)

func TestSonarTrackerIsolatesPairsAndRequiresWarmup(t *testing.T) {
	tr := NewSonarTracker(4, SonarMinSamples)

	// The first three attempts through a fresh pair are baseline only. A
	// slow/fast first exit must never produce a significant Z-score.
	for i := 0; i < int(SonarMinSamples); i++ {
		z, uncalibrated := tr.Evaluate("hostA", "proxy1", 10, DefaultMinSigmaMS)
		if z != 0 || !uncalibrated {
			t.Fatalf("sample %d: z=%v uncalibrated=%v, want 0/true", i+1, z, uncalibrated)
		}
	}
	if got := tr.Samples("hostA", "proxy1"); got != SonarMinSamples {
		t.Fatalf("baseline samples = %d, want %d", got, SonarMinSamples)
	}
	if z, uncalibrated := tr.Evaluate("hostA", "proxy1", 10.5, DefaultMinSigmaMS); uncalibrated || math.Abs(z) > 100 {
		t.Fatalf("calibrated z=%v uncalibrated=%v, want a modest calibrated score", z, uncalibrated)
	}

	// Switching both host and proxy yields a fresh accumulator. The 5000 ms
	// sample would be Z=+4990 if it were compared against hostA/proxy1's
	// tightly clustered baseline; here it must be invisible.
	if z, uncalibrated := tr.Evaluate("hostB", "proxy2", 5000, DefaultMinSigmaMS); z != 0 || !uncalibrated {
		t.Fatalf("new pair inherited a baseline: z=%v uncalibrated=%v", z, uncalibrated)
	}
	// The proxy is part of the key too: the same host through a new exit is
	// just as uncalibrated.
	if z, uncalibrated := tr.Evaluate("hostA", "proxy2", 5000, DefaultMinSigmaMS); z != 0 || !uncalibrated {
		t.Fatalf("proxy change inherited a baseline: z=%v uncalibrated=%v", z, uncalibrated)
	}
}

func TestSonarTrackerZScoreDoesNotConsumeSample(t *testing.T) {
	tr := NewSonarTracker(4, SonarMinSamples)
	for i := 0; i < 2; i++ {
		tr.Observe("host", "proxy", 10)
	}
	if z, uncalibrated := tr.ZScore("host", "proxy", 5000, DefaultMinSigmaMS); z != 0 || !uncalibrated {
		t.Fatalf("two samples still uncalibrated: z=%v uncalibrated=%v", z, uncalibrated)
	}
	if got := tr.Samples("host", "proxy"); got != 2 {
		t.Fatalf("ZScore mutated the baseline: samples=%d", got)
	}
	tr.Observe("host", "proxy", 10)
	if z, uncalibrated := tr.ZScore("host", "proxy", 11, DefaultMinSigmaMS); uncalibrated || z <= 0 || z > 100 {
		t.Fatalf("calibrated z=%v uncalibrated=%v", z, uncalibrated)
	}
	if got := tr.Samples("host", "proxy"); got != 3 {
		t.Fatalf("ZScore mutated the baseline: samples=%d", got)
	}
}

func TestSonarTrackerBoundsSlotsWithLRU(t *testing.T) {
	tr := NewSonarTracker(2, 1)
	tr.Observe("a", "p1", 1)
	tr.Observe("b", "p1", 1)
	tr.ObserveDuration("a", "p1", time.Millisecond) // refresh a

	tr.Observe("c", "p1", 1) // b is the least recently used slot
	if tr.Len() != 2 || tr.Contains("b", "p1") || !tr.Contains("a", "p1") || !tr.Contains("c", "p1") {
		t.Fatalf("LRU eviction failed: len=%d a=%v b=%v c=%v", tr.Len(),
			tr.Contains("a", "p1"), tr.Contains("b", "p1"), tr.Contains("c", "p1"))
	}
	if got := sonarSlotKey("host", "proxy"); got != "host|proxy" {
		t.Fatalf("pair key = %q, want host|proxy", got)
	}
}

func TestSonarTrackerConcurrentPairs(t *testing.T) {
	tr := NewSonarTracker(DefaultSonarSlots, SonarMinSamples)
	var wg sync.WaitGroup
	for host := 0; host < 8; host++ {
		wg.Add(1)
		go func(host int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				proxy := "proxy" + string(rune('0'+i%4))
				name := "host" + string(rune('0'+host))
				tr.Evaluate(name, proxy, 10+float64(i%3), DefaultMinSigmaMS)
			}
		}(host)
	}
	wg.Wait()
	if tr.Len() > DefaultSonarSlots {
		t.Fatalf("tracker grew to %d slots, cap is %d", tr.Len(), DefaultSonarSlots)
	}
}
