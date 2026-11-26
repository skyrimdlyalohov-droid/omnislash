package probe

import (
	"math"
	"strings"
	"testing"
)

func TestObserveSignedKeepsNegativeResiduals(t *testing.T) {
	var signed, latency Welford
	signed.ObserveSigned(-2.5)
	latency.Observe(-2.5)

	if signed.Count() != 1 {
		t.Fatalf("signed count = %d, want 1", signed.Count())
	}
	if math.Abs(signed.Mean()+2.5) > 1e-9 {
		t.Fatalf("signed mean = %v, want -2.5", signed.Mean())
	}
	if latency.Count() != 0 {
		t.Fatalf("latency count = %d, want 0", latency.Count())
	}
}

func TestTimingDesyncFindingUsesSignedResiduals(t *testing.T) {
	var clean, mutated Welford
	for i := 0; i < 6; i++ {
		clean.ObserveSigned(float64(i%3-1) * 0.1)
		mutated.ObserveSigned(-4 - float64(i)*0.1)
	}

	z, detail, ok := timingDesyncFinding(&clean, &mutated)
	if !ok {
		t.Fatal("timing finding was not produced")
	}
	if math.Abs(z) < SignalZThreshold {
		t.Fatalf("z = %.3f, want |z| >= %.1f", z, SignalZThreshold)
	}
	if !strings.Contains(detail, "z=") {
		t.Fatalf("detail = %q, want a z score", detail)
	}

	var empty Welford
	if _, _, ok := timingDesyncFinding(&empty, &mutated); ok {
		t.Fatal("an empty clean side must not produce timing evidence")
	}
}
