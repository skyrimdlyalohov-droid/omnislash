package probe

import (
	"math"
	"reflect"
	"testing"
	"time"
)

func TestWelfordStreamingMatchesBatchStatistics(t *testing.T) {
	var w Welford
	samples := []float64{10, 12, 11, 13, 14}
	for _, sample := range samples {
		w.Observe(sample)
	}
	if w.Count() != uint64(len(samples)) {
		t.Fatalf("count = %d, want %d", w.Count(), len(samples))
	}
	if math.Abs(w.Mean()-12) > 1e-9 {
		t.Fatalf("mean = %v, want 12", w.Mean())
	}
	// Population variance of 10,12,11,13,14 is 2.
	if math.Abs(w.Variance()-2) > 1e-9 {
		t.Fatalf("variance = %v, want 2", w.Variance())
	}
	if math.Abs(w.StdDev(1)-math.Sqrt(2)) > 1e-9 {
		t.Fatalf("stddev = %v, want sqrt(2)", w.StdDev(1))
	}
}

func TestWelfordSigmaFloorAndInvalidSamples(t *testing.T) {
	var w Welford
	w.Observe(5)
	w.Observe(5)
	w.Observe(5)
	if w.Variance() != 0 {
		t.Fatalf("variance of identical samples = %v, want 0", w.Variance())
	}
	if w.StdDev(DefaultMinSigmaMS) != DefaultMinSigmaMS {
		t.Fatalf("stddev floor = %v, want %v", w.StdDev(DefaultMinSigmaMS), DefaultMinSigmaMS)
	}
	if z := w.ZScore(5, DefaultMinSigmaMS); z != 0 {
		t.Fatalf("z-score with zero variance = %v, want 0 (no division by zero)", z)
	}
	if math.IsNaN(w.ZScore(math.NaN(), DefaultMinSigmaMS)) {
		t.Fatal("a NaN sample must not poison the accumulator")
	}

	w.Observe(math.NaN())
	w.Observe(math.Inf(1))
	w.Observe(-1)
	if w.Count() != 3 {
		t.Fatalf("invalid samples were accepted: count=%d", w.Count())
	}

	var empty Welford
	if empty.ZScore(100, DefaultMinSigmaMS) != 0 || empty.StdDev(0) != DefaultMinSigmaMS {
		t.Fatal("an empty accumulator must report no evidence and a safe sigma")
	}
}

func TestWelfordKeepsNoSampleArrays(t *testing.T) {
	// The sonar is called on every attempt of a long-lived session. Its state
	// must be three scalars: a slice/array/map field would grow memory.
	typ := reflect.TypeOf(Welford{})
	for i := 0; i < typ.NumField(); i++ {
		kind := typ.Field(i).Type.Kind()
		if kind == reflect.Slice || kind == reflect.Array || kind == reflect.Map {
			t.Fatalf("Welford field %s is a %s: sample history is not O(1)", typ.Field(i).Name, kind)
		}
	}
	var w Welford
	for i := 0; i < 200000; i++ {
		w.ObserveDuration(2 * time.Millisecond)
	}
	if w.Count() != 200000 || w.Mean() != 2 {
		t.Fatalf("streaming count/mean = %d/%v", w.Count(), w.Mean())
	}
}

func TestShannonEntropyBounds(t *testing.T) {
	if got := ShannonEntropy(nil); got != 0 {
		t.Fatalf("empty entropy = %v, want 0", got)
	}
	if got := ShannonEntropy([]byte("aaaaaaaa")); got != 0 {
		t.Fatalf("constant entropy = %v, want 0", got)
	}
	// Four equally likely bytes carry exactly two bits per byte.
	if got := ShannonEntropy([]byte("abcdabcdabcdabcd")); math.Abs(got-2) > 1e-9 {
		t.Fatalf("uniform entropy = %v, want 2", got)
	}
	if got := NormalizedEntropy([]byte("aaaa")); got != 0 {
		t.Fatalf("normalized constant entropy = %v, want 0", got)
	}
	if got := NormalizedEntropy([]byte("0123456789abcdef")); got <= 0 || got > 1 {
		t.Fatalf("normalized entropy out of range: %v", got)
	}
}

func TestSignalQualityUsesEntropyNCDAndZScore(t *testing.T) {
	baseline := []byte("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody")
	var sonar Welford
	sonar.Observe(10)
	sonar.Observe(11)
	signal := NewSignalQuality(baseline, []byte("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody"), 200, 200, 10, &sonar)
	if signal.NCD != 0 || signal.ZScore >= SignalZThreshold {
		t.Fatalf("identical baseline signal = %+v, want NCD 0 and a sub-threshold Z", signal)
	}
	if signal.Noise() {
		t.Fatal("a normal HTTP response must not be classified as noise")
	}

	noise := SignalQuality{NCD: 0.9, Entropy: 0.99, ZScore: 4, StatusShift: true}
	if !noise.Noise() || noise.Strong() {
		t.Fatalf("random noise must be rejected: %+v", noise)
	}
	strong := SignalQuality{NCD: 0.9, Entropy: 0.5, ZScore: 3, StatusShift: true}
	if !strong.Strong() {
		t.Fatalf("strong signal was rejected: %+v", strong)
	}
	weak := strong
	weak.ZScore = 1
	if weak.Strong() {
		t.Fatal("an ordinary-latency response must not promote a branch")
	}
	identical := strong
	identical.NCD = 0
	if identical.Strong() {
		t.Fatal("an unchanged response must not promote a branch")
	}
	padding := strong
	padding.Entropy = 0
	padding.BodyBytes = 512
	if !padding.Noise() || padding.Strong() {
		t.Fatalf("a constant padding stream must be filtered: %+v", padding)
	}
	// An empty answer is the canonical FE_Closed_BE_Waiting shape: zero entropy
	// must not be mistaken for a tarpit when there are no body bytes at all.
	empty := SignalQuality{NCD: 0.9, Entropy: 0, BodyBytes: 0, ZScore: 3, StatusShift: true}
	if empty.Noise() || !empty.Strong() {
		t.Fatalf("an empty desync answer must be promotable: %+v", empty)
	}
}
