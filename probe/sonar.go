package probe

import (
	"math"
	"time"

	"github.com/skyrimdlyalohov-droid/omnislash"
)

// DefaultMinSigmaMS is the floor applied to the Welford standard deviation.
// A zero variance must never turn into a division by zero: one millisecond is
// the clock-resolution floor for TTFB comparisons.
const DefaultMinSigmaMS = 1.0

// Welford is an O(1)-memory online mean/variance accumulator. It keeps only a
// count, a running mean and a sum of squared deviations: no slice of samples is
// retained, so a long-lived session cannot grow its telemetry footprint.
//
// All samples are milliseconds. Non-finite and negative timings are ignored:
// they are local measurement faults, not evidence about a target.
type Welford struct {
	n    uint64
	mean float64
	m2   float64
}

// Observe folds one TTFB sample into the accumulator.
func (w *Welford) Observe(ms float64) {
	if w == nil || math.IsNaN(ms) || math.IsInf(ms, 0) || ms < 0 {
		return
	}
	w.n++
	delta := ms - w.mean
	w.mean += delta / float64(w.n)
	w.m2 += delta * (ms - w.mean)
}

// ObserveDuration is the time.Duration form of Observe.
func (w *Welford) ObserveDuration(d time.Duration) {
	if w == nil {
		return
	}
	w.Observe(float64(d) / float64(time.Millisecond))
}

// Count reports how many finite samples were accepted.
func (w *Welford) Count() uint64 {
	if w == nil {
		return 0
	}
	return w.n
}

// Mean returns the running mean, or zero before the first sample.
func (w *Welford) Mean() float64 {
	if w == nil || w.n == 0 {
		return 0
	}
	return w.mean
}

// Variance returns the population variance. The first sample has no variance
// and therefore reports zero instead of dividing by n-1 == 0.
func (w *Welford) Variance() float64 {
	if w == nil || w.n < 2 {
		return 0
	}
	return w.m2 / float64(w.n)
}

// StdDev returns the standard deviation with a non-zero floor. A caller may
// pass its own floor; values <= 0 fall back to DefaultMinSigmaMS.
func (w *Welford) StdDev(minSigmaMS float64) float64 {
	if minSigmaMS <= 0 || math.IsNaN(minSigmaMS) {
		minSigmaMS = DefaultMinSigmaMS
	}
	sigma := math.Sqrt(w.Variance())
	if sigma < minSigmaMS {
		return minSigmaMS
	}
	return sigma
}

// ZScore measures how unusual a sample is relative to the accumulated
// baseline. With no baseline it returns zero: no evidence means no transition.
func (w *Welford) ZScore(ms float64, minSigmaMS float64) float64 {
	if w == nil || w.n == 0 || math.IsNaN(ms) || math.IsInf(ms, 0) {
		return 0
	}
	return (ms - w.Mean()) / w.StdDev(minSigmaMS)
}

// ShannonEntropy returns the entropy of the byte distribution in bits per
// byte. The 256-slot histogram lives on the stack, so this is O(1) memory even
// for a multi-megabyte response. Empty input has zero entropy.
func ShannonEntropy(raw []byte) float64 {
	if len(raw) == 0 {
		return 0
	}
	var counts [256]float64
	for _, b := range raw {
		counts[b]++
	}
	total := float64(len(raw))
	entropy := 0.0
	for _, count := range counts {
		if count == 0 {
			continue
		}
		p := count / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// NormalizedEntropy scales ShannonEntropy into [0,1] by the 8 bits/byte bound.
func NormalizedEntropy(raw []byte) float64 {
	return ShannonEntropy(raw) / 8
}

// SignalQuality is the compact evidence packet shared by the sonar, the NCD
// comparator and the orchestrator FSM. It carries scalars only: no response
// body or sample array is retained.
type SignalQuality struct {
	Status      int
	Host        string // pair key component for the per-pair sonar
	Proxy       string // pair key component for the per-pair sonar
	LatencyMS   float64
	NCD         float64
	Entropy     float64 // normalized Shannon entropy in [0,1]
	BodyBytes   int     // length of the response body; empty is a valid FE shape
	ZScore      float64 // Welford Z-score of this attempt's TTFB
	StatusShift bool    // status differs from the calibrated baseline
	// Uncalibrated is true while the (host, proxy) pair has fewer than
	// SonarMinSamples baseline observations. ZScore is then always zero.
	Uncalibrated bool
}

const (
	// SignalZThreshold is the posterior-style latency threshold for a state
	// shift. Two sigma keeps ordinary jitter from promoting a branch.
	SignalZThreshold = 2.0
	// SignalNCDThreshold is the minimum structural divergence from the
	// calibrated baseline. Identical answers score 0 and cannot promote a
	// branch; a frontend closed while the backend waits scores near 1.
	SignalNCDThreshold = 0.5
	// signalMinEntropy and signalMaxEntropy bound plausible HTTP responses:
	// near-zero with a substantial body is a tarpit/padding stream, near-one is
	// random noise. An empty answer has zero entropy but is a valid FE shape.
	signalMinEntropy   = 0.02
	signalMaxEntropy   = 0.92
	signalPaddingBytes = 32
)

// NewSignalQuality combines the NCD comparator from deception.go with the
// Shannon entropy filter and the Welford Z-score in one O(1) scalar packet.
// The response bytes are consumed and never stored. A nil sonar yields Z=0.
func NewSignalQuality(baseline, raw []byte, status, baselineStatus int, latencyMS float64, sonar *Welford) SignalQuality {
	ncd := 0.5
	if len(baseline) > 0 && len(raw) > 0 {
		ncd = omnislash.NormalizedCompressionDistance(baseline, raw)
	}
	zscore := 0.0
	if sonar != nil {
		zscore = sonar.ZScore(latencyMS, DefaultMinSigmaMS)
		sonar.Observe(latencyMS)
	}
	return SignalQuality{
		Status:      status,
		LatencyMS:   latencyMS,
		NCD:         ncd,
		Entropy:     NormalizedEntropy(raw),
		BodyBytes:   len(raw),
		ZScore:      zscore,
		StatusShift: baselineStatus > 0 && status != baselineStatus,
	}
}

// Noise reports whether the response looks like a tarpit or a random-noise
// generator. Such a branch is folded before it can reach the victim stage.
func (s SignalQuality) Noise() bool {
	if math.IsNaN(s.Entropy) || s.Entropy < 0 || s.Entropy > 1 || s.NCD < 0 || s.NCD > 1 {
		return true
	}
	if s.Entropy >= signalMaxEntropy {
		return true
	}
	// A long, near-constant body is padding or a tarpit. A short or empty body
	// is not: EOF with TE on the wire is exactly the FE_Closed_BE_Waiting shape
	// the parser FSM reports.
	return s.Entropy <= signalMinEntropy && s.BodyBytes > signalPaddingBytes
}

// Strong reports whether the branch earned a transition. Every channel must
// agree: a WAF block, a random body, an unchanged response or an ordinary
// latency cannot be promoted by a single lucky marker.
func (s SignalQuality) Strong() bool {
	return !s.Noise() &&
		s.ZScore >= SignalZThreshold &&
		s.NCD >= SignalNCDThreshold &&
		s.StatusShift
}
