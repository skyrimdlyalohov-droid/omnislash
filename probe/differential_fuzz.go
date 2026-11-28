package probe

import (
	"context"
	"fmt"
	"math"
	"net"
	"time"

	"github.com/skyrimdlyalohov-droid/omnislash"
)

// DifferentialFuzzProbe performs paired clean/mutated measurements with
// jitter gating, Kalman-filtered TTFB residuals, and early stop on neighbor shift.
type DifferentialFuzzProbe struct {
	Mutations    []string
	TechStack    []string
	Pairs        int
	JitterMaxIQR time.Duration
	Hold         time.Duration
	Timeout      time.Duration
	MaxHeader    int64
	MaxBody      int64
	// NeighborShiftNCD threshold for clean response structural shift.
	NeighborShiftNCD float64
}

func (p *DifferentialFuzzProbe) Name() string { return "differential-fuzz" }

func (p *DifferentialFuzzProbe) Execute(ctx context.Context, target Target, conn net.Conn) (*Result, error) {
	return nil, fmt.Errorf("%w: use ExecuteMulti", ErrMultiConn)
}

func (p *DifferentialFuzzProbe) pairs() int {
	if p.Pairs > 0 {
		return p.Pairs
	}
	return 5
}

func (p *DifferentialFuzzProbe) hold() time.Duration {
	if p.Hold > 0 {
		return p.Hold
	}
	return 50 * time.Millisecond
}

func (p *DifferentialFuzzProbe) neighborNCD() float64 {
	if p.NeighborShiftNCD > 0 {
		return p.NeighborShiftNCD
	}
	return 0.6
}

// ExecuteMulti runs jitter gate, then paired clean/mutated requests on fresh connections.
func (p *DifferentialFuzzProbe) ExecuteMulti(ctx context.Context, target Target, source ConnSource) (*Result, error) {
	if target.Addr == "" {
		return nil, fmt.Errorf("probe: target address is required")
	}
	// Seed result attribution from a probe connection.
	conn0, err := source.Dial(ctx)
	if err != nil {
		return nil, err
	}
	e := newExec(ctx, p.Name(), target, conn0, p.Timeout, p.MaxHeader, p.MaxBody)
	_ = conn0.Close() // fresh conn per hypothesis; this one was only for attribution

	// Jitter gate: 5 pings through same session/source.
	jg := JitterGate{Samples: 5, Threshold: p.JitterMaxIQR}
	iqr, ok, err := jg.Probe(ctx, target, source)
	if err != nil {
		e.addFinding(Finding{Kind: "jitter_gate_error", Confidence: ConfidenceLow, Detail: err.Error()})
		return e.finish(), nil
	}
	e.res.Findings = append(e.res.Findings, Finding{Kind: "jitter_iqr", Confidence: ConfidenceLow, Detail: fmt.Sprintf("iqr=%s threshold=%s", iqr, jg.threshold())})
	if !ok {
		e.addFinding(Finding{Kind: "jitter_gate_reject", Confidence: ConfidenceHigh, Detail: fmt.Sprintf("IQR %s > %s", iqr, jg.threshold())})
		return e.finish(), nil
	}

	mut := Mutator{TechStack: p.TechStack}
	mutations := p.Mutations
	if len(mutations) == 0 {
		for _, m := range mut.Mutations() {
			mutations = append(mutations, m.Name)
		}
	}

	kalman := NewKalmanFilter1D(1, 25)
	// Streaming O(1) telemetry: only a count/mean/M2 is kept per side, never an
	// array of residuals that grows with the number of pairs.
	var cleanSonar, mutSonar Welford
	var baselineCleanStatus int
	var baselineCleanBody []byte
	var baselineCleanContentType string
	pairs := p.pairs()
	hold := p.hold()
	timeout := orDuration(p.Timeout, defaultTimeout)

	for i := 0; i < pairs; i++ {
		if err := ctx.Err(); err != nil {
			return e.finish(), err
		}
		mutationName := mutations[i%len(mutations)]
		e.res.Mutation = mutationName
		mutReq, mutation, err := mut.Apply(mutationName, target)
		if err != nil {
			e.addFinding(Finding{Kind: "mutation_error", Confidence: ConfidenceLow, Detail: err.Error()})
			continue
		}
		cleanReq := buildCleanRequest(target)

		cleanFirst := PairOrder()
		type sample struct {
			kind string
			req  []byte
			mut  Mutation
		}
		order := []sample{{kind: "clean", req: cleanReq}, {kind: "mutated", req: mutReq, mut: mutation}}
		if !cleanFirst {
			order[0], order[1] = order[1], order[0]
		}

		var cleanResp, mutResp *Response
		var cleanTTFB, mutTTFB time.Duration
		var cleanErr, mutErr error
		for _, s := range order {
			conn, err := source.Dial(ctx)
			if err != nil {
				e.addFinding(Finding{Kind: "dial_error", Confidence: ConfidenceLow, Detail: err.Error()})
				continue
			}
			_ = setNoDelay(conn, true)
			ttfb, resp, rerr := readTTFB(ctx, conn, s.req, hold, timeout)
			_ = conn.Close() // anti-contamination: fresh conn per hypothesis
			if rerr != nil && resp == nil {
				e.addFinding(Finding{Kind: "read_error", Confidence: ConfidenceLow, Detail: fmt.Sprintf("%s: %v", s.kind, rerr)})
				continue
			}
			if resp != nil {
				resp.Seq = len(e.res.Responses) + 1
				e.res.Responses = append(e.res.Responses, *resp)
			}
			e.seq++
			e.res.addWrite(e.seq, s.req, time.Since(e.start), 0)
			if s.kind == "clean" {
				cleanResp, cleanTTFB, cleanErr = resp, ttfb, rerr
			} else {
				mutResp, mutTTFB, mutErr = resp, ttfb, rerr
			}
		}

		// Neighbor shift / early stop: if clean response shifts from baseline.
		if cleanResp != nil {
			if i == 0 {
				baselineCleanStatus = cleanResp.Status
				baselineCleanBody = []byte(cleanResp.Body)
				baselineCleanContentType = responseContentType(cleanResp)
			} else {
				shifted := cleanResp.Status != baselineCleanStatus
				if !shifted && len(baselineCleanBody) > 0 {
					// Structural tokens filter rotating CSRF/timestamp/ad values;
					// plain text and non-HTTP bodies still use the raw NCD path.
					if distance, ok := responseStructuralShift(baselineCleanBody, baselineCleanContentType, cleanResp); ok {
						shifted = distance > p.neighborNCD()
					} else {
						shifted = omnislash.NormalizedCompressionDistance(baselineCleanBody, []byte(cleanResp.Body)) > p.neighborNCD()
					}
				}
				if shifted {
					e.addFinding(Finding{Kind: "neighbor_shift", Confidence: ConfidenceHigh, Detail: fmt.Sprintf("clean response shifted at pair %d: status %d->%d", i+1, baselineCleanStatus, cleanResp.Status), Response: cleanResp.Seq})
					return e.finish(), nil
				}
			}
			_, resid := kalman.Update(float64(cleanTTFB.Microseconds()) / 1000.0)
			cleanSonar.ObserveSigned(resid)
		}
		if mutResp != nil {
			_, resid := kalman.Update(float64(mutTTFB.Microseconds()) / 1000.0)
			mutSonar.ObserveSigned(resid)
			// Simple differential signal: status change or large TTFB residual gap.
			if cleanResp != nil && cleanResp.Status != mutResp.Status {
				e.addFinding(Finding{Kind: "differential_status", Confidence: ConfidenceMedium, Detail: fmt.Sprintf("mutation=%s clean=%d mutated=%d", mutationName, cleanResp.Status, mutResp.Status), Response: mutResp.Seq})
			}
		}
		_ = cleanErr
		_ = mutErr
		_ = mutation
	}

	if z, detail, ok := timingDesyncFinding(&cleanSonar, &mutSonar); ok {
		e.addFinding(Finding{Kind: "differential_ttfb", Confidence: ConfidenceLow, Detail: detail})
		// A jitter-gated residual gap is a timing-only desync signal. It is
		// recorded separately so the byte-level parser FSM can still win with a
		// stronger verdict, but it is never silently discarded.
		if math.Abs(z) >= SignalZThreshold {
			e.addFinding(Finding{Kind: string(ParserTimingDesync), Confidence: ConfidenceMedium, Detail: detail})
			e.res.TimingDivergence = string(ParserTimingDesync)
		}
	}
	if len(e.res.Findings) == 0 {
		e.addFinding(Finding{Kind: "differential_no_signal", Confidence: ConfidenceLow, Detail: "no status/neighbor shift detected"})
	}
	return e.finish(), nil
}

// timingDesyncFinding compares the clean and mutated Kalman residual streams.
// A pair without valid samples on either side carries no timing evidence.
func timingDesyncFinding(clean, mutated *Welford) (z float64, detail string, ok bool) {
	if clean == nil || mutated == nil || clean.Count() == 0 || mutated.Count() == 0 {
		return 0, "", false
	}
	z = (mutated.Mean() - clean.Mean()) / mutated.StdDev(DefaultMinSigmaMS)
	detail = fmt.Sprintf("clean_residual_ms=%.3f mutated_residual_ms=%.3f z=%.3f", clean.Mean(), mutated.Mean(), z)
	return z, detail, true
}

func responseContentType(resp *Response) string {
	if resp == nil {
		return ""
	}
	if values := resp.headerValues("Content-Type"); len(values) > 0 {
		return values[0]
	}
	return ""
}

// responseStructuralShift reports a structural distance only when both bodies
// have value-free tokens (HTML tags or JSON keys). A text/plain response has no
// skeleton, so callers must fall back to raw NCD instead of inventing one.
func responseStructuralShift(base []byte, baseContentType string, sample *Response) (float64, bool) {
	if sample == nil {
		return 0, false
	}
	baseProfile := omnislash.AnalyzeStructure(base, baseContentType)
	if !baseProfile.HasTokens() {
		return 0, false
	}
	sampleProfile := omnislash.AnalyzeStructure([]byte(sample.Body), responseContentType(sample))
	if !sampleProfile.HasTokens() {
		return 0, false
	}
	return omnislash.StructuralDistance(baseProfile, sampleProfile), true
}

func buildCleanRequest(target Target) []byte {
	p := AppendCacheBuster(target.RequestPath())
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: omnislash-probe/1\r\nAccept: */*\r\nConnection: close\r\n\r\n", p, target.HostHeader())
	return []byte(req)
}

// Ensure interfaces.
var _ Probe = (*DifferentialFuzzProbe)(nil)
var _ MultiConnProbe = (*DifferentialFuzzProbe)(nil)
