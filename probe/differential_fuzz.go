package probe

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/skyrimdlyalohov-droid/omnislash"
)

// DifferentialFuzzProbe performs paired clean/mutated measurements with
// jitter gating, Kalman-filtered TTFB residuals, and early stop on neighbor shift.
type DifferentialFuzzProbe struct {
	Mutations      []string
	TechStack      []string
	Pairs          int
	JitterMaxIQR   time.Duration
	Hold           time.Duration
	Timeout        time.Duration
	MaxHeader      int64
	MaxBody        int64
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
	var cleanTTFBs, mutTTFBs []float64
	var baselineCleanStatus int
	var baselineCleanBody []byte
	pairs := p.pairs()
	hold := p.hold()
	timeout := orDuration(p.Timeout, defaultTimeout)

	for i := 0; i < pairs; i++ {
		if err := ctx.Err(); err != nil {
			return e.finish(), err
		}
		mutationName := mutations[i%len(mutations)]
		mutReq, mutation, err := mut.Apply(mutationName, target)
		if err != nil {
			e.addFinding(Finding{Kind: "mutation_error", Confidence: ConfidenceLow, Detail: err.Error()})
			continue
		}
		cleanReq := buildCleanRequest(target)

		cleanFirst := PairOrder()
		type sample struct {
			kind    string
			req     []byte
			mut     Mutation
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
			} else {
				shifted := cleanResp.Status != baselineCleanStatus
				if !shifted && len(baselineCleanBody) > 0 {
					shifted = omnislash.NormalizedCompressionDistance(baselineCleanBody, []byte(cleanResp.Body)) > p.neighborNCD()
				}
				if shifted {
					e.addFinding(Finding{Kind: "neighbor_shift", Confidence: ConfidenceHigh, Detail: fmt.Sprintf("clean response shifted at pair %d: status %d->%d", i+1, baselineCleanStatus, cleanResp.Status), Response: cleanResp.Seq})
					return e.finish(), nil
				}
			}
			est, resid := kalman.Update(float64(cleanTTFB.Microseconds()) / 1000.0)
			_ = est
			cleanTTFBs = append(cleanTTFBs, resid)
		}
		if mutResp != nil {
			est, resid := kalman.Update(float64(mutTTFB.Microseconds()) / 1000.0)
			_ = est
			mutTTFBs = append(mutTTFBs, resid)
			// Simple differential signal: status change or large TTFB residual gap.
			if cleanResp != nil && cleanResp.Status != mutResp.Status {
				e.addFinding(Finding{Kind: "differential_status", Confidence: ConfidenceMedium, Detail: fmt.Sprintf("mutation=%s clean=%d mutated=%d", mutationName, cleanResp.Status, mutResp.Status), Response: mutResp.Seq})
			}
		}
		_ = cleanErr
		_ = mutErr
		_ = mutation
	}

	if len(cleanTTFBs) > 0 && len(mutTTFBs) > 0 {
		e.addFinding(Finding{Kind: "differential_ttfb", Confidence: ConfidenceLow, Detail: fmt.Sprintf("clean_residual_ms=%v mutated_residual_ms=%v", mean(cleanTTFBs), mean(mutTTFBs))})
	}
	if len(e.res.Findings) == 0 {
		e.addFinding(Finding{Kind: "differential_no_signal", Confidence: ConfidenceLow, Detail: "no status/neighbor shift detected"})
	}
	return e.finish(), nil
}

func buildCleanRequest(target Target) []byte {
	p := AppendCacheBuster(target.RequestPath())
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: omnislash-probe/1\r\nAccept: */*\r\nConnection: close\r\n\r\n", p, target.HostHeader())
	return []byte(req)
}

func mean(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	var s float64
	for _, x := range v {
		s += x
	}
	return s / float64(len(v))
}

// Ensure interfaces.
var _ Probe = (*DifferentialFuzzProbe)(nil)
var _ MultiConnProbe = (*DifferentialFuzzProbe)(nil)
