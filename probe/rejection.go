package probe

import "strconv"

// FindingTargetRejected is the shared verdict for a target that refuses the
// syntax under test. A clean 200/301 followed by a 400/501 is a parser
// rejection: it is neither a desync nor an unkeyed-header gadget, and the
// remaining pool must not be spent on that signature.
const FindingTargetRejected = "target_rejected"

// parserRejected reports a syntax refusal between a trusted baseline and a
// mutated sample. Only the documented 200/301 -> 400/501 transition qualifies;
// other status changes stay available to the ordinary differential heuristics.
func parserRejected(baseline, sample int) bool {
	if baseline != 200 && baseline != 301 {
		return false
	}
	return sample == 400 || sample == 501
}

// rejectionDetail renders the evidence without naming an unconfirmed gadget.
func rejectionDetail(kind string, baseline, sample int) string {
	return kind + ": baseline " + strconv.Itoa(baseline) + " -> " + strconv.Itoa(sample)
}
