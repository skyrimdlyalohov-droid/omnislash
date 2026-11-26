package probe

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strconv"

	"github.com/skyrimdlyalohov-droid/omnislash/util"
)

// ParserState is the FSM verdict for one request/response exchange. The string
// values are stable audit labels, not Go identifiers.
type ParserState string

const (
	ParserSyncOK            ParserState = "SyncOK"
	ParserFEClosedBEWaiting ParserState = "FE_Closed_BE_Waiting"
	ParserWAFBlocked        ParserState = "WAF_Blocked"
	ParserEngineFault       ParserState = "Engine_Fault"
	// ParserTimingDesync is a timing-only verdict from differential pairs. It
	// is deliberately weaker than a byte-level parser desync and never promotes
	// a branch to CONFIRMED on its own.
	ParserTimingDesync ParserState = "Timing_Desync"

	// Short aliases used by callers and by the finding that escalates a
	// confirmed desync.
	SyncOK            = ParserSyncOK
	FEClosedBEWaiting = ParserFEClosedBEWaiting
	WAFBlocked        = ParserWAFBlocked
	EngineFault       = ParserEngineFault
	TimingDesync      = ParserTimingDesync
)

const maxParserScanBytes = 4 << 20

// ParserStateMachine classifies raw response bytes without net/http. It is a
// stateful FSM because the request side matters: an empty answer is only a
// desync signal when the request used Transfer-Encoding.
type ParserStateMachine struct {
	RequestHadTE bool

	// PanicOnAnalyze is an explicit fault-injection hook for chaos tests. The
	// panic is still caught by safeAnalyze and becomes an Engine Fault.
	PanicOnAnalyze bool
}

// AnalyzeDivergence returns one of SyncOK, FE_Closed_BE_Waiting, WAF_Blocked
// or Engine_Fault. Timing_Desync is not produced here: it needs paired TTFB
// evidence and is supplied by the differential-fuzz probe instead. The method
// never dials, never parses with net/http and never reads beyond the bytes it
// was given.
func (m *ParserStateMachine) AnalyzeDivergence(rawResponse []byte, err error) ParserState {
	if m == nil {
		return ParserEngineFault
	}
	if m.PanicOnAnalyze {
		panic("probe: injected parser fault")
	}

	scanned := rawResponse
	if len(scanned) > maxParserScanBytes {
		scanned = scanned[:maxParserScanBytes]
	}

	// A local correctness failure outranks any target-looking bytes.
	if errors.Is(err, util.ErrPrecisionLost) {
		return ParserEngineFault
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return ParserEngineFault
	}
	if errors.Is(err, ErrResponseTooLarge) {
		return ParserEngineFault
	}

	lower := bytes.ToLower(scanned)
	status := responseStatus(scanned)

	// 403/429 with a WAF signature is a block, not a parser divergence. A bare
	// 429 is a rate-limit block by itself.
	if status == 403 || status == 429 {
		if status == 429 || wafSignature(lower) {
			return ParserWAFBlocked
		}
	}

	// A front-end that rejects the chunk framing while the back-end is still
	// waiting for the smuggled body is the classic FE closed / BE open state.
	if bytes.Contains(lower, []byte("invalid chunk")) ||
		bytes.Contains(lower, []byte("invalid chunked")) ||
		bytes.Contains(lower, []byte("bad chunk")) ||
		bytes.Contains(lower, []byte("chunked encoding")) {
		return ParserFEClosedBEWaiting
	}
	if bytes.Contains(lower, []byte("bad request")) &&
		(m.RequestHadTE || status == 400 || bytes.Contains(lower, []byte("nginx"))) {
		return ParserFEClosedBEWaiting
	}

	// Empty answer: only meaningful as a desync when TE was on the wire. EOF
	// is the normal way a front-end closes in this state.
	if len(bytes.TrimSpace(scanned)) == 0 {
		if m.RequestHadTE && (err == nil || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)) {
			return ParserFEClosedBEWaiting
		}
		return ParserEngineFault
	}

	if err != nil {
		return ParserEngineFault
	}
	return ParserSyncOK
}

func responseStatus(raw []byte) int {
	line := raw
	if at := bytes.IndexByte(raw, '\n'); at >= 0 {
		line = raw[:at]
	}
	fields := bytes.Fields(bytes.TrimRight(line, "\r \t"))
	if len(fields) < 2 || !bytes.HasPrefix(fields[0], []byte("HTTP/")) {
		return 0
	}
	status, err := strconv.Atoi(string(fields[1]))
	if err != nil {
		return 0
	}
	return status
}

func wafSignature(body []byte) bool {
	for _, marker := range [][]byte{
		[]byte("cloudflare"), []byte("captcha"), []byte("access denied"),
		[]byte("request blocked"), []byte("blocked by"), []byte("mod_security"),
		[]byte("web application firewall"), []byte("security check"),
	} {
		if bytes.Contains(body, marker) {
			return true
		}
	}
	return false
}

// safeAnalyze is the synchronous SafeGo boundary for FSM execution. A panic is
// audited as ErrPrecisionLost and always yields Engine_Fault, never a crash.
func safeAnalyze(m *ParserStateMachine, raw []byte, err error) (state ParserState, fault error) {
	errs := util.SafeGoPayload(raw, func() {
		state = m.AnalyzeDivergence(raw, err)
	})
	if fault = <-errs; fault != nil {
		return ParserEngineFault, fault
	}
	return state, nil
}
