// Package obfuscation contains the transport layer model. This file adds a
// byte-only HTTP/1.1 framing mutation generator.
//
// Contract: no sockets, no net/http, no request writers. The generator receives
// raw request bytes and returns raw request bytes. It never introduces or
// removes a CRLF boundary: header lines and chunk-size lines are edited in
// place, so the number and position of every \r\n in the input is preserved.
package obfuscation

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"

	"github.com/skyrimdlyalohov-droid/omnislash/util"
)

// FramingMode selects one HTTP/1.1 parser-disagreement family.
type FramingMode string

const (
	// FramingOWSBeforeColon puts a non-canonical whitespace/control byte in
	// front of the colon of TE/CL header lines.
	FramingOWSBeforeColon FramingMode = "ows_before_colon"
	// FramingOWSInValue puts the same byte inside a TE/CL value, past the
	// delimiter a strict parser uses to find the token.
	FramingOWSInValue FramingMode = "ows_in_value"
	// FramingConflictingHeaders gives TE/CL conflicting values. If the base
	// already repeats a framing header, each line receives a different value;
	// otherwise the conflict is expressed as a comma-separated token list on
	// the single line, which keeps the CRLF layout byte-exact.
	FramingConflictingHeaders FramingMode = "conflicting_framing"
	// FramingChunkBoundary adds an extension with non-canonical boundary bytes
	// to the first chunk-size line, or to the TE value when no chunked body is
	// present.
	FramingChunkBoundary FramingMode = "chunk_boundary"
)

var (
	// ErrNoFramingHeader means the base request has nothing for the mutation to
	// edit. It is a local precondition failure, never target evidence.
	ErrNoFramingHeader = errors.New("obfuscation: no framing header in request")
	// ErrFramingMode means the caller requested an unknown mutation family.
	ErrFramingMode = errors.New("obfuscation: unknown framing mode")
	// ErrOWSByte means an option tried to use a byte that could break framing.
	ErrOWSByte = errors.New("obfuscation: invalid OWS byte")
)

// allowedOWS contains only bytes that cannot terminate or fold an HTTP/1.1
// header line: horizontal tab, vertical tab, form feed and space.
var allowedOWS = map[byte]struct{}{
	0x09: {}, 0x0b: {}, 0x0c: {}, 0x20: {},
}

var owsChoices = []byte{0x09, 0x0b, 0x0c, 0x20}

// FramingOptions makes one mutation reproducible without relying on hidden
// state. PayloadMutator derives these values from its seed; tests pass them
// directly to assert exact bytes.
type FramingOptions struct {
	// OWS is the whitespace/control byte inserted around a delimiter. Zero
	// selects the horizontal tab.
	OWS byte
	// Variant selects one conflicting TE/CL value pair.
	Variant int
	// FlipCase toggles the case of framing header names.
	FlipCase bool
}

// NormalizeFramingOptions validates the option set used on the byte path.
func NormalizeFramingOptions(opts FramingOptions) (FramingOptions, error) {
	if opts.OWS == 0 {
		opts.OWS = 0x09
	}
	if _, ok := allowedOWS[opts.OWS]; !ok {
		return FramingOptions{}, fmt.Errorf("%w: %#x", ErrOWSByte, opts.OWS)
	}
	if opts.Variant < 0 {
		opts.Variant = 0
	}
	return opts, nil
}

// FramingOptionsFromSeed derives a deterministic option set from seed.
func FramingOptionsFromSeed(seed int64) FramingOptions {
	rng := rand.New(rand.NewSource(seed))
	return FramingOptions{
		OWS:      owsChoices[rng.Intn(len(owsChoices))],
		Variant:  rng.Intn(4),
		FlipCase: rng.Intn(2) == 1,
	}
}

var requestSeparator = []byte("\r\n\r\n")
var lineSeparator = []byte("\r\n")

// ApplyFramingMutationSeeded is ApplyFramingMutation with seed-derived options.
func ApplyFramingMutationSeeded(raw []byte, mode FramingMode, seed int64) ([]byte, error) {
	return ApplyFramingMutation(raw, mode, FramingOptionsFromSeed(seed))
}

// ApplyFramingMutation returns a fresh slice. A framing violation is returned
// as util.ErrPrecisionLost so the probe FSM classifies it as Engine_Fault
// instead of treating it as a target response or a proxy failure.
func ApplyFramingMutation(raw []byte, mode FramingMode, opts FramingOptions) ([]byte, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("obfuscation: empty request")
	}
	if !validFramingCRLF(raw) {
		return nil, fmt.Errorf("%w: input has a bare CR or LF", util.ErrPrecisionLost)
	}
	at := bytes.Index(raw, requestSeparator)
	if at < 0 {
		return nil, fmt.Errorf("%w: request has no header terminator", util.ErrPrecisionLost)
	}
	if !knownFramingMode(mode) {
		return nil, fmt.Errorf("%w: %q", ErrFramingMode, mode)
	}
	normalized, err := NormalizeFramingOptions(opts)
	if err != nil {
		return nil, err
	}

	head, body := raw[:at], raw[at+len(requestSeparator):]
	lines := bytes.Split(head, lineSeparator)
	if len(lines) < 2 {
		return nil, fmt.Errorf("%w: request has no header lines", util.ErrPrecisionLost)
	}

	out := make([][]byte, len(lines))
	copy(out, lines)
	changed := false
	switch mode {
	case FramingOWSBeforeColon:
		changed = rewriteFramingLines(out, func(key, value []byte, _, _ int) ([]byte, []byte) {
			k := append(append([]byte(nil), bytes.TrimRight(key, " \t")...), normalized.OWS)
			v := append([]byte{normalized.OWS}, value...)
			return k, v
		})
	case FramingOWSInValue:
		changed = rewriteFramingLines(out, func(key, value []byte, _, _ int) ([]byte, []byte) {
			v, ok := insertValueOWS(value, normalized.OWS)
			if !ok {
				return key, value
			}
			return key, v
		})
	case FramingConflictingHeaders:
		teTotal := countFramingLines(lines, "transfer-encoding")
		clTotal := countFramingLines(lines, "content-length")
		if teTotal == 0 && clTotal == 0 {
			return nil, fmt.Errorf("%w: conflicting framing needs TE or CL", ErrNoFramingHeader)
		}
		changed = rewriteFramingLines(out, func(key, value []byte, teIndex, clIndex int) ([]byte, []byte) {
			switch {
			case asciiEqualFold(key, []byte("transfer-encoding")):
				v := conflictingTEValue(normalized.Variant, teIndex, teTotal)
				return maybeFlipCase(key, normalized.FlipCase), []byte(" " + v)
			case asciiEqualFold(key, []byte("content-length")):
				v := conflictingCLValue(normalized.Variant, clIndex, clTotal)
				return maybeFlipCase(key, normalized.FlipCase), []byte(" " + v)
			default:
				return key, value
			}
		})
	case FramingChunkBoundary:
		body, changed = applyChunkBoundary(out, body, normalized)
	}
	if !changed {
		return nil, fmt.Errorf("%w: %s applied to no framing bytes", ErrNoFramingHeader, mode)
	}

	result := append([]byte(nil), bytes.Join(out, lineSeparator)...)
	result = append(result, requestSeparator...)
	result = append(result, body...)
	if !validFramingCRLF(result) ||
		bytes.Count(result, lineSeparator) != bytes.Count(raw, lineSeparator) ||
		bytes.Count(result, requestSeparator) != bytes.Count(raw, requestSeparator) {
		return nil, fmt.Errorf("%w: mutation changed a CRLF boundary", util.ErrPrecisionLost)
	}
	if mode != FramingChunkBoundary {
		baseBody := raw[at+len(requestSeparator):]
		if !bytes.Equal(result[len(result)-len(baseBody):], baseBody) {
			return nil, fmt.Errorf("%w: mutation changed the request body", util.ErrPrecisionLost)
		}
	}
	return result, nil
}

func knownFramingMode(mode FramingMode) bool {
	switch mode {
	case FramingOWSBeforeColon, FramingOWSInValue,
		FramingConflictingHeaders, FramingChunkBoundary:
		return true
	default:
		return false
	}
}

// rewriteFramingLines edits only framing header lines. teIndex/clIndex count
// occurrences so a repeated header can receive a different value on each line.
func rewriteFramingLines(lines [][]byte, fn func(key, value []byte, teIndex, clIndex int) ([]byte, []byte)) bool {
	teIndex, clIndex := 0, 0
	changed := false
	for i := 1; i < len(lines); i++ {
		colon := bytes.IndexByte(lines[i], ':')
		if colon < 0 {
			continue
		}
		key, value := lines[i][:colon], lines[i][colon+1:]
		if !isFramingHeader(key) {
			continue
		}
		isTE := asciiEqualFold(key, []byte("transfer-encoding"))
		newKey, newValue := fn(key, value, teIndex, clIndex)
		if isTE {
			teIndex++
		} else {
			clIndex++
		}
		if bytes.Equal(newKey, key) && bytes.Equal(newValue, value) {
			continue
		}
		out := make([]byte, 0, len(newKey)+len(newValue)+1)
		out = append(out, newKey...)
		out = append(out, ':')
		out = append(out, newValue...)
		lines[i] = out
		changed = true
	}
	return changed
}

func countFramingLines(lines [][]byte, name string) int {
	n := 0
	for i := 1; i < len(lines); i++ {
		colon := bytes.IndexByte(lines[i], ':')
		if colon < 0 {
			continue
		}
		if asciiEqualFold(lines[i][:colon], []byte(name)) {
			n++
		}
	}
	return n
}

func isFramingHeader(key []byte) bool {
	return asciiEqualFold(key, []byte("transfer-encoding")) ||
		asciiEqualFold(key, []byte("content-length"))
}

func insertValueOWS(value []byte, ows byte) ([]byte, bool) {
	trimmed := bytes.TrimLeft(value, " \t")
	if len(trimmed) == 0 {
		return nil, false
	}
	out := make([]byte, 0, len(value)+2)
	out = append(out, ' ')
	out = append(out, trimmed[0])
	out = append(out, ows)
	out = append(out, trimmed[1:]...)
	return out, true
}

var teConflicts = [][2]string{
	{"chunked", "identity"},
	{"identity", "chunked"},
	{"cow", "chunked"},
	{"chunked", "cow"},
}

var clConflicts = [][2]string{
	{"4", "0"},
	{"0", "4"},
	{"4", "00"},
	{"0x4", "4"},
}

func conflictingTEValue(variant, index, total int) string {
	pair := teConflicts[variant%len(teConflicts)]
	if total == 1 {
		return pair[0] + ", " + pair[1]
	}
	return pair[index%2]
}

func conflictingCLValue(variant, index, total int) string {
	pair := clConflicts[variant%len(clConflicts)]
	if total == 1 {
		return pair[0] + ", " + pair[1]
	}
	return pair[index%2]
}

func maybeFlipCase(key []byte, flip bool) []byte {
	if !flip {
		return key
	}
	out := append([]byte(nil), key...)
	for i, c := range out {
		if c >= 'a' && c <= 'z' {
			out[i] = c - ('a' - 'A')
		} else if c >= 'A' && c <= 'Z' {
			out[i] = c + ('a' - 'A')
		}
	}
	return out
}

// applyChunkBoundary edits the first chunk-size line in place. When the body
// has no hex chunk size, it extends the TE value instead; both forms stay on
// one line and leave every CRLF boundary untouched.
func applyChunkBoundary(lines [][]byte, body []byte, opts FramingOptions) ([]byte, bool) {
	end := bytes.Index(body, lineSeparator)
	if end > 0 && asciiContainsFold(bytes.Join(lines, lineSeparator), "chunked") {
		size := body[:end]
		if isHexChunkSize(size) {
			ext := append([]byte{';', opts.OWS}, []byte("x="+string(opts.OWS)+"1")...)
			newBody := make([]byte, 0, len(body)+len(ext))
			newBody = append(newBody, size...)
			newBody = append(newBody, ext...)
			newBody = append(newBody, body[end:]...)
			return newBody, true
		}
	}
	changed := rewriteFramingLines(lines, func(key, value []byte, _, _ int) ([]byte, []byte) {
		if !asciiEqualFold(key, []byte("transfer-encoding")) {
			return key, value
		}
		ext := append([]byte{';', opts.OWS}, []byte("x="+string(opts.OWS)+"1")...)
		out := append(append([]byte(nil), bytes.TrimRight(value, " \t")...), ext...)
		return key, out
	})
	return body, changed
}

func isHexChunkSize(v []byte) bool {
	if len(v) == 0 {
		return false
	}
	for _, c := range v {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

func validFramingCRLF(raw []byte) bool {
	for i := 0; i < len(raw); i++ {
		switch raw[i] {
		case '\r':
			if i+1 >= len(raw) || raw[i+1] != '\n' {
				return false
			}
			i++
		case '\n':
			return false
		}
	}
	return true
}

func asciiEqualFold(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if asciiLower(a[i]) != asciiLower(b[i]) {
			return false
		}
	}
	return true
}

func asciiContainsFold(raw []byte, needle string) bool {
	if len(needle) == 0 || len(raw) < len(needle) {
		return false
	}
	for i := 0; i+len(needle) <= len(raw); i++ {
		if asciiEqualFold(raw[i:i+len(needle)], []byte(needle)) {
			return true
		}
	}
	return false
}

func asciiLower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}
