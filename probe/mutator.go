package probe

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/skyrimdlyalohov-droid/omnislash/util"

	rawhttp "github.com/projectdiscovery/rawhttp/client"
)

// Mutation describes a grammar mutation applied to an HTTP request.
type Mutation struct {
	Name        string `json:"name"`
	Category    string `json:"category"`
	Description string `json:"description"`
}

// Mutator generates HTTP grammar mutations bound to a tech stack signature.
type Mutator struct {
	TechStack []string
	Seed      int64
}

// TechStackHash returns a stable hash for a tech stack.
func TechStackHash(stack []string) string {
	norm := make([]string, 0, len(stack))
	for _, s := range stack {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" {
			norm = append(norm, s)
		}
	}
	sort.Strings(norm)
	sum := sha256.Sum256([]byte(strings.Join(norm, "|")))
	return hex.EncodeToString(sum[:8])
}

func (m Mutator) Hash() string { return TechStackHash(m.TechStack) }

// Mutations returns the available grammar mutations.
func (m Mutator) Mutations() []Mutation {
	return []Mutation{
		{Name: "ctl_nul", Category: "control", Description: "inject 0x00 in header value"},
		{Name: "ctl_tab", Category: "control", Description: "inject 0x09 in header value"},
		{Name: "ctl_vtab", Category: "control", Description: "inject 0x0b in header value"},
		{Name: "ctl_ff", Category: "control", Description: "inject 0x0c in header value"},
		{Name: "ctl_del", Category: "control", Description: "inject 0x7f in header value"},
		{Name: "unpaired_cr", Category: "linebreak", Description: "unpaired \\r in header folding"},
		{Name: "unpaired_lf", Category: "linebreak", Description: "unpaired \\n in header folding"},
		{Name: "space_before_colon", Category: "separator", Description: "Header : value"},
		{Name: "cl_te_duplicate", Category: "framing", Description: "duplicate CL and TE variations"},
		{Name: "te_obfuscation", Category: "framing", Description: "Transfer-Encoding obfuscation"},
	}
}

// Apply applies a named mutation to a base request and returns raw bytes.
func (m Mutator) Apply(name string, target Target) ([]byte, Mutation, error) {
	basePath := target.RequestPath()
	if !strings.Contains(basePath, "_omni_cb=") {
		basePath = AppendCacheBuster(basePath)
	}
	spec := requestSpec{
		Method:  "GET",
		Path:    basePath,
		Version: rawhttp.HTTP_1_1,
		Headers: []rawhttp.Header{
			{Key: "Host", Value: target.HostHeader()},
			{Key: "User-Agent", Value: "omnislash-probe/1"},
			{Key: "Accept", Value: "*/*"},
			{Key: "Connection", Value: "keep-alive"},
		},
	}
	mut := Mutation{Name: name, Category: "unknown"}

	switch name {
	case "ctl_nul", "ctl_tab", "ctl_vtab", "ctl_ff", "ctl_del":
		b := map[string]byte{"ctl_nul": 0x00, "ctl_tab": 0x09, "ctl_vtab": 0x0b, "ctl_ff": 0x0c, "ctl_del": 0x7f}[name]
		spec.Headers = append(spec.Headers, rawhttp.Header{Key: "X-Omni-Probe", Value: "value" + string([]byte{b}) + "x"})
		mut = Mutation{Name: name, Category: "control", Description: "control byte in header value"}
	case "unpaired_cr":
		spec.Headers = append(spec.Headers, rawhttp.Header{Key: "X-Omni-Probe", Value: "value\rinjected"})
		mut = Mutation{Name: name, Category: "linebreak", Description: "unpaired CR"}
	case "unpaired_lf":
		spec.Headers = append(spec.Headers, rawhttp.Header{Key: "X-Omni-Probe", Value: "value\ninjected"})
		mut = Mutation{Name: name, Category: "linebreak", Description: "unpaired LF"}
	case "space_before_colon":
		// Render manually to preserve "Header : value"
		mut = Mutation{Name: name, Category: "separator", Description: "space before colon"}
		raw := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent : omnislash-probe/1\r\nAccept: */*\r\nConnection: close\r\n\r\n", spec.Path, target.HostHeader())
		return []byte(raw), mut, nil
	case "cl_te_duplicate":
		mut = Mutation{Name: name, Category: "framing", Description: "CL/TE duplicate"}
		body := "0\r\n\r\n"
		raw := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: omnislash-probe/1\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\nConnection: keep-alive\r\n\r\n%s", spec.Path, target.HostHeader(), body)
		return []byte(raw), mut, nil
	case "te_obfuscation":
		mut = Mutation{Name: name, Category: "framing", Description: "TE obfuscation"}
		body := "0\r\n\r\n"
		raw := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: omnislash-probe/1\r\nContent-Length: 4\r\nTransfer-Encoding: xchunked\r\nConnection: keep-alive\r\n\r\n%s", spec.Path, target.HostHeader(), body)
		return []byte(raw), mut, nil
	default:
		return nil, mut, fmt.Errorf("unknown mutation %q", name)
	}

	b, err := render(spec)
	if err != nil {
		// fallback: build manually for control chars that rawhttp may normalize
		raw := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: omnislash-probe/1\r\nX-Omni-Probe: value%sx\r\nAccept: */*\r\nConnection: close\r\n\r\n", spec.Path, target.HostHeader(), mutationControl(name))
		return []byte(raw), mut, nil
	}
	return b, mut, nil
}

func mutationControl(name string) string {
	switch name {
	case "ctl_nul":
		return "\x00"
	case "ctl_tab":
		return "\x09"
	case "ctl_vtab":
		return "\x0b"
	case "ctl_ff":
		return "\x0c"
	case "ctl_del":
		return "\x7f"
	default:
		return ""
	}
}

// ApplyRandom picks a mutation (deterministic by seed/index if caller controls it).
func (m Mutator) ApplyRandom(target Target, idx int) ([]byte, Mutation, error) {
	muts := m.Mutations()
	if len(muts) == 0 {
		return nil, Mutation{}, fmt.Errorf("no mutations")
	}
	i := idx % len(muts)
	if i < 0 {
		i = -i
	}
	return m.Apply(muts[i].Name, target)
}

// ScopeGuard is the fail-closed allowlist contract used before any payload is
// mutated. *omnislash.Scope satisfies it; a nil guard never authorizes a write.
type ScopeGuard interface {
	CheckTarget(ctx context.Context, target string) (string, error)
}

// ErrMutationScopeDenied means a mutation was refused before any byte was
// changed. Refusal is fail-closed: no guard or no target means no mutation.
var ErrMutationScopeDenied = errors.New("probe: mutation denied by scope guard")

// MutationMode selects one mutation family. Auto rotates deterministically by
// seed, so one attempt is reproducible from (base payload, seed, mode).
type MutationMode string

const (
	MutationAuto            MutationMode = ""
	MutationHeaderFolding   MutationMode = "header_folding"
	MutationChunkExtensions MutationMode = "chunk_extensions"
	MutationCaseMixing      MutationMode = "case_mixing"
	// Directed modes are chosen by the orchestrator's FSM, never by the
	// mutator's own rotation. They are intentionally absent from
	// mutationModeOrder so legacy differential-fuzz behaviour is unchanged.
	MutationBoundaryShift  MutationMode = "boundary_shift"
	MutationEliteCrossover MutationMode = "elite_crossover"
)

var mutationModeOrder = []MutationMode{
	MutationHeaderFolding,
	MutationChunkExtensions,
	MutationCaseMixing,
}

const maxMutationPayload = 4 << 20

// payloadMutationPool is the default pool for mutation scratch buffers. A
// caller can supply its own Pool (tests use it to prove every byte is wiped and
// the buffer is returned with len 0).
var payloadMutationPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 32<<10)
		return &buf
	},
}

// BufferPool is the sync.Pool-shaped contract for mutation scratch buffers.
// *sync.Pool satisfies it; tests can supply an observer to prove zeroing and
// return-to-pool without relying on pool reuse heuristics.
type BufferPool interface {
	Get() any
	Put(any)
}

// PayloadMutator rewrites raw HTTP/1 requests without touching net/http. It
// only changes bytes inside header lines or chunk-size lines: the number and
// position of every \r\n in the base request is preserved.
//
// A mutation is never performed without a successful ScopeGuard.CheckTarget on
// Target. This is independent of the transport's own dial-time scope check: the
// mutation layer does not trust an upstream decision.
type PayloadMutator struct {
	Scope  ScopeGuard
	Target string
	Mode   MutationMode
	Ctx    context.Context
	// Fitness is the normalized reward supplied by the orchestrator's FSM.
	// A negative value shifts a framing boundary down, a positive one up.
	Fitness float64
	// Elite holds up to two confirmed patterns for crossover. It is data
	// supplied by the caller; the mutator never runs an evolution loop.
	Elite [][]byte
	// Pool is optional. It must return *[]byte.
	Pool BufferPool
}

func (m *PayloadMutator) pool() BufferPool {
	if m != nil && m.Pool != nil {
		return m.Pool
	}
	return &payloadMutationPool
}

// Mutate returns a fresh byte slice. The pooled scratch buffer is cleared,
// truncated to len 0 and returned before the function exits, on every path.
// A panic (for example from a hostile pool) is converted to ErrPrecisionLost
// by safeMutate; callers must use that wrapper on the probe hot path.
func (m *PayloadMutator) Mutate(basePayload []byte, seed int64) ([]byte, error) {
	if m == nil {
		return nil, errors.New("probe: nil payload mutator")
	}
	if len(basePayload) == 0 {
		return nil, errors.New("probe: empty payload")
	}
	if len(basePayload) > maxMutationPayload {
		return nil, fmt.Errorf("probe: payload exceeds %d bytes", maxMutationPayload)
	}
	if err := m.checkScope(); err != nil {
		return nil, err
	}
	if !validCRLF(basePayload) {
		return nil, errors.New("probe: payload contains bare CR or LF")
	}

	ptr := m.pool().Get().(*[]byte)
	buf := (*ptr)[:0]
	released := false
	defer func() {
		if !released {
			releaseMutationBuffer(m.pool(), buf)
		}
	}()

	buf = append(buf, basePayload...)
	rng := rand.New(rand.NewSource(seed))
	mode := m.Mode
	if mode == MutationAuto {
		idx := seed % int64(len(mutationModeOrder))
		if idx < 0 {
			idx = -idx
		}
		mode = mutationModeOrder[idx]
	}
	switch mode {
	case MutationHeaderFolding:
		buf = rewriteRequestHeaders(buf, foldingRewrite(rng))
	case MutationCaseMixing:
		buf = rewriteRequestHeaders(buf, caseRewrite(rng))
	case MutationChunkExtensions:
		buf = appendChunkExtension(buf, rng)
	case MutationBoundaryShift:
		buf = shiftRequestBoundary(buf, rng, m.Fitness)
	case MutationEliteCrossover:
		buf = crossoverEliteFraming(buf, rng, m.Elite)
	default:
		return nil, fmt.Errorf("probe: unknown mutation mode %q", mode)
	}

	out := append([]byte(nil), buf...)
	releaseMutationBuffer(m.pool(), buf)
	released = true
	return out, nil
}

func (m *PayloadMutator) checkScope() error {
	if m.Scope == nil {
		return fmt.Errorf("%w: no scope guard configured", ErrMutationScopeDenied)
	}
	if m.Target == "" {
		return fmt.Errorf("%w: empty target", ErrMutationScopeDenied)
	}
	ctx := m.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	if _, err := m.Scope.CheckTarget(ctx, m.Target); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrMutationScopeDenied, m.Target, err)
	}
	return nil
}

// safeMutate is the synchronous SafeGo boundary for the mutation hot path. A
// panic becomes util.ErrPrecisionLost and is written to the panic audit, never
// propagated as an unrecovered daemon crash.
func safeMutate(m *PayloadMutator, base []byte, seed int64) (out []byte, err error) {
	errs := util.SafeGoPayload(base, func() {
		out, err = m.Mutate(base, seed)
	})
	if fault := <-errs; fault != nil {
		return nil, fault
	}
	return out, err
}

func releaseMutationBuffer(p BufferPool, buf []byte) {
	full := buf[:cap(buf)]
	clear(full)
	buf = buf[:0]
	p.Put(&buf)
}

// validCRLF rejects a base request with any bare CR or LF. Rewriting such a
// request could silently change framing, so it is refused instead of guessed.
func validCRLF(raw []byte) bool {
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

var requestSeparator = []byte("\r\n\r\n")

// rewriteRequestHeaders rebuilds only the header section. Body bytes are copied
// verbatim and every line boundary is re-emitted as CRLF.
func rewriteRequestHeaders(raw []byte, fn func(key, value []byte) ([]byte, []byte)) []byte {
	at := bytes.Index(raw, requestSeparator)
	if at < 0 {
		return raw
	}
	head, body := raw[:at], raw[at+len(requestSeparator):]
	lines := bytes.Split(head, []byte("\r\n"))
	if len(lines) == 0 {
		return raw
	}
	out := make([]byte, 0, len(raw)+64)
	out = append(out, lines[0]...)
	for _, line := range lines[1:] {
		out = append(out, '\r', '\n')
		colon := bytes.IndexByte(line, ':')
		if colon < 0 {
			out = append(out, line...)
			continue
		}
		key, value := fn(line[:colon], line[colon+1:])
		out = append(out, key...)
		out = append(out, ':')
		out = append(out, value...)
	}
	out = append(out, requestSeparator...)
	return append(out, body...)
}

func isFramingHeader(key []byte) bool {
	return asciiEqualFold(key, []byte("content-length")) ||
		asciiEqualFold(key, []byte("transfer-encoding"))
}

// Header Folding: OWS inside CL/TE values becomes a tab or a double space.
// inserted OWS is legal and never includes a line break.
func foldingRewrite(rng *rand.Rand) func([]byte, []byte) ([]byte, []byte) {
	return func(key, value []byte) ([]byte, []byte) {
		if !isFramingHeader(key) {
			return key, value
		}
		sep := []byte("\t")
		if rng.Intn(2) == 1 {
			sep = []byte("  ")
		}
		value = bytes.TrimLeft(value, " \t")
		out := make([]byte, 0, len(value)+len(sep))
		out = append(out, sep...)
		for _, c := range value {
			if c == ' ' || c == '\t' {
				out = append(out, sep...)
				continue
			}
			out = append(out, c)
		}
		return key, out
	}
}

// Case Mixing: randomize the case of CL/TE header names. The first letter is
// always toggled so the mutation is observable even for an unlucky draw.
func caseRewrite(rng *rand.Rand) func([]byte, []byte) ([]byte, []byte) {
	return func(key, value []byte) ([]byte, []byte) {
		if !isFramingHeader(key) {
			return key, value
		}
		out := append([]byte(nil), key...)
		toggled := false
		for i, c := range out {
			if !isASCIILetter(c) {
				continue
			}
			if !toggled || rng.Intn(2) == 0 {
				out[i] = toggleASCIICase(c)
				toggled = true
			}
		}
		return out, value
	}
}

// shiftRequestBoundary performs one fitness-directed edit of a framing
// boundary: Content-Length moves by one in the reward's direction and
// Transfer-Encoding gains a one-token parameter. Both edits stay inside an
// existing header line, so every CRLF boundary is preserved.
func shiftRequestBoundary(raw []byte, rng *rand.Rand, fitness float64) []byte {
	delta := 1
	if fitness < 0 {
		delta = -1
	}
	out := rewriteRequestHeaders(raw, func(key, value []byte) ([]byte, []byte) {
		switch {
		case asciiEqualFold(key, []byte("content-length")):
			n, err := strconv.Atoi(string(bytes.TrimSpace(value)))
			if err != nil {
				return key, value
			}
			n += delta
			if n < 0 {
				n = 0
			}
			if n > 99999 {
				n = 99999
			}
			out := append(leadingOWS(value), []byte(strconv.Itoa(n))...)
			return key, out
		case asciiEqualFold(key, []byte("transfer-encoding")):
			const hexChars = "0123456789abcdef"
			param := []byte(";omni=")
			param = append(param, hexChars[rng.Intn(len(hexChars))])
			// Copy before appending: value aliases the scratch buffer and an
			// in-place append could overwrite the following header line.
			out := append(leadingOWS(value), bytes.TrimSpace(value)...)
			return key, append(out, param...)
		default:
			return key, value
		}
	})
	if asciiContainsFold(out, "content-length") || asciiContainsFold(out, "transfer-encoding") {
		return out
	}
	return insertHeader(out, "X-Omni-Boundary", "shift")
}

// leadingOWS preserves the optional space/tab that followed the original
// colon, so a directed edit stays visually and syntactically inside the line.
func leadingOWS(value []byte) []byte {
	end := 0
	for end < len(value) && (value[end] == ' ' || value[end] == '\t') {
		end++
	}
	return append([]byte(nil), value[:end]...)
}

// insertHeader adds one header without changing any existing line boundary.
func insertHeader(raw []byte, key, value string) []byte {
	at := bytes.Index(raw, requestSeparator)
	if at < 0 {
		return raw
	}
	line := append([]byte(key+": "+value), requestSeparator...)
	out := make([]byte, 0, len(raw)+len(line))
	out = append(out, raw[:at]...)
	out = append(out, line...)
	return append(out, raw[at:]...)
}

// crossoverEliteFraming combines framing values from two elite patterns onto
// the current request. It never invents new framing bytes and copies only the
// header values that were actually confirmed in earlier attempts.
func crossoverEliteFraming(raw []byte, rng *rand.Rand, elite [][]byte) []byte {
	patterns := make([][]byte, 0, 2)
	for _, pattern := range elite {
		if len(pattern) == 0 || len(pattern) > maxMutationPayload || !validCRLF(pattern) {
			continue
		}
		patterns = append(patterns, pattern)
		if len(patterns) == 2 {
			break
		}
	}
	if len(patterns) == 0 {
		return raw
	}
	first := framingHeaderValues(patterns[0])
	preferFirst := rng.Intn(2) == 0
	if len(patterns) == 1 {
		return replaceFramingHeaders(raw, first, first)
	}
	second := framingHeaderValues(patterns[1])
	if preferFirst {
		return replaceFramingHeaders(raw, first, second)
	}
	return replaceFramingHeaders(raw, second, first)
}

func framingHeaderValues(raw []byte) map[string][]byte {
	values := make(map[string][]byte, 2)
	at := bytes.Index(raw, requestSeparator)
	if at < 0 {
		return values
	}
	for _, line := range bytes.Split(raw[:at], []byte("\r\n"))[1:] {
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		key := bytes.ToLower(bytes.TrimSpace(line[:colon]))
		if isFramingHeader(key) {
			values[string(key)] = append([]byte(nil), bytes.TrimSpace(line[colon+1:])...)
		}
	}
	return values
}

func replaceFramingHeaders(raw []byte, primary, secondary map[string][]byte) []byte {
	out := rewriteRequestHeaders(raw, func(key, value []byte) ([]byte, []byte) {
		lower := bytes.ToLower(key)
		if found, ok := primary[string(lower)]; ok {
			return key, append(leadingOWS(value), found...)
		}
		if found, ok := secondary[string(lower)]; ok {
			return key, append(leadingOWS(value), found...)
		}
		return key, value
	})
	if asciiContainsFold(out, "content-length") || asciiContainsFold(out, "transfer-encoding") {
		return out
	}
	for _, key := range []string{"content-length", "transfer-encoding"} {
		if value, ok := primary[key]; ok {
			return insertHeader(out, key, string(value))
		}
		if value, ok := secondary[key]; ok {
			return insertHeader(out, key, string(value))
		}
	}
	return out
}

// Chunk Extensions: add a junk hex extension to the first chunk-size line when
// the request has a chunked body. Otherwise extend the TE header value itself.
// Both forms stay on one line, so CRLF framing is unchanged.
func appendChunkExtension(raw []byte, rng *rand.Rand) []byte {
	ext := make([]byte, 0, 9)
	ext = append(ext, ';')
	const hexChars = "0123456789abcdef"
	for i := 0; i < 4; i++ {
		ext = append(ext, hexChars[rng.Intn(len(hexChars))])
	}
	at := bytes.Index(raw, requestSeparator)
	if at >= 0 {
		body := raw[at+len(requestSeparator):]
		if end := bytes.Index(body, []byte("\r\n")); end > 0 {
			size := body[:end]
			if isHexChunkSize(size) && asciiContainsFold(raw[:at], "chunked") {
				out := make([]byte, 0, len(raw)+len(ext))
				out = append(out, raw[:at+len(requestSeparator)]...)
				out = append(out, size...)
				out = append(out, ext...)
				return append(out, body[end:]...)
			}
		}
	}
	return rewriteRequestHeaders(raw, func(key, value []byte) ([]byte, []byte) {
		if !asciiEqualFold(key, []byte("transfer-encoding")) {
			return key, value
		}
		out := make([]byte, 0, len(value)+len(ext))
		out = append(out, value...)
		return key, append(out, ext...)
	})
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

func isASCIILetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func toggleASCIICase(c byte) byte {
	if c >= 'a' && c <= 'z' {
		return c - ('a' - 'A')
	}
	return c + ('a' - 'A')
}

func asciiEqualFold(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if lowerASCII(a[i]) != lowerASCII(b[i]) {
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

func lowerASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}
