package omnislash

import (
	"bytes"
	"hash/fnv"
	"math/bits"
	"sort"
	"strings"
)

// This file is the local, stdlib-only structural analyzer. It complements the
// zlib NCD in deception.go: NCD still measures raw byte similarity, while this
// analyzer compares a value-free skeleton and a SimHash of that skeleton. A
// rotating CSRF token, timestamp or advertising id changes bytes but not the
// skeleton, so it cannot be mistaken for a changed response queue or layout.

const (
	maxStructureBytes  = 64 << 10
	maxStructureTokens = 512
	maxStructureKeyLen = 128
)

// StructuralProfile is a value-free description of one response body. Keys are
// sorted so a reordered JSON object or repeated tag does not produce noise.
type StructuralProfile struct {
	Kind        string `json:"kind,omitempty"`
	Skeleton    string `json:"skeleton,omitempty"`
	Fingerprint uint64 `json:"fingerprint,omitempty"`
	keys        []string
}

// volatileJSONKeys carry per-request values. They are omitted from the
// skeleton: a new token value is expected, a new page layout is not.
var volatileJSONKeys = map[string]struct{}{
	"csrf": {}, "csrf_token": {}, "csrftoken": {}, "token": {},
	"timestamp": {}, "time": {}, "ts": {}, "nonce": {},
	"request_id": {}, "requestid": {}, "session_id": {}, "sessionid": {},
	"sid": {}, "trace_id": {}, "traceid": {}, "correlation_id": {},
	// Random identifiers rotate on every response. They carry no page
	// structure, so they must not move the SimHash between clean requests.
	"uuid": {}, "guid": {}, "random": {}, "random_id": {}, "randomid": {},
	"state": {}, "sig": {}, "signature": {}, "jsessionid": {}, "phpsessid": {},
	"auth_token": {}, "authtoken": {}, "access_token": {}, "accesstoken": {},
	"refresh_token": {}, "refreshtoken": {}, "idempotency_key": {},
	"ad": {}, "ads": {}, "ad_id": {}, "adid": {}, "advert_id": {},
	"expires": {}, "expiry": {}, "etag": {}, "cache_key": {}, "cachekey": {},
	"bust": {}, "cb": {},
}

// AnalyzeStructure builds a structural profile from body. It does no I/O and
// never reads anything beyond the supplied bytes.
func AnalyzeStructure(body []byte, contentType string) StructuralProfile {
	if len(body) > maxStructureBytes {
		body = body[:maxStructureBytes]
	}
	kind := structureKind(body, contentType)
	tokens := make(map[string]struct{})
	switch kind {
	case "html":
		collectHTMLStructure(body, tokens)
	case "json":
		collectJSONStructure(body, tokens)
	}
	if len(tokens) == 0 {
		return StructuralProfile{Kind: kind}
	}
	keys := make([]string, 0, len(tokens))
	for key := range tokens {
		keys = append(keys, key)
		if len(keys) == maxStructureTokens {
			break
		}
	}
	sort.Strings(keys)
	var skeleton strings.Builder
	skeleton.WriteString(kind)
	for _, key := range keys {
		skeleton.WriteByte('|')
		skeleton.WriteString(key)
	}
	return StructuralProfile{
		Kind:        kind,
		Skeleton:    skeleton.String(),
		Fingerprint: simhash(keys),
		keys:        keys,
	}
}

// HasTokens reports whether the profile carries value-free structural tokens.
// Profiles for plain text have none, so callers should fall back to raw NCD.
func (p StructuralProfile) HasTokens() bool { return len(p.keys) > 0 }

// StructuralShift compares two raw bodies directly. A zero result means the
// value-free skeletons are identical, not that the bytes were identical.
func StructuralShift(base, sample []byte, contentType string) float64 {
	return StructuralDistance(
		AnalyzeStructure(base, contentType),
		AnalyzeStructure(sample, contentType),
	)
}

// StructuralDistance returns 0..1. It takes the larger of token-set distance
// and SimHash Hamming distance, so a single new tag or JSON key is visible
// while a changed token value is not.
func StructuralDistance(a, b StructuralProfile) float64 {
	if len(a.keys) == 0 && len(b.keys) == 0 {
		return 0
	}
	intersection, union := 0, 0
	for i, j := 0, 0; i < len(a.keys) || j < len(b.keys); {
		switch {
		case j >= len(b.keys) || (i < len(a.keys) && a.keys[i] < b.keys[j]):
			union++
			i++
		case i >= len(a.keys) || b.keys[j] < a.keys[i]:
			union++
			j++
		default:
			intersection++
			union++
			i++
			j++
		}
	}
	distance := 0.0
	if union > 0 {
		distance = 1 - float64(intersection)/float64(union)
	}
	hashDistance := float64(bits.OnesCount64(a.Fingerprint^b.Fingerprint)) / 64
	if hashDistance > distance {
		return hashDistance
	}
	return distance
}

func structureKind(body []byte, contentType string) string {
	ct := strings.ToLower(contentType)
	if strings.Contains(ct, "json") {
		return "json"
	}
	if strings.Contains(ct, "html") {
		return "html"
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') {
		return "json"
	}
	head := trimmed
	if len(head) > 512 {
		head = head[:512]
	}
	lower := bytes.ToLower(head)
	if bytes.Contains(lower, []byte("<html")) || bytes.Contains(lower, []byte("<body")) ||
		bytes.Contains(lower, []byte("<div")) || bytes.Contains(lower, []byte("<form")) {
		return "html"
	}
	return "text"
}

// collectJSONStructure records container kinds and stable key names. Values
// (including nested strings, numbers and booleans) are deliberately ignored.
func collectJSONStructure(body []byte, tokens map[string]struct{}) {
	inString := false
	escaped := false
	var str []byte
	for i := 0; i < len(body); i++ {
		c := body[i]
		if inString {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
				j := i + 1
				for j < len(body) && isJSONSpace(body[j]) {
					j++
				}
				if j < len(body) && body[j] == ':' {
					key := strings.ToLower(string(str))
					if len(key) > 0 && len(key) <= maxStructureKeyLen {
						if _, volatile := volatileJSONKeys[key]; !volatile {
							tokens["key:"+key] = struct{}{}
						}
					}
				}
				str = str[:0]
			default:
				if len(str) < maxStructureKeyLen {
					str = append(str, c)
				}
			}
			continue
		}
		switch c {
		case '"':
			inString = true
			str = str[:0]
		case '{':
			tokens["obj"] = struct{}{}
		case '[':
			tokens["arr"] = struct{}{}
		}
	}
}

func isJSONSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}

// collectHTMLStructure records element names only. Attribute values carry the
// rotating tokens, so reading them would turn noise into a false structural
// shift. Script and style bodies are skipped: their text is not page structure.
func collectHTMLStructure(body []byte, tokens map[string]struct{}) {
	tokens["document"] = struct{}{}
	for i := 0; i < len(body); {
		if body[i] != '<' {
			i++
			continue
		}
		if bytes.HasPrefix(body[i:], []byte("<!--")) {
			if end := bytes.Index(body[i+4:], []byte("-->")); end >= 0 {
				i += 4 + end + 3
				continue
			}
			i++
			continue
		}
		j := i + 1
		if j < len(body) && body[j] == '/' {
			j++
		}
		start := j
		for j < len(body) && isHTMLTagName(body[j]) {
			j++
		}
		if j == start {
			i++
			continue
		}
		name := strings.ToLower(string(body[start:j]))
		if len(name) <= maxStructureKeyLen {
			tokens["tag:"+name] = struct{}{}
		}
		switch name {
		case "script", "style":
			closing := []byte("</" + name)
			if end := bytes.Index(bytes.ToLower(body[j:]), closing); end >= 0 {
				i = j + end + len(closing)
				continue
			}
		}
		i = j
	}
}

func isHTMLTagName(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '-'
}

// simhash folds the sorted token set into a 64-bit fingerprint. Accumulation
// is commutative, so the result does not depend on map iteration order.
func simhash(keys []string) uint64 {
	var counts [64]int
	for _, key := range keys {
		h := fnv.New64a()
		_, _ = h.Write([]byte(key))
		sum := h.Sum64()
		for bit := 0; bit < 64; bit++ {
			if sum&(uint64(1)<<uint(bit)) != 0 {
				counts[bit]++
			} else {
				counts[bit]--
			}
		}
	}
	var fingerprint uint64
	for bit := 0; bit < 64; bit++ {
		if counts[bit] >= 0 {
			fingerprint |= uint64(1) << uint(bit)
		}
	}
	return fingerprint
}
