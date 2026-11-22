package omnislash

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

var ErrDeceptionDetected = errors.New("omnislash: deception/tarpit detected")

// DeceptionKind classifies why a response or target was flagged.
type DeceptionKind string

const (
	DeceptionSynthetic200 DeceptionKind = "synthetic_200"
	DeceptionTarpit       DeceptionKind = "tarpit_latency"
	DeceptionRepeat       DeceptionKind = "repeat_pattern"
	DeceptionSecretCanary DeceptionKind = "secret_canary"
)

// DeceptionDecision is the defensive action taken by the filter.
type DeceptionDecision struct {
	Flagged   bool          `json:"flagged"`
	Kind      DeceptionKind `json:"kind,omitempty"`
	Host      string        `json:"host,omitempty"`
	Prefix    string        `json:"prefix,omitempty"`
	Reason    string        `json:"reason,omitempty"`
	Score     float64       `json:"score,omitempty"`
	Quarantine []string     `json:"quarantine,omitempty"`
}

// QuarantinedSecret is a finding that must not be auto-reused until verified.
type QuarantinedSecret struct {
	Value     string    `json:"value"`
	Kind      string    `json:"kind"`
	Source    string    `json:"source"`
	Host      string    `json:"host"`
	FirstSeen time.Time `json:"first_seen"`
	Verified  bool      `json:"verified"`
}

// BaselineProfile summarizes responses to known-nonexistent paths.
type BaselineProfile struct {
	Host         string
	Prefix       string
	Status       int
	BodyLen      int
	Entropy      float64
	TokenCount   int
	HasAdmin     bool
	HasJSONList  bool
	HTMLTagCount int
	Samples      int
	Sample       []byte `json:"-"`
}

// DeceptionFilter detects synthetic/tarpit responses and quarantines unverified
// secrets. It is defensive only: it never bypasses deception controls.
type DeceptionFilter struct {
	cfg DeceptionConfig
	log Logger

	mu         sync.Mutex
	baselines  map[string]*BaselineProfile // host|prefix
	flagged    map[string]DeceptionDecision
	repeats    map[string]*repeatState
	quarantine map[string]QuarantinedSecret
}

type repeatState struct {
	status  int
	count   int
	last    time.Time
	samples [][]byte
}

type Logger interface {
	Debug(msg string, args ...any)
	Warn(msg string, args ...any)
}

// NewDeceptionFilter creates a filter. A nil logger disables logging.
func NewDeceptionFilter(cfg DeceptionConfig, log Logger) *DeceptionFilter {
	if cfg.BaselineSamples <= 0 {
		cfg.BaselineSamples = 2
	}
	if cfg.MaxBodySample <= 0 {
		cfg.MaxBodySample = 64 << 10
	}
	if cfg.SimilarityThreshold <= 0 {
		cfg.SimilarityThreshold = 0.92
	}
	if cfg.RepeatStatus == 0 {
		cfg.RepeatStatus = 200
	}
	if cfg.RepeatThreshold <= 0 {
		cfg.RepeatThreshold = 8
	}
	if cfg.LatencySpikeFactor <= 0 {
		cfg.LatencySpikeFactor = 4
	}
	if cfg.Action == "" {
		cfg.Action = "cooldown"
	}
	return &DeceptionFilter{
		cfg:        cfg,
		log:        log,
		baselines:  make(map[string]*BaselineProfile),
		flagged:    make(map[string]DeceptionDecision),
		repeats:    make(map[string]*repeatState),
		quarantine: make(map[string]QuarantinedSecret),
	}
}

func (f *DeceptionFilter) Enabled() bool { return f != nil && f.cfg.Enabled }

func baselineKey(host, prefix string) string {
	return strings.ToLower(strings.TrimSpace(host)) + "|" + normalizePrefix(prefix)
}

func normalizePrefix(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if len(p) > 1 {
		p = strings.TrimRight(p, "/")
	}
	return p
}

// IsFlagged reports whether host/prefix is flagged as deception/tarpit.
func (f *DeceptionFilter) IsFlagged(host, prefix string) (DeceptionDecision, bool) {
	if f == nil {
		return DeceptionDecision{}, false
	}
	host = strings.ToLower(strings.TrimSpace(host))
	prefix = normalizePrefix(prefix)
	f.mu.Lock()
	defer f.mu.Unlock()
	if d, ok := f.flagged[baselineKey(host, prefix)]; ok {
		return d, true
	}
	if d, ok := f.flagged[baselineKey(host, "/")]; ok {
		return d, true
	}
	// Prefix match: flagged /api should match /api/v1.
	hostPrefix := host + "|"
	for k, d := range f.flagged {
		if !strings.HasPrefix(k, hostPrefix) {
			continue
		}
		fp := strings.TrimPrefix(k, hostPrefix)
		if fp == "/" {
			return d, true
		}
		if prefix == fp || strings.HasPrefix(prefix, fp+"/") {
			return d, true
		}
	}
	return DeceptionDecision{}, false
}

func (f *DeceptionFilter) flag(d DeceptionDecision) {
	f.mu.Lock()
	f.flagged[baselineKey(d.Host, d.Prefix)] = d
	f.mu.Unlock()
	if f.log != nil {
		f.log.Warn("deception flagged", "kind", d.Kind, "host", d.Host, "prefix", d.Prefix, "reason", d.Reason, "score", d.Score)
	}
}

// CalibrateBaseline issues 2-3 control requests to nonexistent random paths
// under baseURL+prefix and stores the baseline profile. doRequest should perform
// the request through the same transport/gateway path as real scans.
func (f *DeceptionFilter) CalibrateBaseline(ctx context.Context, baseURL, prefix string, doRequest func(context.Context, string) (*http.Response, time.Duration, error)) (*BaselineProfile, error) {
	if f == nil || !f.Enabled() {
		return nil, nil
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	host := u.Hostname()
	prefix = normalizePrefix(prefix)
	samples := f.cfg.BaselineSamples
	if samples < 2 {
		samples = 2
	}
	prof := &BaselineProfile{Host: host, Prefix: prefix}
	for i := 0; i < samples; i++ {
		rp, err := randomPath(prefix)
		if err != nil {
			return nil, err
		}
		target := *u
		target.Path = rp
		target.RawQuery = ""
		resp, _, err := doRequest(ctx, target.String())
		if err != nil {
			return nil, err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, f.cfg.MaxBodySample))
		_ = resp.Body.Close()
		fp := fingerprintResponse(resp.StatusCode, body)
		prof.Samples++
		prof.Status = resp.StatusCode
		prof.BodyLen = len(body)
		prof.Entropy = fp.entropy
		prof.TokenCount = fp.tokenCount
		prof.HasAdmin = fp.hasAdmin
		prof.HasJSONList = fp.hasJSONList
		prof.HTMLTagCount = fp.htmlTagCount
		if len(body) > 0 {
			sample := body
			if len(sample) > 8<<10 {
				sample = sample[:8<<10]
			}
			prof.Sample = append([]byte(nil), sample...)
		}
		// If nonexistent random path returns 200 with admin/tokens/endpoints, flag immediately.
		if resp.StatusCode == 200 && (fp.hasAdmin || fp.tokenCount > 0 || fp.hasJSONList && fp.endpointHints > 2) {
			d := DeceptionDecision{Flagged: true, Kind: DeceptionSynthetic200, Host: host, Prefix: prefix, Reason: "nonexistent path returned synthetic 200", Score: 1}
			f.flag(d)
			return prof, nil
		}
	}
	f.mu.Lock()
	f.baselines[baselineKey(host, prefix)] = prof
	f.mu.Unlock()
	return prof, nil
}

func randomPath(prefix string) (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	prefix = normalizePrefix(prefix)
	base := prefix
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	return base + "nonexistent_" + hex.EncodeToString(b[:]), nil
}

type responseFingerprint struct {
	status       int
	bodyLen      int
	entropy      float64
	tokenCount   int
	hasAdmin     bool
	hasJSONList  bool
	endpointHints int
	htmlTagCount int
}

var (
	reToken      = regexp.MustCompile(`(?i)(api[_-]?key|secret|token|password|bearer|session[_-]?id|authorization)["'\s:=]+([A-Za-z0-9_\-\.]{8,})`)
	reEndpoint   = regexp.MustCompile(`(?i)(/api/[\w\-/]+|/admin[\w\-/]*|/internal[\w\-/]*|/graphql\b)`) 
	reAdmin      = regexp.MustCompile(`(?i)(admin panel|dashboard|sign in|api keys?|access token|internal api|swagger|graphql)`) 
	reHTMLTag    = regexp.MustCompile(`<([a-zA-Z][a-zA-Z0-9]*)\b`) 
	reCanaryLike = regexp.MustCompile(`(?i)(canarytoken|oastify|interact\.sh|burpcollaborator|webhook\.site|pipedream)`) 
)

func fingerprintResponse(status int, body []byte) responseFingerprint {
	s := string(body)
	fp := responseFingerprint{status: status, bodyLen: len(body), entropy: shannonEntropy(body)}
	matches := reToken.FindAllStringSubmatch(s, -1)
	fp.tokenCount = len(matches)
	fp.hasAdmin = reAdmin.MatchString(s)
	fp.endpointHints = len(reEndpoint.FindAllString(s, -1))
	fp.htmlTagCount = len(reHTMLTag.FindAllString(s, -1))
	trim := strings.TrimSpace(s)
	fp.hasJSONList = strings.HasPrefix(trim, "[") || (strings.HasPrefix(trim, "{") && strings.Contains(s, "\"endpoints\""))
	return fp
}

func shannonEntropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var freq [256]int
	for _, c := range b {
		freq[c]++
	}
	var ent float64
	n := float64(len(b))
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		ent -= p * math.Log2(p)
	}
	return ent
}

// InspectResponse evaluates a response for deception/tarpit signals. It does not
// close resp.Body; caller should pass a body sample and keep ownership.
func (f *DeceptionFilter) InspectResponse(host, path string, status int, body []byte, latency time.Duration) DeceptionDecision {
	if f == nil || !f.Enabled() {
		return DeceptionDecision{}
	}
	host = strings.ToLower(strings.TrimSpace(host))
	prefix := pathPrefix(path)
	if d, ok := f.IsFlagged(host, prefix); ok {
		return d
	}
	fp := fingerprintResponse(status, body)

	// Quarantine secrets/tokens/paths from response (never auto-reuse).
	f.quarantineFindings(host, path, fp, string(body))

	// Baseline comparison for synthetic 200.
	f.mu.Lock()
	base := f.baselines[baselineKey(host, prefix)]
	if base == nil {
		base = f.baselines[baselineKey(host, "/")]
	}
	f.mu.Unlock()
	if status == 200 && base != nil && base.Status != 200 {
		sim := similarityScore(base, fp)
		if sim >= f.cfg.SimilarityThreshold && (fp.hasAdmin || fp.tokenCount > 0 || fp.endpointHints > 0) {
			d := DeceptionDecision{Flagged: true, Kind: DeceptionSynthetic200, Host: host, Prefix: prefix, Reason: "response matches nonexistent-path baseline with sensitive hints", Score: sim}
			f.flag(d)
			return d
		}
	}
	if status == 200 && (fp.hasAdmin || fp.tokenCount > 0) && looksRandomNotFoundPath(path) {
		d := DeceptionDecision{Flagged: true, Kind: DeceptionSynthetic200, Host: host, Prefix: prefix, Reason: "random nonexistent path returned sensitive 200", Score: 1}
		f.flag(d)
		return d
	}
	if base != nil && len(base.Sample) > 0 && len(body) > 0 {
		ncd := NormalizedCompressionDistance(base.Sample, body)
		if ncd > 0.6 && status == 200 && (fp.hasAdmin || fp.tokenCount > 0 || fp.endpointHints > 0) {
			d := DeceptionDecision{Flagged: true, Kind: DeceptionSynthetic200, Host: host, Prefix: prefix, Reason: "structural anomaly vs baseline (NCD)", Score: ncd}
			f.flag(d)
			return d
		}
	}

	// Repetition / tarpit latency anomaly.
	key := host + "|" + prefix
	f.mu.Lock()
	rs := f.repeats[key]
	if rs == nil {
		rs = &repeatState{}
		f.repeats[key] = rs
	}
	if status == f.cfg.RepeatStatus {
		rs.status = status
		rs.count++
		rs.last = time.Now()
		if len(body) > 0 {
			sample := body
			if len(sample) > 8<<10 {
				sample = sample[:8<<10]
			}
			cp := append([]byte(nil), sample...)
			rs.samples = append(rs.samples, cp)
			if len(rs.samples) > 4 {
				rs.samples = rs.samples[len(rs.samples)-4:]
			}
		}
	} else if status < 400 {
		rs.count = 0
		rs.samples = nil
	}
	repeatCount := rs.count
	samples := append([][]byte(nil), rs.samples...)
	f.mu.Unlock()
	if repeatCount >= f.cfg.RepeatThreshold && (fp.hasAdmin || fp.tokenCount > 0 || fp.endpointHints > 2) {
		d := DeceptionDecision{Flagged: true, Kind: DeceptionRepeat, Host: host, Prefix: prefix, Reason: fmt.Sprintf("repeated status %d with suspicious content", status), Score: float64(repeatCount)}
		f.flag(d)
		return d
	}
	if len(samples) >= 3 && IsDynamicTarpitTemplate(samples, 0.25) && (fp.hasAdmin || fp.tokenCount > 0 || fp.endpointHints > 0) {
		d := DeceptionDecision{Flagged: true, Kind: DeceptionTarpit, Host: host, Prefix: prefix, Reason: "dynamic tarpit template (low NCD)", Score: 1}
		f.flag(d)
		return d
	}
	if latency > 0 && base != nil && base.Samples > 0 {
		// latency degradation heuristic: very slow 200 with synthetic hints.
		if latency > time.Duration(f.cfg.LatencySpikeFactor*float64(time.Second)) && status == 200 && (fp.hasAdmin || fp.endpointHints > 0 || fp.tokenCount > 0) {
			d := DeceptionDecision{Flagged: true, Kind: DeceptionTarpit, Host: host, Prefix: prefix, Reason: "latency spike with synthetic-looking response", Score: latency.Seconds()}
			f.flag(d)
			return d
		}
	}
	return DeceptionDecision{}
}

func pathPrefix(path string) string {
	if path == "" {
		return "/"
	}
	if i := strings.Index(path, "?"); i >= 0 {
		path = path[:i]
	}
	segs := strings.Split(strings.Trim(path, "/"), "/")
	if len(segs) == 0 || segs[0] == "" {
		return "/"
	}
	if len(segs) == 1 {
		return "/" + segs[0]
	}
	return "/" + segs[0] + "/" + segs[1]
}

func looksRandomNotFoundPath(path string) bool {
	p := strings.ToLower(path)
	return strings.Contains(p, "nonexistent_") || strings.Contains(p, "does-not-exist") || strings.Contains(p, "__omnislash_probe__")
}

func similarityScore(base *BaselineProfile, fp responseFingerprint) float64 {
	if base == nil {
		return 0
	}
	score := 0.0
	weights := 0.0
	// status
	weights += 0.25
	if base.Status == fp.status {
		score += 0.25
	}
	// length proximity
	weights += 0.25
	if base.BodyLen > 0 {
		ratio := float64(fp.bodyLen) / float64(base.BodyLen)
		if ratio > 1 {
			ratio = 1 / ratio
		}
		score += 0.25 * ratio
	}
	// entropy proximity
	weights += 0.25
	entDen := math.Max(base.Entropy, fp.entropy)
	if entDen > 0 {
		ratio := math.Min(base.Entropy, fp.entropy) / entDen
		score += 0.25 * ratio
	}
	// structure hints
	weights += 0.25
	structScore := 0.0
	if base.HasAdmin == fp.hasAdmin {
		structScore += 0.4
	}
	if base.HasJSONList == fp.hasJSONList {
		structScore += 0.3
	}
	if base.HTMLTagCount > 0 && fp.htmlTagCount > 0 {
		ratio := float64(fp.htmlTagCount) / float64(base.HTMLTagCount)
		if ratio > 1 {
			ratio = 1 / ratio
		}
		structScore += 0.3 * ratio
	} else if base.HTMLTagCount == 0 && fp.htmlTagCount == 0 {
		structScore += 0.3
	}
	score += 0.25 * structScore
	if weights == 0 {
		return 0
	}
	return score / weights
}

func (f *DeceptionFilter) quarantineFindings(host, path string, fp responseFingerprint, body string) {
	if f == nil || !f.cfg.QuarantineSecrets {
		return
	}
	now := time.Now()
	add := func(kind, value string) {
		value = strings.TrimSpace(value)
		if value == "" || len(value) > 512 {
			return
		}
		// do not auto-reuse; mark unverified
		key := kind + "|" + value
		f.mu.Lock()
		defer f.mu.Unlock()
		if existing, ok := f.quarantine[key]; ok {
			// duplicate across endpoints - keep unverified, don't promote
			if existing.Source != path {
				existing.Kind = kind
			}
			f.quarantine[key] = existing
			return
		}
		f.quarantine[key] = QuarantinedSecret{Value: value, Kind: kind, Source: path, Host: host, FirstSeen: now, Verified: false}
	}
	for _, m := range reToken.FindAllStringSubmatch(body, -1) {
		if len(m) > 2 {
			add("token", m[2])
		}
	}
	for _, ep := range reEndpoint.FindAllString(body, -1) {
		add("path", ep)
	}
	if reCanaryLike.MatchString(body) {
		add("canary_hint", "canary_pattern")
	}
	_ = fp
}

// Quarantined returns a snapshot of quarantined secrets/paths. Values are
// unverified by default and MUST NOT be auto-reused.
func (f *DeceptionFilter) Quarantined() []QuarantinedSecret {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]QuarantinedSecret, 0, len(f.quarantine))
	for _, v := range f.quarantine {
		out = append(out, v)
	}
	return out
}

// ShouldBlock returns true when host/prefix is flagged and action is not mark-only.
func (f *DeceptionFilter) ShouldBlock(host, prefix string) (DeceptionDecision, bool) {
	d, ok := f.IsFlagged(host, prefix)
	if !ok {
		return DeceptionDecision{}, false
	}
	action := strings.ToLower(strings.TrimSpace(f.cfg.Action))
	if action == "mark" {
		return d, false
	}
	return d, true
}

// InspectHTTPResponse samples resp.Body, evaluates deception, and restores the
// body for downstream consumers. It returns the decision and any read error.
func (f *DeceptionFilter) InspectHTTPResponse(resp *http.Response, latency time.Duration) (DeceptionDecision, error) {
	if f == nil || !f.Enabled() || resp == nil || resp.Request == nil || resp.Request.URL == nil {
		return DeceptionDecision{}, nil
	}
	host := resp.Request.URL.Hostname()
	path := resp.Request.URL.Path
	max := f.cfg.MaxBodySample
	if max <= 0 {
		max = 64 << 10
	}
	var sample []byte
	if resp.Body != nil {
		var err error
		sample, err = io.ReadAll(io.LimitReader(resp.Body, max))
		if err != nil {
			_ = resp.Body.Close()
			return DeceptionDecision{}, err
		}
		rest := resp.Body
		resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(sample), rest))
	}
	d := f.InspectResponse(host, path, resp.StatusCode, sample, latency)
	return d, nil
}

// NormalizedCompressionDistance computes NCD using zlib compression.
// NCD(x,y) = (C(xy)-min(C(x),C(y))) / max(C(x),C(y))
func NormalizedCompressionDistance(a, b []byte) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 0
	}
	ca := compressedLen(a)
	cb := compressedLen(b)
	var ab []byte
	ab = append(ab, a...)
	ab = append(ab, b...)
	cab := compressedLen(ab)
	minC := ca
	maxC := cb
	if cb < minC {
		minC = cb
	}
	if ca > maxC {
		maxC = ca
	}
	if maxC == 0 {
		return 0
	}
	ncd := float64(cab-minC) / float64(maxC)
	if ncd < 0 {
		return 0
	}
	if ncd > 1 {
		return 1
	}
	return ncd
}

func compressedLen(b []byte) int {
	var buf bytes.Buffer
	zw, err := zlib.NewWriterLevel(&buf, zlib.BestSpeed)
	if err != nil {
		return len(b)
	}
	_, _ = zw.Write(b)
	_ = zw.Close()
	return buf.Len()
}

// IsDynamicTarpitTemplate returns true when responses are highly similar by NCD
// (<threshold, default 0.25), indicating same template with dynamic tokens/timestamps.
func IsDynamicTarpitTemplate(samples [][]byte, threshold float64) bool {
	if len(samples) < 2 {
		return false
	}
	if threshold <= 0 {
		threshold = 0.25
	}
	for i := 0; i < len(samples)-1; i++ {
		ncd := NormalizedCompressionDistance(samples[i], samples[i+1])
		if ncd >= threshold {
			return false
		}
	}
	return true
}

// IsStructuralAnomaly returns true when NCD between baseline and sample exceeds
// threshold (default 0.6), indicating structural shift.
func IsStructuralAnomaly(baseline, sample []byte, threshold float64) bool {
	if threshold <= 0 {
		threshold = 0.6
	}
	return NormalizedCompressionDistance(baseline, sample) > threshold
}
