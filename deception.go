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

var (
	ErrDeceptionDetected = errors.New("omnislash: deception/tarpit detected")
	ErrDeceptionBaseline = errors.New("omnislash: deception baseline unavailable")
)

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
	Flagged    bool          `json:"flagged"`
	Kind       DeceptionKind `json:"kind,omitempty"`
	Host       string        `json:"host,omitempty"`
	Prefix     string        `json:"prefix,omitempty"`
	Reason     string        `json:"reason,omitempty"`
	Score      float64       `json:"score,omitempty"`
	Quarantine []string      `json:"quarantine,omitempty"`
	// Uncertain means the mandatory semantic/NCD check could not run. The
	// decision is deliberately not a verdict: callers must fail closed and
	// record deception_uncertain instead of treating raw bytes as clean.
	Uncertain bool `json:"uncertain,omitempty"`
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
	// Skeleton is the value-free canonical form used for NCD. It is empty
	// when the loopback semantic service is unavailable or disabled.
	Skeleton string `json:"-"`
}

// DeceptionFilter detects synthetic/tarpit responses and quarantines unverified
// secrets. It is defensive only: it never bypasses deception controls.
type DeceptionFilter struct {
	cfg DeceptionConfig
	log Logger

	now      func() time.Time
	semantic *SemanticClient

	mu          sync.Mutex
	baselines   map[string]*BaselineProfile // host|prefix
	flagged     map[string]DeceptionDecision
	banned      map[string]targetBan // host-wide session ban ("mark")
	calibrating map[string]*calibrationState
	repeats     map[string]*repeatState
	quarantine  map[string]QuarantinedSecret
	semWarned   bool
}

type targetBan struct {
	expires time.Time
	reason  string
	kind    DeceptionKind
}

type calibrationState struct {
	done    chan struct{}
	profile *BaselineProfile
	err     error
}

type repeatState struct {
	status    int
	count     int
	last      time.Time
	samples   [][]byte // raw samples, used to reject identical-body false positives
	skeletons []string // value-free skeletons used by the tarpit NCD branch
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
	if cfg.RepeatWindow <= 0 {
		cfg.RepeatWindow = Duration(10 * time.Second)
	}
	if cfg.NCDTarpit <= 0 {
		cfg.NCDTarpit = 0.25
	}
	if cfg.NCDStructural <= 0 {
		cfg.NCDStructural = 0.6
	}
	if cfg.LatencySpikeFactor <= 0 {
		cfg.LatencySpikeFactor = 4
	}
	if cfg.TargetBanTTL <= 0 {
		cfg.TargetBanTTL = Duration(5 * time.Minute)
	}
	if cfg.SemanticAddr == "" {
		cfg.SemanticAddr = "127.0.0.1:8000"
	}
	if cfg.Action == "" {
		cfg.Action = "cooldown"
	}
	f := &DeceptionFilter{
		cfg:         cfg,
		log:         log,
		now:         time.Now,
		baselines:   make(map[string]*BaselineProfile),
		flagged:     make(map[string]DeceptionDecision),
		banned:      make(map[string]targetBan),
		calibrating: make(map[string]*calibrationState),
		repeats:     make(map[string]*repeatState),
		quarantine:  make(map[string]QuarantinedSecret),
	}
	if cfg.SemanticService {
		client, err := NewSemanticClient(cfg.SemanticAddr)
		if err != nil {
			if log != nil {
				log.Warn("semantic skeleton service disabled", "addr", cfg.SemanticAddr, "error", err)
			}
		} else {
			f.semantic = client
		}
	}
	return f
}

func (f *DeceptionFilter) Enabled() bool { return f != nil && f.cfg.Enabled }

// maxNCDBytes caps the input to zlib. NCD is only a similarity heuristic; there
// is no reason to compress an entire multi-megabyte response on every probe.
const maxNCDBytes = 8 << 10

// bodySkeleton returns a canonical value-free form of a body sample. The Python
// analyzer runs as one loopback child process owned by the caller; no os/exec
// happens here.
//
// When semantic_required is true, an unavailable analyzer is a hard error. The
// caller must fail closed: using raw bytes for NCD in that mode could let a
// honeypot's dynamic body look like a legitimate response.
func (f *DeceptionFilter) bodySkeleton(body []byte, contentType string) ([]byte, error) {
	body = append([]byte(nil), body...)
	if len(body) > maxNCDBytes {
		body = body[:maxNCDBytes]
	}
	if f.semantic == nil {
		if f.cfg.SemanticRequired {
			return nil, fmt.Errorf("%w: semantic service is not configured", ErrDeceptionUncertain)
		}
		return body, nil
	}
	skeleton, err := f.semantic.Skeleton(body, contentType)
	if err != nil {
		f.mu.Lock()
		warn := !f.semWarned
		f.semWarned = true
		f.mu.Unlock()
		if warn && f.log != nil {
			f.log.Warn("semantic skeleton unavailable", "addr", f.cfg.SemanticAddr, "required", f.cfg.SemanticRequired, "error", err)
		}
		if f.cfg.SemanticRequired {
			return nil, fmt.Errorf("%w: %v", ErrDeceptionUncertain, err)
		}
		return body, nil
	}
	if len(skeleton) > maxNCDBytes {
		skeleton = skeleton[:maxNCDBytes]
	}
	return []byte(skeleton), nil
}

// EnsureBaseline runs CalibrateBaseline once per host/prefix before the first
// real probe. Concurrent callers wait for the same calibration instead of
// multiplying control traffic. doRequest MUST use the raw transport path: it
// must not call EnsureBaseline again.
func (f *DeceptionFilter) EnsureBaseline(ctx context.Context, baseURL, prefix string, doRequest func(context.Context, string) (*http.Response, time.Duration, error)) (*BaselineProfile, error) {
	if f == nil || !f.Enabled() || doRequest == nil {
		return nil, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	key := baselineKey(u.Hostname(), prefix)
	f.mu.Lock()
	if st, ok := f.calibrating[key]; ok {
		f.mu.Unlock()
		select {
		case <-st.done:
			return st.profile, st.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	st := &calibrationState{done: make(chan struct{})}
	f.calibrating[key] = st
	f.mu.Unlock()

	profile, err := f.CalibrateBaseline(ctx, baseURL, prefix, doRequest)
	st.profile, st.err = profile, err
	close(st.done)
	return profile, err
}

func baselineKey(host, prefix string) string {
	return strings.ToLower(strings.TrimSpace(host)) + "|" + normalizePrefix(prefix)
}

// baselineFor walks from the most specific known prefix to the host root, so a
// baseline calibrated for /api also applies to /api/users/123.
func (f *DeceptionFilter) baselineFor(host, prefix string) *BaselineProfile {
	f.mu.Lock()
	defer f.mu.Unlock()
	for p := normalizePrefix(prefix); ; p = parentPrefix(p) {
		if base := f.baselines[baselineKey(host, p)]; base != nil {
			return base
		}
		if p == "/" {
			return nil
		}
	}
}

func parentPrefix(p string) string {
	p = strings.TrimRight(p, "/")
	i := strings.LastIndex(p, "/")
	if i <= 0 {
		return "/"
	}
	return p[:i]
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
		skeleton, skErr := f.bodySkeleton(body, resp.Header.Get("Content-Type"))
		if skErr != nil {
			return nil, skErr
		}
		if prof.Skeleton == "" && len(skeleton) > 0 {
			prof.Skeleton = string(skeleton)
		}
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
	status        int
	bodyLen       int
	entropy       float64
	tokenCount    int
	hasAdmin      bool
	hasJSONList   bool
	endpointHints int
	htmlTagCount  int
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
func (f *DeceptionFilter) InspectResponse(host, path string, status int, body []byte, latency time.Duration) (DeceptionDecision, error) {
	return f.InspectResponseWithContentType(host, path, status, body, "", latency)
}

// InspectResponseWithContentType is InspectResponse with the response content
// type, which the semantic analyzer uses to choose JSON vs HTML normalization.
//
// The error is non-nil only when a mandatory semantic check could not run. The
// returned decision then has Uncertain=true and Flagged=false; it is never a
// false positive and never evidence that the response was clean.
func (f *DeceptionFilter) InspectResponseWithContentType(host, path string, status int, body []byte, contentType string, latency time.Duration) (DeceptionDecision, error) {
	if f == nil || !f.Enabled() {
		return DeceptionDecision{}, nil
	}
	host = strings.ToLower(strings.TrimSpace(host))
	prefix := pathPrefix(path)
	if d, ok := f.IsFlagged(host, prefix); ok {
		return d, nil
	}
	fp := fingerprintResponse(status, body)
	skeleton, skErr := f.bodySkeleton(body, contentType)
	if skErr != nil {
		d := DeceptionDecision{Host: host, Prefix: prefix, Reason: skErr.Error(), Uncertain: true}
		return d, skErr
	}

	// Quarantine secrets/tokens/paths from response (never auto-reuse).
	f.quarantineFindings(host, path, fp, string(body))

	// Baseline comparison for synthetic 200.
	base := f.baselineFor(host, prefix)
	if status == 200 && base != nil && base.Status != 200 {
		sim := similarityScore(base, fp)
		if sim >= f.cfg.SimilarityThreshold && (fp.hasAdmin || fp.tokenCount > 0 || fp.endpointHints > 0) {
			d := DeceptionDecision{Flagged: true, Kind: DeceptionSynthetic200, Host: host, Prefix: prefix, Reason: "response matches nonexistent-path baseline with sensitive hints", Score: sim}
			f.flag(d)
			return d, nil
		}
	}
	if status == 200 && (fp.hasAdmin || fp.tokenCount > 0) && looksRandomNotFoundPath(path) {
		d := DeceptionDecision{Flagged: true, Kind: DeceptionSynthetic200, Host: host, Prefix: prefix, Reason: "random nonexistent path returned sensitive 200", Score: 1}
		f.flag(d)
		return d, nil
	}
	if base != nil && len(body) > 0 {
		a, b := base.Sample, body
		if base.Skeleton != "" {
			a, b = []byte(base.Skeleton), skeleton
		}
		if len(a) > 0 && len(b) > 0 {
			ncd := NormalizedCompressionDistance(a, b)
			if ncd > f.cfg.NCDStructural && status == 200 && (fp.hasAdmin || fp.tokenCount > 0 || fp.endpointHints > 0) {
				d := DeceptionDecision{Flagged: true, Kind: DeceptionSynthetic200, Host: host, Prefix: prefix, Reason: "structural shift vs baseline (skeleton NCD)", Score: ncd}
				f.flag(d)
				return d, nil
			}
		}
	}

	// Repetition / tarpit latency anomaly. The window prevents an old burst
	// from poisoning a later, unrelated experiment on the same host.
	key := host + "|" + prefix
	now := f.now()
	window := f.cfg.RepeatWindow.Std()
	if window <= 0 {
		window = 10 * time.Second
	}
	f.mu.Lock()
	rs := f.repeats[key]
	if rs == nil {
		rs = &repeatState{}
		f.repeats[key] = rs
	}
	if now.Sub(rs.last) > window {
		rs.count = 0
		rs.samples = nil
		rs.skeletons = nil
	}
	if status == f.cfg.RepeatStatus {
		rs.status = status
		rs.count++
		rs.last = now
		if len(body) > 0 {
			sample := body
			if len(sample) > maxNCDBytes {
				sample = sample[:maxNCDBytes]
			}
			rs.samples = append(rs.samples, append([]byte(nil), sample...))
			if len(rs.samples) > 4 {
				rs.samples = rs.samples[len(rs.samples)-4:]
			}
			if len(skeleton) > 0 {
				rs.skeletons = append(rs.skeletons, string(skeleton))
				if len(rs.skeletons) > 4 {
					rs.skeletons = rs.skeletons[len(rs.skeletons)-4:]
				}
			}
		}
	} else {
		rs.count = 0
		rs.samples = nil
		rs.skeletons = nil
		rs.last = now
	}
	repeatCount := rs.count
	samples := append([][]byte(nil), rs.samples...)
	skeletons := append([]string(nil), rs.skeletons...)
	f.mu.Unlock()
	if repeatCount >= f.cfg.RepeatThreshold && (fp.hasAdmin || fp.tokenCount > 0 || fp.endpointHints > 2) {
		d := DeceptionDecision{Flagged: true, Kind: DeceptionRepeat, Host: host, Prefix: prefix, Reason: fmt.Sprintf("repeated status %d with suspicious content", status), Score: float64(repeatCount)}
		f.flag(d)
		return d, nil
	}
	// Identical "perfect" responses are a normal cache hit, not a dynamic
	// tarpit. Require at least two different raw samples with a stable
	// value-free skeleton before using the low-NCD tarpit rule.
	if len(skeletons) >= 3 && hasDistinctSamples(samples) && IsDynamicTarpitTemplate(skeletonBytes(skeletons), f.cfg.NCDTarpit) && (fp.hasAdmin || fp.tokenCount > 0 || fp.endpointHints > 0) {
		d := DeceptionDecision{Flagged: true, Kind: DeceptionTarpit, Host: host, Prefix: prefix, Reason: "dynamic tarpit template (low skeleton NCD)", Score: 1}
		f.flag(d)
		return d, nil
	}
	if latency > 0 && base != nil && base.Samples > 0 {
		// latency degradation heuristic: very slow 200 with synthetic hints.
		if latency > time.Duration(f.cfg.LatencySpikeFactor*float64(time.Second)) && status == 200 && (fp.hasAdmin || fp.endpointHints > 0 || fp.tokenCount > 0) {
			d := DeceptionDecision{Flagged: true, Kind: DeceptionTarpit, Host: host, Prefix: prefix, Reason: "latency spike with synthetic-looking response", Score: latency.Seconds()}
			f.flag(d)
			return d, nil
		}
	}
	return DeceptionDecision{}, nil
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

// hasDistinctSamples rejects byte-identical responses from the dynamic tarpit
// rule: a stable legitimate body is not evidence of a deceptive template.
func hasDistinctSamples(samples [][]byte) bool {
	for i := 1; i < len(samples); i++ {
		if !bytes.Equal(samples[0], samples[i]) {
			return true
		}
	}
	return false
}

func skeletonBytes(skeletons []string) [][]byte {
	out := make([][]byte, 0, len(skeletons))
	for _, s := range skeletons {
		out = append(out, []byte(s))
	}
	return out
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

// BanTarget blocks one target in this process for ttl. It is the "mark"
// reaction: the proxy is not blamed and the pool circuit stays healthy.
func (f *DeceptionFilter) BanTarget(host, prefix, reason string, kind DeceptionKind, ttl time.Duration) {
	if f == nil {
		return
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return
	}
	if ttl <= 0 {
		ttl = f.cfg.TargetBanTTL.Std()
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	f.mu.Lock()
	f.banned[host] = targetBan{expires: f.now().Add(ttl), reason: reason, kind: kind}
	f.mu.Unlock()
	if f.log != nil {
		f.log.Warn("deception target banned for session", "host", host, "prefix", prefix, "kind", kind, "ttl", ttl)
	}
}

// TargetBanned reports an active session-level ban. It does not consult the
// proxy pool, so a honeypot can never cool down an innocent exit IP.
func (f *DeceptionFilter) TargetBanned(host string) (DeceptionDecision, bool) {
	if f == nil {
		return DeceptionDecision{}, false
	}
	key := strings.ToLower(strings.TrimSpace(host))
	f.mu.Lock()
	b, ok := f.banned[key]
	if ok && !f.now().Before(b.expires) {
		delete(f.banned, key)
		ok = false
	}
	f.mu.Unlock()
	if !ok {
		return DeceptionDecision{}, false
	}
	return DeceptionDecision{Flagged: true, Kind: b.kind, Host: host, Reason: b.reason, Score: 1}, true
}

// ShouldBlock returns true for an active target ban, or when host/prefix is
// flagged and the configured action blocks. "mark" only records a flag, but its
// explicit BanTarget still blocks that one target without touching the pool.
func (f *DeceptionFilter) ShouldBlock(host, prefix string) (DeceptionDecision, bool) {
	if d, ok := f.TargetBanned(host); ok {
		return d, true
	}
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
	return f.InspectResponseWithContentType(host, path, resp.StatusCode, sample, resp.Header.Get("Content-Type"), latency)
}

// NormalizedCompressionDistance computes NCD using zlib compression.
// NCD(x,y) = (C(xy)-min(C(x),C(y))) / max(C(x),C(y))
func NormalizedCompressionDistance(a, b []byte) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 0
	}
	// zlib's per-stream header/trailer makes C(aa) larger than 2*C(a) for
	// short inputs. Without this guard identical "perfect" bodies get a false
	// high NCD and trip the structural anomaly branch.
	if bytes.Equal(a, b) {
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
