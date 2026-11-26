package omnislash

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Proxy is one upstream HTTP CONNECT, HTTPS CONNECT or SOCKS5 endpoint.
//
// Proxy values are safe for concurrent use. The exported address fields must
// not be mutated after the proxy has been added to a Pool.
type Proxy struct {
	Scheme   string
	Addr     string
	Username string
	Password string

	limiter *tokenBucket

	mu            sync.Mutex
	disabled      bool
	alive         bool
	checked       bool
	cooldownUntil time.Time
	failures      int
	lastError     string
	lastChecked   time.Time
	latency       time.Duration
	egressIP      string
	egressLatency time.Duration

	uses          atomic.Uint64
	successes     atomic.Uint64
	failuresTotal atomic.Uint64
	bans          atomic.Uint64
	inflight      atomic.Int64
	lastUsedUnix  atomic.Int64

	// Echelon 3 pool stratification and tail-latency control.
	latencySamples []time.Duration
	p90Latency     time.Duration
	admissionMode  string
	lastBan        time.Time
}

// Proxy tiers. Sniper proxies are reserved for final synchronized series and
// cross-proxy verification; Infantry handles background OSINT/calibration.
const (
	TierInfantry = "infantry"
	TierSniper   = "sniper"

	// Aliases matching the architecture vocabulary.
	InfantryTier = TierInfantry
	SniperTier   = TierSniper
)

const (
	maxLatencySamples = 64
	sniperIQR         = 20 * time.Millisecond
	banWindow         = time.Hour
	infantryFloor     = 300 * time.Millisecond
)

// NewProxy parses a proxy URL. If raw has no scheme, defaultScheme is used.
// Empty lines and comments are rejected; ParseProxyList skips them.
func NewProxy(raw, defaultScheme string) (*Proxy, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("empty proxy URL")
	}
	if !strings.Contains(raw, "://") {
		if defaultScheme == "" {
			defaultScheme = "socks5"
		}
		raw = defaultScheme + "://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse proxy URL: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q", u.Scheme)
	}
	host := u.Hostname()
	port := u.Port()
	if host == "" || port == "" {
		return nil, fmt.Errorf("proxy URL must include host and port")
	}
	pn, err := strconv.Atoi(port)
	if err != nil || pn < 1 || pn > 65535 {
		return nil, fmt.Errorf("invalid proxy port %q", port)
	}
	if u.Path != "" && u.Path != "/" {
		return nil, fmt.Errorf("proxy URL must not contain a path")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("proxy URL must not contain query or fragment")
	}
	p := &Proxy{
		Scheme: scheme,
		Addr:   net.JoinHostPort(host, port),
	}
	if u.User != nil {
		p.Username = u.User.Username()
		p.Password, _ = u.User.Password()
	}
	return p, nil
}

// Label returns a log-safe representation without the password.
func (p *Proxy) Label() string {
	if p.Username != "" || p.Password != "" {
		return fmt.Sprintf("%s://%s:***@%s", p.Scheme, p.Username, p.Addr)
	}
	return p.Scheme + "://" + p.Addr
}

func (p *Proxy) key() string {
	return strings.Join([]string{p.Scheme, p.Addr, p.Username, p.Password}, "\x00")
}

// String returns the proxy as a URL including credentials. Use Label for logs.
func (p *Proxy) String() string {
	u := &url.URL{Scheme: p.Scheme, Host: p.Addr}
	if p.Username != "" || p.Password != "" {
		u.User = url.UserPassword(p.Username, p.Password)
	}
	return u.String()
}

// ParseProxyList reads one proxy per line from r. Blank lines and lines
// starting with '#' are ignored. Duplicate endpoints are removed.
func ParseProxyList(r io.Reader, defaultScheme string) ([]*Proxy, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	var out []*Proxy
	seen := make(map[string]struct{})
	for lineNo := 1; sc.Scan(); lineNo++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p, err := NewProxy(line, defaultScheme)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		if _, ok := seen[p.key()]; ok {
			continue
		}
		seen[p.key()] = struct{}{}
		out = append(out, p)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read proxy list: %w", err)
	}
	if len(out) == 0 {
		return nil, errors.New("proxy list is empty")
	}
	return out, nil
}

// LoadProxyFile opens path and parses it with ParseProxyList.
func LoadProxyFile(path, defaultScheme string) ([]*Proxy, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open proxy list: %w", err)
	}
	defer f.Close()
	proxies, err := ParseProxyList(f, defaultScheme)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return proxies, nil
}

// EgressIP returns the egress address recorded by the last successful
// validation, or an empty string when the proxy was never validated. It is the
// only way to attribute a probe result to an exit IP without an extra request.
func (p *Proxy) EgressIP() string {
	if p == nil {
		return ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.egressIP
}

func (p *Proxy) available(now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.disabled && (p.cooldownUntil.IsZero() || !now.Before(p.cooldownUntil))
}

func (p *Proxy) acquire(ctx context.Context) error {
	if p.limiter != nil {
		if err := p.limiter.wait(ctx); err != nil {
			return err
		}
	}
	p.inflight.Add(1)
	p.lastUsedUnix.Store(time.Now().UnixNano())
	return nil
}

func (p *Proxy) release() { p.inflight.Add(-1) }

func (p *Proxy) markSuccess(now time.Time, latency time.Duration) {
	p.successes.Add(1)
	p.mu.Lock()
	p.failures = 0
	p.cooldownUntil = time.Time{}
	p.alive = true
	p.checked = true
	p.lastChecked = now
	p.lastError = ""
	if latency > 0 {
		if p.latency == 0 {
			p.latency = latency
		} else {
			p.latency = time.Duration(float64(p.latency)*0.8 + float64(latency)*0.2)
		}
		p.latencySamples = append(p.latencySamples, latency)
		if len(p.latencySamples) > maxLatencySamples {
			p.latencySamples = p.latencySamples[len(p.latencySamples)-maxLatencySamples:]
		}
		p.p90Latency = percentileDuration(p.latencySamples, 0.90)
	}
	p.mu.Unlock()
}

func (p *Proxy) markFailure(now time.Time, err error, cfg CooldownConfig) {
	p.failuresTotal.Add(1)
	if err == nil {
		err = errors.New("unknown error")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.failLocked(now, err, cfg)
}

func (p *Proxy) markHealthFailure(now time.Time, err error, cfg CooldownConfig) {
	p.failuresTotal.Add(1)
	if err == nil {
		err = errors.New("unknown error")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.checked = true
	p.lastChecked = now
	p.failLocked(now, err, cfg)
}

func (p *Proxy) failLocked(now time.Time, err error, cfg CooldownConfig) {
	p.failures++
	p.alive = false
	p.lastError = err.Error()
	if p.failures < cfg.FailuresBeforeCooldown {
		return
	}
	delay := time.Duration(cfg.Initial)
	for i := 1; i < p.failures; i++ {
		f := float64(delay) * cfg.Multiplier
		if f >= float64(cfg.Max) {
			delay = time.Duration(cfg.Max)
			break
		}
		delay = time.Duration(f)
	}
	if delay > time.Duration(cfg.Max) {
		delay = time.Duration(cfg.Max)
	}
	until := now.Add(delay)
	if until.After(p.cooldownUntil) {
		p.cooldownUntil = until
	}
}

func (p *Proxy) markBan(now time.Time, reason string, cooldown time.Duration) {
	p.failuresTotal.Add(1)
	p.bans.Add(1)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.failures++
	p.alive = false
	p.lastBan = now
	p.lastError = "banned: " + reason
	until := now.Add(cooldown)
	if until.After(p.cooldownUntil) {
		p.cooldownUntil = until
	}
}

// addLatencySample records one successful raw admission round. The samples feed
// the IQR gate used by SniperTier; they are latency observations, not target
// responses, so they never affect the WAF/learning outcome of a probe.
func (p *Proxy) addLatencySample(latency time.Duration) {
	if p == nil || latency <= 0 {
		return
	}
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.latency == 0 {
		p.latency = latency
	} else {
		p.latency = time.Duration(float64(p.latency)*0.8 + float64(latency)*0.2)
	}
	p.latencySamples = append(p.latencySamples, latency)
	if len(p.latencySamples) > maxLatencySamples {
		p.latencySamples = p.latencySamples[len(p.latencySamples)-maxLatencySamples:]
	}
	p.p90Latency = percentileDuration(p.latencySamples, 0.90)
	if !p.alive {
		p.alive = true
	}
	if !p.checked {
		p.checked = true
	}
	if p.lastChecked.IsZero() {
		p.lastChecked = now
	}
}

// setAdmissionMode records which admission suite this proxy passed.
func (p *Proxy) setAdmissionMode(mode string) {
	p.mu.Lock()
	p.admissionMode = mode
	p.mu.Unlock()
}

// AdmissionMode returns the admission suite the proxy passed, if known.
func (p *Proxy) AdmissionMode() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.admissionMode
}

// P90Latency returns the rolling 90th percentile latency.
func (p *Proxy) P90Latency() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.p90Latency > 0 {
		return p.p90Latency
	}
	return p.latency
}

// P75Latency returns the rolling 75th percentile latency. Hedged dials use it
// as the moment to launch a backup exit.
func (p *Proxy) P75Latency() time.Duration {
	p.mu.Lock()
	samples := append([]time.Duration(nil), p.latencySamples...)
	fallback := p.latency
	p.mu.Unlock()
	if len(samples) == 0 {
		return fallback
	}
	sortDurations(samples)
	return percentileDuration(samples, 0.75)
}

// IQR returns the interquartile range of recent latency samples.
func (p *Proxy) IQR() time.Duration {
	p.mu.Lock()
	samples := append([]time.Duration(nil), p.latencySamples...)
	p.mu.Unlock()
	if len(samples) < 2 {
		return 0
	}
	sortDurations(samples)
	q1 := percentileDuration(samples, 0.25)
	q3 := percentileDuration(samples, 0.75)
	if q3 < q1 {
		return 0
	}
	return q3 - q1
}

// AdaptiveTimeout is the tail-latency cut used for Infantry background checks:
// max(1.5 * p90, 300ms).
func (p *Proxy) AdaptiveTimeout() time.Duration {
	p90 := p.P90Latency()
	if p90 <= 0 {
		return infantryFloor
	}
	t := time.Duration(float64(p90) * 1.5)
	if t < infantryFloor {
		t = infantryFloor
	}
	return t
}

// Tier classifies the proxy for scheduling. Sniper requires http_parsing
// admission, IQR < 20ms and no ban in the last hour.
func (p *Proxy) Tier() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.tierLocked(time.Now())
}

func (p *Proxy) tierLocked(now time.Time) string {
	if p.disabled || !p.alive {
		return TierInfantry
	}
	if p.admissionMode != AdmissionModeHTTPParsing {
		return TierInfantry
	}
	if len(p.latencySamples) < 3 || p.p90Latency <= 0 {
		return TierInfantry
	}
	if p.iqrLocked() >= sniperIQR {
		return TierInfantry
	}
	if !p.lastBan.IsZero() && now.Sub(p.lastBan) < banWindow {
		return TierInfantry
	}
	return TierSniper
}

func (p *Proxy) iqrLocked() time.Duration {
	samples := append([]time.Duration(nil), p.latencySamples...)
	if len(samples) < 2 {
		return 0
	}
	sortDurations(samples)
	q1 := percentileDuration(samples, 0.25)
	q3 := percentileDuration(samples, 0.75)
	if q3 < q1 {
		return 0
	}
	return q3 - q1
}

func sortDurations(v []time.Duration) {
	for i := 1; i < len(v); i++ {
		for j := i; j > 0 && v[j] < v[j-1]; j-- {
			v[j], v[j-1] = v[j-1], v[j]
		}
	}
}

func percentileDuration(sorted []time.Duration, q float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	if len(sorted) == 1 {
		return sorted[0]
	}
	pos := q * float64(len(sorted)-1)
	lo := int(pos)
	hi := lo + 1
	if hi >= len(sorted) {
		return sorted[len(sorted)-1]
	}
	frac := pos - float64(lo)
	return time.Duration(float64(sorted[lo]) + frac*float64(sorted[hi]-sorted[lo]))
}

func (p *Proxy) setDisabled(v bool) {
	p.mu.Lock()
	p.disabled = v
	p.mu.Unlock()
}

// setEgress records the public address observed by the validator.
func (p *Proxy) setEgress(ip string, latency time.Duration) {
	p.mu.Lock()
	p.egressIP = ip
	p.egressLatency = latency
	p.mu.Unlock()
}

// ProxyStats is a point-in-time view of a single proxy.
type ProxyStats struct {
	Proxy               string     `json:"proxy"`
	Scheme              string     `json:"scheme"`
	Addr                string     `json:"addr"`
	Available           bool       `json:"available"`
	Alive               bool       `json:"alive"`
	Checked             bool       `json:"checked"`
	Disabled            bool       `json:"disabled"`
	InCooldown          bool       `json:"in_cooldown"`
	CooldownUntil       *time.Time `json:"cooldown_until,omitempty"`
	ConsecutiveFailures int        `json:"consecutive_failures"`
	Successes           uint64     `json:"successes"`
	Failures            uint64     `json:"failures"`
	Bans                uint64     `json:"bans"`
	Uses                uint64     `json:"uses"`
	Inflight            int64      `json:"inflight"`
	LatencyMS           float64    `json:"latency_ms"`
	EgressIP            string     `json:"egress_ip,omitempty"`
	ValidationLatencyMS float64    `json:"validation_latency_ms,omitempty"`
	LastError           string     `json:"last_error,omitempty"`
	LastChecked         *time.Time `json:"last_checked,omitempty"`
	LastUsed            *time.Time `json:"last_used,omitempty"`
}

func (p *Proxy) stats(now time.Time) ProxyStats {
	p.mu.Lock()
	s := ProxyStats{
		Proxy:               p.Label(),
		Scheme:              p.Scheme,
		Addr:                p.Addr,
		Available:           !p.disabled && (p.cooldownUntil.IsZero() || !now.Before(p.cooldownUntil)),
		Alive:               p.alive,
		Checked:             p.checked,
		Disabled:            p.disabled,
		InCooldown:          !p.cooldownUntil.IsZero() && now.Before(p.cooldownUntil),
		ConsecutiveFailures: p.failures,
		Successes:           p.successes.Load(),
		Failures:            p.failuresTotal.Load(),
		Bans:                p.bans.Load(),
		Uses:                p.uses.Load(),
		Inflight:            p.inflight.Load(),
		LatencyMS:           float64(p.latency.Microseconds()) / 1000,
		EgressIP:            p.egressIP,
		ValidationLatencyMS: float64(p.egressLatency.Microseconds()) / 1000,
		LastError:           p.lastError,
	}
	if !p.cooldownUntil.IsZero() {
		t := p.cooldownUntil
		s.CooldownUntil = &t
	}
	if !p.lastChecked.IsZero() {
		t := p.lastChecked
		s.LastChecked = &t
	}
	if ns := p.lastUsedUnix.Load(); ns != 0 {
		t := time.Unix(0, ns)
		s.LastUsed = &t
	}
	p.mu.Unlock()
	return s
}
