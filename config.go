package omnislash

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/bogdanfinn/tls-client/profiles"
)

// Duration is a JSON-friendly time.Duration. It accepts Go duration strings
// ("15s", "2m") and integers interpreted as nanoseconds.
type Duration time.Duration

// Std returns the value as time.Duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

func (d Duration) String() string { return time.Duration(d).String() }

// MarshalJSON encodes the duration as a Go duration string.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// UnmarshalJSON decodes a Go duration string or an integer number of
// nanoseconds.
func (d *Duration) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		*d = 0
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		if s == "" {
			*d = 0
			return nil
		}
		v, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("invalid duration %q: %w", s, err)
		}
		*d = Duration(v)
		return nil
	}
	var n int64
	if err := json.Unmarshal(b, &n); err != nil {
		return fmt.Errorf("duration must be a string or nanoseconds: %w", err)
	}
	*d = Duration(n)
	return nil
}

// Config controls the proxy pool, dialer, HTTP transport, health checker,
// local gateway and stats endpoint.
type Config struct {
	DefaultScheme      string          `json:"default_scheme"`
	Strategy           string          `json:"strategy"`
	TrustTier          string          `json:"trust_tier"`
	AllowDirect        bool            `json:"allow_direct"`
	StickyTTL          Duration        `json:"sticky_ttl"`
	DialTimeout        Duration        `json:"dial_timeout"`
	HandshakeTimeout   Duration        `json:"handshake_timeout"`
	MaxDialAttempts    int             `json:"max_dial_attempts"`
	ProxyTLSSkipVerify bool            `json:"proxy_tls_skip_verify"`
	Cooldown           CooldownConfig  `json:"cooldown"`
	Health             HealthConfig    `json:"health"`
	HTTP               HTTPConfig      `json:"http"`
	Probe              ProbeConfig     `json:"probe"`
	Stats              StatsConfig     `json:"stats"`
	Gateway            GatewayConfig   `json:"gateway"`
	RateLimit          RateLimitConfig `json:"rate_limit"`
	Safety             SafetyConfig    `json:"safety"`
	Audit              AuditConfig     `json:"audit"`
	Scope              ScopeConfig     `json:"scope"`
	Scraper            ScraperConfig   `json:"scraper"`
	LogLevel           string          `json:"log_level"`
	// OnlineLearning starts the streaming feedback loop next to the control
	// UI. Nil means enabled; set false to keep serve read-only.
	OnlineLearning *bool `json:"online_learning,omitempty"`
	// TLSFingerprints are the ClientHello profiles rotated per Session. Nil
	// means the defaults (Chrome/iOS/OkHttp); an explicit empty array disables
	// fingerprinting and keeps crypto/tls for compatibility.
	TLSFingerprints []string `json:"tls_fingerprints,omitempty"`
}

// IsOnlineLearningEnabled reports whether the streaming feedback loop should
// be started. Nil means enabled so existing configs need no change.
func (c *Config) IsOnlineLearningEnabled() bool {
	return c == nil || c.OnlineLearning == nil || *c.OnlineLearning
}

// CooldownConfig controls exponential backoff after proxy failures.
type CooldownConfig struct {
	Initial                Duration `json:"initial"`
	Max                    Duration `json:"max"`
	Multiplier             float64  `json:"multiplier"`
	FailuresBeforeCooldown int      `json:"failures_before_cooldown"`
}

// HealthConfig controls periodic proxy probes.
type HealthConfig struct {
	Enabled       bool     `json:"enabled"`
	Interval      Duration `json:"interval"`
	Timeout       Duration `json:"timeout"`
	Concurrency   int      `json:"concurrency"`
	ProbeURL      string   `json:"probe_url"`
	StartupCheck  bool     `json:"startup_check"`
	StartupWait   Duration `json:"startup_wait"`
	TLSSkipVerify bool     `json:"tls_skip_verify"`
}

// HTTPConfig controls the rotating net/http transport.
type HTTPConfig struct {
	Timeout             Duration `json:"timeout"`
	MaxRetries          int      `json:"max_retries"`
	BanStatuses         []int    `json:"ban_statuses"`
	BanCooldown         Duration `json:"ban_cooldown"`
	MaxIdleConns        int      `json:"max_idle_conns"`
	MaxIdleConnsPerHost int      `json:"max_idle_conns_per_host"`
	IdleConnTimeout     Duration `json:"idle_conn_timeout"`
	TLSHandshakeTimeout Duration `json:"tls_handshake_timeout"`
	MaxBodyBuffer       int64    `json:"max_body_buffer"`
	TLSSkipVerify       bool     `json:"tls_skip_verify"`
}

// ProbeConfig bounds the byte-exact probe engine. The limits are enforced by
// probe.Runner on every raw connection, independently of net/http.
//
// RaceReadTimeout is deliberately separate: race probes measure scheduling
// windows, so their per-read deadline must not change between runs. It is fixed
// at 1500 ms by default and must not be derived from a per-job timeout.
type ProbeConfig struct {
	MaxResponseBytes int64    `json:"max_response_bytes"`
	ReadTimeout      Duration `json:"read_timeout"`
	RaceReadTimeout  Duration `json:"race_read_timeout"`
}

// StatsConfig controls the optional JSON stats HTTP endpoint.
type StatsConfig struct {
	Listen string `json:"listen"`
}

// GatewayConfig controls the local rotating CONNECT proxy.
type GatewayConfig struct {
	Listen         string `json:"listen"`
	Token          string `json:"token"`
	ProxyPinHeader string `json:"proxy_pin_header,omitempty"` // debug/audit only: pin requests to proxy label for Replay
}

// RateLimitConfig enables token buckets. PerProxyRPS limits each upstream
// proxy; GlobalRPS limits the whole pool regardless of rotation. Zero disables
// the corresponding limiter. A safe scanning profile sets global_rps to 4 and
// global_burst to 1 so proxy rotation cannot multiply the effective rate.
type RateLimitConfig struct {
	PerProxyRPS float64 `json:"per_proxy_rps"`
	Burst       int     `json:"burst"`
	GlobalRPS   float64 `json:"global_rps"`
	GlobalBurst int     `json:"global_burst"`
}

// SafetyConfig stops all traffic when the target starts rejecting the scan.
// Statuses are counted in a sliding window; reaching Threshold trips the
// breaker for Cooldown. MaxRequests is an optional hard request budget; zero
// means unlimited. The breaker is fail-closed: while open, every dial and HTTP
// request is refused instead of rotating to another proxy.
type SafetyConfig struct {
	Enabled        bool                 `json:"enabled"`
	StopStatuses   []int                `json:"stop_statuses"`
	Threshold      int                  `json:"threshold"`
	Window         Duration             `json:"window"`
	Cooldown       Duration             `json:"cooldown"`
	MaxRequests    int64                `json:"max_requests"`
	TargetCooldown TargetCooldownConfig `json:"target_cooldown"`
	Deception      DeceptionConfig      `json:"deception"`
}

// TargetCooldownConfig pauses one target after a burst of block responses that
// arrived through independent exit IPs. A single 429 is normal rate limiting
// and must never stop a scan; the threshold and the distinct-proxy requirement
// are what separate a target-wide block from one noisy proxy.
type TargetCooldownConfig struct {
	Enabled            bool     `json:"enabled"`
	Statuses           []int    `json:"statuses"`
	Threshold          int      `json:"threshold"`
	Window             Duration `json:"window"`
	Cooldown           Duration `json:"cooldown"`
	MinDistinctProxies int      `json:"min_distinct_proxies"`
}

// DeceptionConfig enables defensive response-side filtering for tarpit/deception
// targets. It never bypasses deception; it detects and excludes/quarantines.
type DeceptionConfig struct {
	Enabled             bool     `json:"enabled"`
	BaselineSamples     int      `json:"baseline_samples"`
	MaxBodySample       int64    `json:"max_body_sample"`
	SimilarityThreshold float64  `json:"similarity_threshold"`
	RepeatStatus        int      `json:"repeat_status"`
	RepeatThreshold     int      `json:"repeat_threshold"`
	RepeatWindow        Duration `json:"repeat_window"` // default 10s
	LatencySpikeFactor  float64  `json:"latency_spike_factor"`
	NCDTarpit           float64  `json:"ncd_tarpit"`     // default 0.25
	NCDStructural       float64  `json:"ncd_structural"` // default 0.6
	QuarantineSecrets   bool     `json:"quarantine_secrets"`
	Action              string   `json:"action"` // "cooldown" | "disable" | "mark"
	// SemanticService uses the loopback Python skeleton service so NCD runs on
	// value-free canonical skeletons instead of raw dynamic bodies. When it is
	// unavailable the filter falls back to the sampled bytes.
	SemanticService bool `json:"semantic_service"`
	// SemanticRequired fails closed when the skeleton service is unavailable:
	// the response is marked deception_uncertain and the probe is refused
	// instead of running NCD on raw bytes that a honeypot may have chosen.
	SemanticRequired bool   `json:"semantic_required"`
	SemanticAddr     string `json:"semantic_addr"` // loopback only, default 127.0.0.1:8000
	// TargetBanTTL bounds a session-level target ban created by "mark".
	TargetBanTTL Duration `json:"target_ban_ttl"` // default 5m
}

// AuditConfig writes one JSON object per event to Path. Path "-" means stdout.
// The audit log contains method, target, status, proxy label and reason, never
// request or response bodies.
type AuditConfig struct {
	Enabled bool   `json:"enabled"`
	Path    string `json:"path"`
}

// ScopeConfig is a fail-closed target allowlist for the dialer and gateway.
// When enabled, a target must match allow_hosts or allow_cidrs, its port must
// match allow_ports (when non-empty), and every resolved address must not be
// private, loopback, link-local or cloud metadata. Cloud metadata addresses are
// always denied, even with allow_private.
//
// Hostnames are always resolved locally when scope is enabled so an untrusted
// proxy cannot rebind an approved name to an internal address. resolve_locally
// additionally pins the first validated literal IP as the CONNECT target.
type ScopeConfig struct {
	Enabled        bool     `json:"enabled"`
	AllowHosts     []string `json:"allow_hosts"`
	AllowCIDRs     []string `json:"allow_cidrs"`
	AllowPorts     []int    `json:"allow_ports"`
	AllowPrivate   bool     `json:"allow_private"`
	DenyCIDRs      []string `json:"deny_cidrs"`
	ResolveLocally bool     `json:"resolve_locally"`
	DNSCacheTTL    Duration `json:"dns_cache_ttl"`
	DNSTimeout     Duration `json:"dns_timeout"`
}

// SourceConfig describes one proxy-list source. Type is "text" (one proxy per
// line) or "regex" (extract matches from an HTML/JSON/text page). For regex
// sources the first capture group is used when present, otherwise the whole
// match. Scheme overrides the scheme used for entries without one.
type SourceConfig struct {
	Name    string            `json:"name,omitempty"`
	URL     string            `json:"url"`
	Type    string            `json:"type,omitempty"`
	Regex   string            `json:"regex,omitempty"`
	Scheme  string            `json:"scheme,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

// ValidationConfig controls strict verification of scraped proxies. A proxy is
// accepted only if it can reach enough HTTPS canaries, return the same public
// egress IP, and (optionally) that IP differs from the scanner's real IP.
// TLS certificates are verified unless TLSSkipVerify is explicitly enabled.
//
// Mode selects the admission suite. "connect" verifies an opaque CONNECT
// tunnel, the target certificate and a paused long-lived connection.
// "http_parsing" additionally/proactively verifies exact HTTP framing bytes
// through the tunnel, which is what an HTTP-parsing consumer needs. Both modes
// use raw sockets; net/http never sees target bytes.
type ValidationConfig struct {
	Enabled                   bool            `json:"enabled"`
	Mode                      string          `json:"mode"`
	Admission                 AdmissionConfig `json:"admission"`
	CanaryURLs                []string        `json:"canary_urls"`
	RealIPURL                 string          `json:"real_ip_url"`
	RealIP                    string          `json:"real_ip,omitempty"`
	Timeout                   Duration        `json:"timeout"`
	Concurrency               int             `json:"concurrency"`
	Attempts                  int             `json:"attempts"`
	MinCanaries               int             `json:"min_canaries"`
	RequireSameEgressIP       bool            `json:"require_same_egress_ip"`
	RequireDistinctFromRealIP bool            `json:"require_distinct_from_real_ip"`
	MaxLatency                Duration        `json:"max_latency"`
	TLSSkipVerify             bool            `json:"tls_skip_verify"`
	AllowPrivateEgress        bool            `json:"allow_private_egress"`
	// Profile is a bogdanfinn/tls-client fingerprint name such as
	// "safari_ios_26_0", "okhttp4_android_13" or "chrome_133". Validating with a
	// mobile profile distinguishes proxies that only work for a desktop stack.
	Profile string `json:"profile"`
	// UserAgent overrides the request User-Agent used for canaries.
	UserAgent string `json:"user_agent,omitempty"`
	// MaxBodyBytes bounds the canary response body read for an egress IP.
	MaxBodyBytes int64 `json:"max_body_bytes"`
}

// AdmissionConfig controls the raw, mode-specific admission probes. They run
// in addition to egress-IP canaries for the strict trust tier.
//
// TLSCanaryURL is an HTTPS endpoint used to prove CONNECT, certificate
// verification and a paused keep-alive connection. EchoAddr is a raw TCP echo
// endpoint used for the N-bytes-out/N-bytes-back test. Empty values skip the
// corresponding probe; the test suite supplies both with local fakes.
type AdmissionConfig struct {
	Enabled      bool     `json:"enabled"`
	TLSCanaryURL string   `json:"tls_canary_url"`
	EchoAddr     string   `json:"echo_addr"`
	Hold         Duration `json:"hold"`
	EchoBytes    int      `json:"echo_bytes"`
	Timeout      Duration `json:"timeout"`
	// TLSSkipVerify is only for trusted labs. Strict connect mode rejects it.
	TLSSkipVerify bool `json:"tls_skip_verify"`
}

// ScraperConfig repeatedly fetches free proxy lists, validates candidates and
// hot-swaps the verified set into the pool while preserving state of proxies
// that are already present.
type ScraperConfig struct {
	Enabled         bool             `json:"enabled"`
	Sources         []SourceConfig   `json:"sources"`
	RefreshInterval Duration         `json:"refresh_interval"`
	StartupRefresh  bool             `json:"startup_refresh"`
	StartupWait     Duration         `json:"startup_wait"`
	FetchTimeout    Duration         `json:"fetch_timeout"`
	Concurrency     int              `json:"concurrency"`
	MaxCandidates   int              `json:"max_candidates"`
	MinPoolSize     int              `json:"min_pool_size"`
	MaxBodyBytes    int64            `json:"max_body_bytes"`
	UserAgent       string           `json:"user_agent,omitempty"`
	Validation      ValidationConfig `json:"validation"`
}

// Strategy values.
const (
	StrategyRoundRobin   = "round_robin"
	StrategyRandom       = "random"
	StrategyLeastUsed    = "least_used"
	StrategySticky       = "sticky"
	StrategyLatencyAware = "latency_aware"
	StrategyThompson     = "thompson"
)

// Trust tiers select the admission policy. Strict is the default for public
// proxies; trusted is for a proxy pool the operator owns (for example LTE
// modems) and only applies health plus egress checks.
const (
	TrustTierStrict  = "strict"
	TrustTierTrusted = "trusted"
)

// Admission modes.
const (
	AdmissionModeConnect     = "connect"
	AdmissionModeHTTPParsing = "http_parsing"
)

// defaultMobileUserAgent pairs with the default mobile TLS profile. A mobile
// ClientHello with a desktop or Go User-Agent is an obvious fingerprint
// mismatch, so validation uses a matching UA unless one is configured.
const defaultMobileUserAgent = "Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1"

// DefaultConfig returns a ready-to-use configuration.
func DefaultConfig() Config {
	return Config{
		DefaultScheme:      "socks5",
		Strategy:           StrategyRoundRobin,
		TrustTier:          TrustTierStrict,
		AllowDirect:        false,
		TLSFingerprints:    append([]string(nil), DefaultFingerprints...),
		StickyTTL:          Duration(5 * time.Minute),
		DialTimeout:        Duration(10 * time.Second),
		HandshakeTimeout:   Duration(15 * time.Second),
		MaxDialAttempts:    3,
		ProxyTLSSkipVerify: false,
		Cooldown: CooldownConfig{
			Initial:                Duration(15 * time.Second),
			Max:                    Duration(10 * time.Minute),
			Multiplier:             2,
			FailuresBeforeCooldown: 1,
		},
		Health: HealthConfig{
			Enabled:      true,
			Interval:     Duration(60 * time.Second),
			Timeout:      Duration(10 * time.Second),
			Concurrency:  50,
			ProbeURL:     "https://www.gstatic.com/generate_204",
			StartupCheck: true,
			StartupWait:  Duration(30 * time.Second),
		},
		HTTP: HTTPConfig{
			Timeout:             Duration(30 * time.Second),
			MaxRetries:          2,
			BanStatuses:         []int{403, 407, 429, 503},
			BanCooldown:         Duration(5 * time.Minute),
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     Duration(90 * time.Second),
			TLSHandshakeTimeout: Duration(10 * time.Second),
			MaxBodyBuffer:       4 << 20,
		},
		Probe: ProbeConfig{
			MaxResponseBytes: 4 << 20,
			ReadTimeout:      Duration(10 * time.Second),
			RaceReadTimeout:  Duration(1500 * time.Millisecond),
		},
		Stats:     StatsConfig{Listen: "127.0.0.1:9090"},
		Gateway:   GatewayConfig{Listen: "127.0.0.1:3128"},
		RateLimit: RateLimitConfig{},
		Safety: SafetyConfig{
			Enabled:      false,
			StopStatuses: []int{403, 429, 503},
			Threshold:    5,
			Window:       Duration(60 * time.Second),
			Cooldown:     Duration(10 * time.Minute),
			TargetCooldown: TargetCooldownConfig{
				Enabled:            true,
				Statuses:           []int{403, 429},
				Threshold:          5,
				Window:             Duration(60 * time.Second),
				Cooldown:           Duration(2 * time.Minute),
				MinDistinctProxies: 2,
			},
			Deception: DeceptionConfig{
				Enabled:             false,
				BaselineSamples:     2,
				MaxBodySample:       64 << 10,
				SimilarityThreshold: 0.92,
				RepeatStatus:        200,
				RepeatThreshold:     8,
				RepeatWindow:        Duration(10 * time.Second),
				LatencySpikeFactor:  4.0,
				NCDTarpit:           0.25,
				NCDStructural:       0.6,
				QuarantineSecrets:   true,
				Action:              "cooldown",
				SemanticService:     true,
				SemanticRequired:    false,
				SemanticAddr:        "127.0.0.1:8000",
				TargetBanTTL:        Duration(5 * time.Minute),
			},
		},
		Audit: AuditConfig{},
		Scope: ScopeConfig{
			DNSCacheTTL: Duration(5 * time.Minute),
			DNSTimeout:  Duration(3 * time.Second),
		},
		Scraper: ScraperConfig{
			RefreshInterval: Duration(15 * time.Minute),
			StartupRefresh:  true,
			StartupWait:     Duration(90 * time.Second),
			FetchTimeout:    Duration(20 * time.Second),
			Concurrency:     50,
			MaxCandidates:   1500,
			MinPoolSize:     1,
			MaxBodyBytes:    4 << 20,
			UserAgent:       "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
			Validation: ValidationConfig{
				Enabled: true,
				Mode:    AdmissionModeConnect,
				Admission: AdmissionConfig{
					Enabled:      true,
					TLSCanaryURL: "https://api.ipify.org",
					Hold:         Duration(2 * time.Second),
					EchoBytes:    256,
					Timeout:      Duration(10 * time.Second),
				},
				CanaryURLs: []string{
					"https://api.ipify.org",
					"https://ifconfig.me/ip",
					"https://icanhazip.com",
				},
				RealIPURL:                 "https://api.ipify.org",
				Timeout:                   Duration(12 * time.Second),
				Concurrency:               50,
				Attempts:                  2,
				MinCanaries:               2,
				RequireSameEgressIP:       true,
				RequireDistinctFromRealIP: true,
				MaxLatency:                Duration(5 * time.Second),
				Profile:                   "safari_ios_26_0",
				UserAgent:                 defaultMobileUserAgent,
				MaxBodyBytes:              64 << 10,
			},
		},
		LogLevel: "info",
	}
}

// LoadConfig reads JSON from path on top of DefaultConfig. Fields omitted in
// the file keep their default values.
func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open config: %w", err)
		}
		defer f.Close()
		dec := json.NewDecoder(f)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&cfg); err != nil {
			return nil, fmt.Errorf("decode config %s: %w", path, err)
		}
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) normalize() {
	d := DefaultConfig()
	if c.DefaultScheme == "" {
		c.DefaultScheme = d.DefaultScheme
	}
	if c.Strategy == "" {
		c.Strategy = d.Strategy
	}
	if c.TrustTier == "" {
		c.TrustTier = d.TrustTier
	}
	if c.StickyTTL == 0 {
		c.StickyTTL = d.StickyTTL
	}
	if c.DialTimeout == 0 {
		c.DialTimeout = d.DialTimeout
	}
	if c.HandshakeTimeout == 0 {
		c.HandshakeTimeout = d.HandshakeTimeout
	}
	if c.MaxDialAttempts == 0 {
		c.MaxDialAttempts = d.MaxDialAttempts
	}
	if c.TLSFingerprints == nil {
		c.TLSFingerprints = append([]string(nil), d.TLSFingerprints...)
	}
	if c.Cooldown.Initial == 0 {
		c.Cooldown.Initial = d.Cooldown.Initial
	}
	if c.Cooldown.Max == 0 {
		c.Cooldown.Max = d.Cooldown.Max
	}
	if c.Cooldown.Multiplier == 0 {
		c.Cooldown.Multiplier = d.Cooldown.Multiplier
	}
	if c.Cooldown.FailuresBeforeCooldown == 0 {
		c.Cooldown.FailuresBeforeCooldown = d.Cooldown.FailuresBeforeCooldown
	}
	if c.Health.Interval == 0 {
		c.Health.Interval = d.Health.Interval
	}
	if c.Health.Timeout == 0 {
		c.Health.Timeout = d.Health.Timeout
	}
	if c.Health.Concurrency == 0 {
		c.Health.Concurrency = d.Health.Concurrency
	}
	if c.Health.ProbeURL == "" {
		c.Health.ProbeURL = d.Health.ProbeURL
	}
	if c.Health.StartupWait == 0 {
		c.Health.StartupWait = d.Health.StartupWait
	}
	if c.HTTP.Timeout == 0 {
		c.HTTP.Timeout = d.HTTP.Timeout
	}
	if len(c.HTTP.BanStatuses) == 0 {
		c.HTTP.BanStatuses = append([]int(nil), d.HTTP.BanStatuses...)
	}
	if c.HTTP.BanCooldown == 0 {
		c.HTTP.BanCooldown = d.HTTP.BanCooldown
	}
	if c.HTTP.MaxIdleConns == 0 {
		c.HTTP.MaxIdleConns = d.HTTP.MaxIdleConns
	}
	if c.HTTP.MaxIdleConnsPerHost == 0 {
		c.HTTP.MaxIdleConnsPerHost = d.HTTP.MaxIdleConnsPerHost
	}
	if c.HTTP.IdleConnTimeout == 0 {
		c.HTTP.IdleConnTimeout = d.HTTP.IdleConnTimeout
	}
	if c.HTTP.TLSHandshakeTimeout == 0 {
		c.HTTP.TLSHandshakeTimeout = d.HTTP.TLSHandshakeTimeout
	}
	if c.HTTP.MaxBodyBuffer == 0 {
		c.HTTP.MaxBodyBuffer = d.HTTP.MaxBodyBuffer
	}
	if c.Probe.MaxResponseBytes == 0 {
		c.Probe.MaxResponseBytes = d.Probe.MaxResponseBytes
	}
	if c.Probe.ReadTimeout == 0 {
		c.Probe.ReadTimeout = d.Probe.ReadTimeout
	}
	if c.Probe.RaceReadTimeout == 0 {
		c.Probe.RaceReadTimeout = d.Probe.RaceReadTimeout
	}
	if c.LogLevel == "" {
		c.LogLevel = d.LogLevel
	}
	if c.RateLimit.PerProxyRPS > 0 && c.RateLimit.Burst == 0 {
		c.RateLimit.Burst = 1
	}
	if c.RateLimit.GlobalRPS > 0 && c.RateLimit.GlobalBurst == 0 {
		c.RateLimit.GlobalBurst = 1
	}
	if c.Safety.Threshold == 0 {
		c.Safety.Threshold = d.Safety.Threshold
	}
	if len(c.Safety.StopStatuses) == 0 {
		c.Safety.StopStatuses = append([]int(nil), d.Safety.StopStatuses...)
	}
	if c.Safety.Window == 0 {
		c.Safety.Window = d.Safety.Window
	}
	if c.Safety.Cooldown == 0 {
		c.Safety.Cooldown = d.Safety.Cooldown
	}
	if len(c.Safety.TargetCooldown.Statuses) == 0 {
		c.Safety.TargetCooldown.Statuses = append([]int(nil), d.Safety.TargetCooldown.Statuses...)
	}
	if c.Safety.TargetCooldown.Threshold == 0 {
		c.Safety.TargetCooldown.Threshold = d.Safety.TargetCooldown.Threshold
	}
	if c.Safety.TargetCooldown.Window == 0 {
		c.Safety.TargetCooldown.Window = d.Safety.TargetCooldown.Window
	}
	if c.Safety.TargetCooldown.Cooldown == 0 {
		c.Safety.TargetCooldown.Cooldown = d.Safety.TargetCooldown.Cooldown
	}
	if c.Safety.TargetCooldown.MinDistinctProxies == 0 {
		c.Safety.TargetCooldown.MinDistinctProxies = d.Safety.TargetCooldown.MinDistinctProxies
	}
	if c.Safety.Deception.BaselineSamples == 0 {
		c.Safety.Deception.BaselineSamples = d.Safety.Deception.BaselineSamples
	}
	if c.Safety.Deception.MaxBodySample == 0 {
		c.Safety.Deception.MaxBodySample = d.Safety.Deception.MaxBodySample
	}
	if c.Safety.Deception.SimilarityThreshold == 0 {
		c.Safety.Deception.SimilarityThreshold = d.Safety.Deception.SimilarityThreshold
	}
	if c.Safety.Deception.RepeatStatus == 0 {
		c.Safety.Deception.RepeatStatus = d.Safety.Deception.RepeatStatus
	}
	if c.Safety.Deception.RepeatThreshold == 0 {
		c.Safety.Deception.RepeatThreshold = d.Safety.Deception.RepeatThreshold
	}
	if c.Safety.Deception.RepeatWindow == 0 {
		c.Safety.Deception.RepeatWindow = d.Safety.Deception.RepeatWindow
	}
	if c.Safety.Deception.LatencySpikeFactor == 0 {
		c.Safety.Deception.LatencySpikeFactor = d.Safety.Deception.LatencySpikeFactor
	}
	if c.Safety.Deception.NCDTarpit == 0 {
		c.Safety.Deception.NCDTarpit = d.Safety.Deception.NCDTarpit
	}
	if c.Safety.Deception.NCDStructural == 0 {
		c.Safety.Deception.NCDStructural = d.Safety.Deception.NCDStructural
	}
	if c.Safety.Deception.SemanticAddr == "" {
		c.Safety.Deception.SemanticAddr = d.Safety.Deception.SemanticAddr
	}
	if c.Safety.Deception.TargetBanTTL == 0 {
		c.Safety.Deception.TargetBanTTL = d.Safety.Deception.TargetBanTTL
	}
	if c.Safety.Deception.Action == "" {
		c.Safety.Deception.Action = d.Safety.Deception.Action
	}
	if c.Scope.DNSCacheTTL == 0 {
		c.Scope.DNSCacheTTL = d.Scope.DNSCacheTTL
	}
	if c.Scope.DNSTimeout == 0 {
		c.Scope.DNSTimeout = d.Scope.DNSTimeout
	}
	if c.Scraper.RefreshInterval == 0 {
		c.Scraper.RefreshInterval = d.Scraper.RefreshInterval
	}
	if c.Scraper.StartupWait == 0 {
		c.Scraper.StartupWait = d.Scraper.StartupWait
	}
	if c.Scraper.FetchTimeout == 0 {
		c.Scraper.FetchTimeout = d.Scraper.FetchTimeout
	}
	if c.Scraper.Concurrency == 0 {
		c.Scraper.Concurrency = d.Scraper.Concurrency
	}
	if c.Scraper.MaxCandidates == 0 {
		c.Scraper.MaxCandidates = d.Scraper.MaxCandidates
	}
	if c.Scraper.MinPoolSize == 0 {
		c.Scraper.MinPoolSize = d.Scraper.MinPoolSize
	}
	if c.Scraper.MaxBodyBytes == 0 {
		c.Scraper.MaxBodyBytes = d.Scraper.MaxBodyBytes
	}
	if c.Scraper.UserAgent == "" {
		c.Scraper.UserAgent = d.Scraper.UserAgent
	}
	if len(c.Scraper.Validation.CanaryURLs) == 0 {
		c.Scraper.Validation.CanaryURLs = append([]string(nil), d.Scraper.Validation.CanaryURLs...)
	}
	if c.Scraper.Validation.Mode == "" {
		c.Scraper.Validation.Mode = d.Scraper.Validation.Mode
	}
	if c.Scraper.Validation.Admission.Hold == 0 {
		c.Scraper.Validation.Admission.Hold = d.Scraper.Validation.Admission.Hold
	}
	if c.Scraper.Validation.Admission.EchoBytes == 0 {
		c.Scraper.Validation.Admission.EchoBytes = d.Scraper.Validation.Admission.EchoBytes
	}
	if c.Scraper.Validation.Admission.Timeout == 0 {
		c.Scraper.Validation.Admission.Timeout = d.Scraper.Validation.Admission.Timeout
	}
	if c.Scraper.Validation.Admission.TLSCanaryURL == "" {
		c.Scraper.Validation.Admission.TLSCanaryURL = d.Scraper.Validation.Admission.TLSCanaryURL
	}
	if c.Scraper.Validation.RealIPURL == "" {
		c.Scraper.Validation.RealIPURL = d.Scraper.Validation.RealIPURL
	}
	if c.Scraper.Validation.Timeout == 0 {
		c.Scraper.Validation.Timeout = d.Scraper.Validation.Timeout
	}
	if c.Scraper.Validation.Concurrency == 0 {
		c.Scraper.Validation.Concurrency = d.Scraper.Validation.Concurrency
	}
	if c.Scraper.Validation.Attempts == 0 {
		c.Scraper.Validation.Attempts = d.Scraper.Validation.Attempts
	}
	if c.Scraper.Validation.MinCanaries == 0 {
		c.Scraper.Validation.MinCanaries = d.Scraper.Validation.MinCanaries
	}
	if c.Scraper.Validation.MaxLatency == 0 {
		c.Scraper.Validation.MaxLatency = d.Scraper.Validation.MaxLatency
	}
	if c.Scraper.Validation.RealIP == "" {
		c.Scraper.Validation.RealIP = d.Scraper.Validation.RealIP
	}
	if c.Scraper.Validation.Profile == "" {
		c.Scraper.Validation.Profile = d.Scraper.Validation.Profile
	}
	if c.Scraper.Validation.UserAgent == "" {
		c.Scraper.Validation.UserAgent = d.Scraper.Validation.UserAgent
	}
	if c.Scraper.Validation.MaxBodyBytes == 0 {
		c.Scraper.Validation.MaxBodyBytes = d.Scraper.Validation.MaxBodyBytes
	}
}

// Validate checks the configuration for impossible or unsafe values.
// validateLoopbackAddr forbids remote skeleton services. The analyzer is
// intelligence-only: no target request is ever routed through it, so there is
// no reason for it to bind or connect outside the loopback interface.
func validateLoopbackAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("expected host:port: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("must use a loopback IP literal (127.0.0.0/8 or ::1), got %q", host)
	}
	if _, err := net.ResolveTCPAddr("tcp", addr); err != nil {
		return fmt.Errorf("invalid address: %w", err)
	}
	return nil
}

func (c *Config) Validate() error {
	c.normalize()
	var errs []error
	add := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf(format, args...))
	}

	switch c.DefaultScheme {
	case "http", "https", "socks5", "socks5h":
	default:
		add("default_scheme: unsupported %q", c.DefaultScheme)
	}
	switch c.Strategy {
	case StrategyRoundRobin, StrategyRandom, StrategyLeastUsed, StrategySticky, StrategyLatencyAware, StrategyThompson:
	default:
		add("strategy: unsupported %q", c.Strategy)
	}
	switch c.TrustTier {
	case TrustTierStrict:
		if c.AllowDirect {
			add("allow_direct is forbidden in the strict trust tier; use trust_tier=trusted for an owned pool")
		}
	case TrustTierTrusted:
	default:
		add("trust_tier must be strict or trusted")
	}
	if c.DialTimeout <= 0 {
		add("dial_timeout must be > 0")
	}
	if c.HandshakeTimeout <= 0 {
		add("handshake_timeout must be > 0")
	}
	if c.MaxDialAttempts < 1 {
		add("max_dial_attempts must be >= 1")
	}
	for _, name := range c.TLSFingerprints {
		if _, err := ParseFingerprint(name); err != nil {
			add("tls_fingerprints: %v", err)
		}
	}
	if c.Cooldown.Initial <= 0 {
		add("cooldown.initial must be > 0")
	}
	if c.Cooldown.Max < c.Cooldown.Initial {
		add("cooldown.max must be >= cooldown.initial")
	}
	if c.Cooldown.Multiplier < 1 {
		add("cooldown.multiplier must be >= 1")
	}
	if c.Cooldown.FailuresBeforeCooldown < 1 {
		add("cooldown.failures_before_cooldown must be >= 1")
	}
	if c.Health.Interval <= 0 {
		add("health.interval must be > 0")
	}
	if c.Health.Timeout <= 0 {
		add("health.timeout must be > 0")
	}
	if c.Health.Concurrency < 1 {
		add("health.concurrency must be >= 1")
	}
	u, err := url.Parse(c.Health.ProbeURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		add("health.probe_url must be an absolute http(s) URL")
	}
	if c.HTTP.MaxRetries < 0 {
		add("http.max_retries must be >= 0")
	}
	for _, code := range c.HTTP.BanStatuses {
		if code < 100 || code > 599 {
			add("http.ban_statuses: invalid status %d", code)
		}
	}
	if c.HTTP.MaxBodyBuffer < 0 {
		add("http.max_body_buffer must be >= 0")
	}
	if c.Probe.MaxResponseBytes <= 0 {
		add("probe.max_response_bytes must be > 0")
	}
	if c.Probe.ReadTimeout <= 0 {
		add("probe.read_timeout must be > 0")
	}
	if c.Probe.RaceReadTimeout <= 0 {
		add("probe.race_read_timeout must be > 0")
	}
	if c.RateLimit.PerProxyRPS < 0 {
		add("rate_limit.per_proxy_rps must be >= 0")
	}
	if c.RateLimit.Burst < 0 {
		add("rate_limit.burst must be >= 0")
	}
	if c.RateLimit.GlobalRPS < 0 {
		add("rate_limit.global_rps must be >= 0")
	}
	if c.RateLimit.GlobalBurst < 0 {
		add("rate_limit.global_burst must be >= 0")
	}
	for _, code := range c.Safety.StopStatuses {
		if code < 100 || code > 599 {
			add("safety.stop_statuses: invalid status %d", code)
		}
	}
	if c.Safety.Threshold < 1 {
		add("safety.threshold must be >= 1")
	}
	if c.Safety.Window <= 0 {
		add("safety.window must be > 0")
	}
	if c.Safety.Cooldown <= 0 {
		add("safety.cooldown must be > 0")
	}
	if c.Safety.MaxRequests < 0 {
		add("safety.max_requests must be >= 0")
	}
	if c.Safety.TargetCooldown.Enabled {
		for _, code := range c.Safety.TargetCooldown.Statuses {
			if code < 100 || code > 599 {
				add("safety.target_cooldown.statuses: invalid status %d", code)
			}
		}
		if c.Safety.TargetCooldown.Threshold < 1 {
			add("safety.target_cooldown.threshold must be >= 1")
		}
		if c.Safety.TargetCooldown.Window <= 0 {
			add("safety.target_cooldown.window must be > 0")
		}
		if c.Safety.TargetCooldown.Cooldown <= 0 {
			add("safety.target_cooldown.cooldown must be > 0")
		}
		if c.Safety.TargetCooldown.MinDistinctProxies < 1 {
			add("safety.target_cooldown.min_distinct_proxies must be >= 1")
		}
	}
	if c.Safety.Deception.SemanticRequired && !c.Safety.Deception.SemanticService {
		add("safety.deception.semantic_required requires semantic_service=true")
	}
	if c.Safety.Deception.BaselineSamples < 1 {
		add("safety.deception.baseline_samples must be >= 1")
	}
	if c.Safety.Deception.MaxBodySample < 0 {
		add("safety.deception.max_body_sample must be >= 0")
	}
	if c.Safety.Deception.SimilarityThreshold <= 0 || c.Safety.Deception.SimilarityThreshold > 1 {
		add("safety.deception.similarity_threshold must be in (0,1]")
	}
	if c.Safety.Deception.RepeatStatus < 100 || c.Safety.Deception.RepeatStatus > 599 {
		add("safety.deception.repeat_status: invalid status %d", c.Safety.Deception.RepeatStatus)
	}
	if c.Safety.Deception.RepeatThreshold < 1 {
		add("safety.deception.repeat_threshold must be >= 1")
	}
	if c.Safety.Deception.RepeatWindow <= 0 {
		add("safety.deception.repeat_window must be > 0")
	}
	if c.Safety.Deception.NCDTarpit <= 0 || c.Safety.Deception.NCDTarpit > 1 {
		add("safety.deception.ncd_tarpit must be in (0,1]")
	}
	if c.Safety.Deception.NCDStructural <= 0 || c.Safety.Deception.NCDStructural > 1 {
		add("safety.deception.ncd_structural must be in (0,1]")
	}
	if c.Safety.Deception.LatencySpikeFactor <= 0 {
		add("safety.deception.latency_spike_factor must be > 0")
	}
	if c.Safety.Deception.TargetBanTTL <= 0 {
		add("safety.deception.target_ban_ttl must be > 0")
	}
	if err := validateLoopbackAddr(c.Safety.Deception.SemanticAddr); err != nil {
		add("safety.deception.semantic_addr: %v", err)
	}
	switch strings.ToLower(strings.TrimSpace(c.Safety.Deception.Action)) {
	case "cooldown", "disable", "mark":
	default:
		add("safety.deception.action must be cooldown, disable or mark")
	}
	if err := validateScopeConfig(c.Scope); err != nil {
		add("scope: %v", err)
	}
	if err := validateScraperConfig(c); err != nil {
		add("scraper: %v", err)
	}
	switch strings.ToLower(c.LogLevel) {
	case "debug", "info", "warn", "warning", "error":
	default:
		add("log_level must be debug, info, warn or error")
	}
	if len(errs) > 0 {
		var b strings.Builder
		b.WriteString("invalid config:")
		for _, e := range errs {
			b.WriteString("\n  - ")
			b.WriteString(e.Error())
		}
		return fmt.Errorf("%s", b.String())
	}
	return nil
}

func validateScopeConfig(s ScopeConfig) error {
	var errs []error
	add := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf(format, args...))
	}
	if s.DNSCacheTTL < 0 {
		add("dns_cache_ttl must be >= 0")
	}
	if s.DNSTimeout < 0 {
		add("dns_timeout must be >= 0")
	}
	for _, raw := range s.AllowCIDRs {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(raw)); err != nil {
			add("allow_cidrs: invalid CIDR %q", raw)
		}
	}
	for _, raw := range s.DenyCIDRs {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(raw)); err != nil {
			add("deny_cidrs: invalid CIDR %q", raw)
		}
	}
	for _, port := range s.AllowPorts {
		if port < 1 || port > 65535 {
			add("allow_ports: invalid port %d", port)
		}
	}
	for _, raw := range s.AllowHosts {
		h := strings.TrimSpace(raw)
		if h == "" {
			add("allow_hosts: empty host")
			continue
		}
		if h == "*" || h == "*." || h == "." {
			add("allow_hosts: global wildcard %q is refused", raw)
			continue
		}
		if strings.ContainsAny(h, " \t\r\n/") || strings.Contains(h, "://") {
			add("allow_hosts: %q must be a hostname or IP, without scheme, path or spaces", raw)
		}
	}
	if s.Enabled {
		if len(s.AllowHosts) == 0 && len(s.AllowCIDRs) == 0 {
			add("enabled scope requires allow_hosts or allow_cidrs")
		}
		if len(s.AllowHosts) == 0 && len(s.AllowCIDRs) > 0 && !s.ResolveLocally {
			add("resolve_locally must be true when only allow_cidrs are configured")
		}
	}
	if len(errs) > 0 {
		return errorsJoin(errs)
	}
	return nil
}

func validateScraperConfig(c *Config) error {
	s := c.Scraper
	if !s.Enabled {
		return nil
	}
	var errs []error
	add := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf(format, args...))
	}
	if len(s.Sources) == 0 {
		add("enabled scraper requires at least one source")
	}
	for i, src := range s.Sources {
		name := src.Name
		if name == "" {
			name = fmt.Sprintf("#%d", i+1)
		}
		u, err := url.Parse(strings.TrimSpace(src.URL))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			add("source %s: url must be an absolute http(s) URL", name)
		}
		typ := strings.ToLower(strings.TrimSpace(src.Type))
		if typ == "" {
			typ = "text"
		}
		switch typ {
		case "text":
		case "regex":
			if strings.TrimSpace(src.Regex) == "" {
				add("source %s: regex source requires a regex", name)
			} else if _, err := regexp.Compile(src.Regex); err != nil {
				add("source %s: invalid regex: %v", name, err)
			}
		default:
			add("source %s: type must be text or regex", name)
		}
		if src.Scheme != "" {
			switch strings.ToLower(src.Scheme) {
			case "http", "https", "socks5", "socks5h":
			default:
				add("source %s: unsupported scheme %q", name, src.Scheme)
			}
		}
		for k := range src.Headers {
			if strings.TrimSpace(k) == "" {
				add("source %s: empty header name", name)
			}
		}
	}
	if s.RefreshInterval <= 0 {
		add("refresh_interval must be > 0")
	}
	if s.StartupWait < 0 {
		add("startup_wait must be >= 0")
	}
	if s.FetchTimeout <= 0 {
		add("fetch_timeout must be > 0")
	}
	if s.Concurrency < 1 {
		add("concurrency must be >= 1")
	}
	if s.MaxCandidates < 1 {
		add("max_candidates must be >= 1")
	}
	if s.MinPoolSize < 0 {
		add("min_pool_size must be >= 0")
	}
	if s.MaxBodyBytes < 1 {
		add("max_body_bytes must be >= 1")
	}
	if strings.TrimSpace(s.UserAgent) == "" {
		add("user_agent must not be empty")
	}

	v := s.Validation
	if v.Timeout <= 0 {
		add("validation.timeout must be > 0")
	}
	switch v.Mode {
	case AdmissionModeConnect, AdmissionModeHTTPParsing:
	default:
		add("validation.mode must be connect or http_parsing")
	}
	if v.Admission.Enabled {
		if v.Admission.Timeout <= 0 {
			add("validation.admission.timeout must be > 0")
		}
		if v.Admission.Hold < 0 {
			add("validation.admission.hold must be >= 0")
		}
		if v.Admission.EchoBytes < 1 || v.Admission.EchoBytes > 1<<20 {
			add("validation.admission.echo_bytes must be between 1 and 1048576")
		}
		if v.Admission.TLSCanaryURL != "" {
			u, err := url.Parse(strings.TrimSpace(v.Admission.TLSCanaryURL))
			if err != nil || u.Scheme != "https" || u.Host == "" {
				add("validation.admission.tls_canary_url must be an absolute https URL")
			}
		}
		if v.Admission.EchoAddr != "" {
			host, port, err := net.SplitHostPort(v.Admission.EchoAddr)
			if err != nil || host == "" || port == "" {
				add("validation.admission.echo_addr must be host:port")
			}
		}
		if v.Admission.TLSCanaryURL == "" && v.Admission.EchoAddr == "" {
			add("validation.admission needs tls_canary_url or echo_addr")
		}
		if v.Mode == AdmissionModeHTTPParsing && v.Admission.EchoAddr == "" {
			add("validation.mode=http_parsing requires admission.echo_addr")
		}
		if v.Mode == AdmissionModeConnect && v.Admission.TLSCanaryURL == "" {
			add("validation.mode=connect requires admission.tls_canary_url")
		}
		if c.TrustTier == TrustTierStrict && v.Mode == AdmissionModeConnect && v.Admission.TLSSkipVerify {
			add("validation.admission.tls_skip_verify is forbidden in strict connect mode")
		}
	}
	if v.Concurrency < 1 {
		add("validation.concurrency must be >= 1")
	}
	if v.Attempts < 1 {
		add("validation.attempts must be >= 1")
	}
	if v.MinCanaries < 1 {
		add("validation.min_canaries must be >= 1")
	}
	if v.MaxLatency < 0 {
		add("validation.max_latency must be >= 0")
	}
	if v.MaxBodyBytes < 1 {
		add("validation.max_body_bytes must be >= 1")
	}
	if v.Profile != "" {
		if _, ok := profiles.MappedTLSClients[strings.ToLower(v.Profile)]; !ok {
			add("validation.profile: unknown tls-client profile %q", v.Profile)
		}
	}
	if v.Enabled {
		if len(v.CanaryURLs) == 0 {
			add("validation.canary_urls must not be empty")
		}
		for _, raw := range v.CanaryURLs {
			u, err := url.Parse(strings.TrimSpace(raw))
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				add("validation.canary_urls: %q must be an absolute http(s) URL", raw)
			}
		}
		if v.MinCanaries > len(v.CanaryURLs) {
			add("validation.min_canaries cannot exceed len(canary_urls)")
		}
		if v.RequireDistinctFromRealIP && v.RealIP == "" {
			u, err := url.Parse(strings.TrimSpace(v.RealIPURL))
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				add("validation.real_ip_url must be an absolute http(s) URL when distinctness is required")
			}
		}
		if v.RealIP != "" && net.ParseIP(strings.TrimSpace(v.RealIP)) == nil {
			add("validation.real_ip must be an IP address")
		}
	}
	if len(errs) > 0 {
		return errorsJoin(errs)
	}
	return nil
}

// errorsJoin avoids importing errors just for a small helper.
func errorsJoin(errs []error) error {
	if len(errs) == 1 {
		return errs[0]
	}
	var b strings.Builder
	for i, e := range errs {
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(e.Error())
	}
	return fmt.Errorf("%s", b.String())
}
