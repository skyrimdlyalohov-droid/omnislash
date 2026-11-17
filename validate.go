package omnislash

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
)

var ipv4Pattern = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)

// ValidationResult describes a proxy that passed strict validation.
type ValidationResult struct {
	EgressIP string        `json:"egress_ip"`
	Canaries int           `json:"canaries"`
	Attempts int           `json:"attempts"`
	Latency  time.Duration `json:"-"`
}

// Validator checks scraped proxies with a real browser/mobile TLS fingerprint
// through bogdanfinn/tls-client. The proxy must reach enough HTTPS canaries,
// report a stable public egress IP and, unless disabled, that IP must differ
// from the scanner's real address.
type Validator struct {
	cfg     ValidationConfig
	log     *slog.Logger
	profile profiles.ClientProfile

	realMu     sync.Mutex
	realIP     net.IP
	realCached bool

	now func() time.Time
}

// NewValidator compiles a validator. Unknown TLS profiles are rejected by
// Config.Validate; here they fall back to the library default defensively.
func NewValidator(cfg ValidationConfig, logger *slog.Logger) (*Validator, error) {
	if cfg.Timeout <= 0 {
		return nil, fmt.Errorf("validation timeout must be > 0")
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 64 << 10
	}
	if strings.TrimSpace(cfg.UserAgent) == "" {
		cfg.UserAgent = defaultMobileUserAgent
	}
	profile, ok := profiles.MappedTLSClients[strings.ToLower(cfg.Profile)]
	if !ok {
		profile = profiles.DefaultClientProfile
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Validator{cfg: cfg, log: logger, profile: profile, now: time.Now}, nil
}

// RealIP returns the scanner's real public address, either from the config or
// by asking RealIPURL directly. Successful lookups are cached; a transient
// failure is retried on the next call instead of poisoning the validator for
// the lifetime of a long-running service.
func (v *Validator) RealIP(ctx context.Context) (net.IP, error) {
	v.realMu.Lock()
	defer v.realMu.Unlock()
	if v.realCached {
		return v.realIP, nil
	}
	if raw := strings.TrimSpace(v.cfg.RealIP); raw != "" {
		ip := net.ParseIP(raw)
		if ip == nil {
			return nil, fmt.Errorf("validation.real_ip %q is not an IP address", raw)
		}
		v.realIP = ip
		v.realCached = true
		return v.realIP, nil
	}
	if v.cfg.RealIPURL == "" {
		return nil, fmt.Errorf("validation.real_ip or real_ip_url is required")
	}
	ip, err := v.directEgressIP(ctx)
	if err != nil {
		return nil, err
	}
	v.realIP = ip
	v.realCached = true
	return v.realIP, nil
}

// Validate checks one proxy. A nil error means the proxy passed every enabled
// check. Validation errors are proxy-specific and should not be confused with
// context cancellation.
func (v *Validator) Validate(ctx context.Context, pr *Proxy) (ValidationResult, error) {
	var res ValidationResult
	if pr == nil {
		return res, fmt.Errorf("validation: nil proxy")
	}
	if !v.cfg.Enabled {
		return res, nil
	}
	var realIP net.IP
	if v.cfg.RequireDistinctFromRealIP {
		ip, err := v.RealIP(ctx)
		if err != nil {
			return res, fmt.Errorf("validation: determine real IP: %w", err)
		}
		realIP = ip
	}

	attempts := v.cfg.Attempts
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		res, lastErr = v.attempt(ctx, pr, realIP)
		if lastErr == nil {
			return res, nil
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("validation failed")
	}
	return res, lastErr
}

func (v *Validator) attempt(ctx context.Context, pr *Proxy, realIP net.IP) (ValidationResult, error) {
	res := ValidationResult{Attempts: 1}
	attemptStarted := v.now()
	client, err := v.newClient(pr)
	if err != nil {
		return res, fmt.Errorf("create TLS client: %w", err)
	}
	defer client.Close()

	maxLatency := v.cfg.MaxLatency.Std()
	var egress net.IP
	successes := 0

	for _, canary := range v.cfg.CanaryURLs {
		started := v.now()
		ip, err := v.fetchEgressIP(ctx, client, canary)
		elapsed := v.now().Sub(started)
		if err != nil {
			v.log.Debug("proxy validation canary failed", "proxy", pr.Label(), "canary", canary, "error", err)
			continue
		}
		if maxLatency > 0 && elapsed > maxLatency {
			v.log.Debug("proxy validation canary too slow", "proxy", pr.Label(), "canary", canary, "latency", elapsed)
			continue
		}
		if !v.cfg.AllowPrivateEgress && isNonPublicIP(ip) {
			return res, fmt.Errorf("%s: egress %s is private or otherwise non-public", canary, ip)
		}
		if egress == nil {
			egress = ip
		} else if v.cfg.RequireSameEgressIP && !egress.Equal(ip) {
			return res, fmt.Errorf("canaries reported different egress IPs (%s and %s)", egress, ip)
		}
		successes++
	}

	if successes < v.cfg.MinCanaries {
		return res, fmt.Errorf("only %d/%d canaries succeeded", successes, v.cfg.MinCanaries)
	}
	if egress == nil {
		return res, fmt.Errorf("no egress IP observed")
	}
	if v.cfg.RequireDistinctFromRealIP && realIP != nil {
		if egress.Equal(realIP) || (egress.To4() != nil && realIP.To4() != nil && egress.To4().Equal(realIP.To4())) {
			return res, fmt.Errorf("egress %s equals the scanner's real IP", egress)
		}
	}
	res.EgressIP = egress.String()
	res.Canaries = successes
	res.Latency = v.now().Sub(attemptStarted)
	return res, nil
}

func (v *Validator) newClient(pr *Proxy) (tlsclient.HttpClient, error) {
	timeout := v.cfg.Timeout.Std()
	if timeout <= 0 {
		timeout = 12 * time.Second
	}
	opts := []tlsclient.HttpClientOption{
		tlsclient.WithTimeoutMilliseconds(int(timeout / time.Millisecond)),
		tlsclient.WithClientProfile(v.profile),
		tlsclient.WithNotFollowRedirects(),
		tlsclient.WithDisableHttp3(),
	}
	if v.cfg.TLSSkipVerify {
		opts = append(opts, tlsclient.WithInsecureSkipVerify())
	}
	if pr != nil {
		opts = append(opts, tlsclient.WithProxyUrl(proxyURLFor(pr)))
	}
	if ua := strings.TrimSpace(v.cfg.UserAgent); ua != "" {
		headers := fhttp.Header{}
		headers.Set("User-Agent", ua)
		headers.Set("Accept", "*/*")
		opts = append(opts, tlsclient.WithDefaultHeaders(headers))
	}
	return tlsclient.NewHttpClient(nil, opts...)
}

func (v *Validator) directEgressIP(ctx context.Context) (net.IP, error) {
	client, err := v.newClient(nil)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	ip, err := v.fetchEgressIP(ctx, client, v.cfg.RealIPURL)
	if err != nil {
		return nil, fmt.Errorf("fetch real IP from %s: %w", v.cfg.RealIPURL, err)
	}
	return ip, nil
}

func (v *Validator) fetchEgressIP(ctx context.Context, client tlsclient.HttpClient, canary string) (net.IP, error) {
	req, err := fhttp.NewRequestWithContext(ctx, fhttp.MethodGet, canary, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	limit := v.cfg.MaxBodyBytes
	if limit <= 0 {
		limit = 64 << 10
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return parseIPFromBody(body)
}

func proxyURLFor(pr *Proxy) string {
	u := &url.URL{Scheme: pr.Scheme, Host: pr.Addr}
	if pr.Username != "" || pr.Password != "" {
		u.User = url.UserPassword(pr.Username, pr.Password)
	}
	return u.String()
}

func parseIPFromBody(body []byte) (net.IP, error) {
	text := strings.TrimSpace(string(body))
	if ip := net.ParseIP(strings.Trim(text, "[]")); ip != nil {
		return ip, nil
	}
	if match := ipv4Pattern.FindString(text); match != "" {
		if ip := net.ParseIP(match); ip != nil {
			return ip, nil
		}
	}
	for _, field := range strings.Fields(text) {
		field = strings.Trim(field, "[]()<>,.;\"'")
		if ip := net.ParseIP(field); ip != nil {
			return ip, nil
		}
	}
	return nil, fmt.Errorf("response does not contain an IP address")
}
