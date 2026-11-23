package omnislash

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"math/rand/v2"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type stickyEntry struct {
	proxy   *Proxy
	expires time.Time
}

// maxStickyEntries bounds memory when a scanner rotates through a very large
// number of target hosts with the sticky strategy. When the limit is reached,
// expired entries are pruned and, if necessary, the map is reset; stickiness
// is an optimization, so dropping entries is safe.
const maxStickyEntries = 65536

// Pool owns a set of proxies, their health state and selection strategy.
// It is safe for concurrent use.
type Pool struct {
	cfg   Config
	log   *slog.Logger
	scope *Scope

	mu      sync.RWMutex
	proxies []*Proxy

	rr     atomic.Uint64
	closed atomic.Bool
	gen    atomic.Uint64

	stickyMu sync.Mutex
	sticky   map[string]stickyEntry

	scraperMu    sync.RWMutex
	scraperStats func() ScraperStats

	globalLimiter *tokenBucket
	circuit       *CircuitBreaker
	audit         *AuditLogger
	deception     *DeceptionFilter

	now func() time.Time
}

// NewPool creates a pool. The config is copied and normalized; proxies are
// used in the given order for deterministic round-robin selection.
func NewPool(cfg *Config, proxies []*Proxy, logger *slog.Logger) (*Pool, error) {
	if logger == nil {
		logger = slog.Default()
	}
	c := DefaultConfig()
	if cfg != nil {
		c = *cfg
	}
	c.normalize()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if len(proxies) == 0 && !c.AllowDirect && !c.Scraper.Enabled {
		return nil, ErrNoProxies
	}
	scope, err := NewScope(c.Scope)
	if err != nil {
		return nil, fmt.Errorf("scope: %w", err)
	}
	if c.RateLimit.PerProxyRPS > 0 {
		for _, p := range proxies {
			p.limiter = newTokenBucket(c.RateLimit.PerProxyRPS, c.RateLimit.Burst)
		}
	}
	audit, err := newAuditLogger(c.Audit)
	if err != nil {
		return nil, err
	}
	p := &Pool{
		cfg:     c,
		proxies: proxies,
		scope:   scope,
		log:     logger,
		sticky:  make(map[string]stickyEntry),
		audit:   audit,
		now:     time.Now,
	}
	if c.RateLimit.GlobalRPS > 0 {
		p.globalLimiter = newTokenBucket(c.RateLimit.GlobalRPS, c.RateLimit.GlobalBurst)
	}
	if c.Safety.Enabled {
		p.circuit = NewCircuitBreaker(c.Safety, p.now)
	}
	if c.Safety.Deception.Enabled {
		p.deception = NewDeceptionFilter(c.Safety.Deception, logger)
	}
	return p, nil
}

// Config returns a copy of the pool configuration.
func (p *Pool) Config() Config { return p.cfg }

// Proxies returns a shallow copy of the proxy slice.
func (p *Pool) Proxies() []*Proxy {
	proxies := p.snapshot()
	out := make([]*Proxy, len(proxies))
	copy(out, proxies)
	return out
}

// ProxyByLabel returns the proxy with the given label, if present.
func (p *Pool) ProxyByLabel(label string) (*Proxy, bool) {
	label = strings.TrimSpace(label)
	if label == "" {
		return nil, false
	}
	for _, pr := range p.snapshot() {
		if pr.Label() == label {
			return pr, true
		}
	}
	return nil, false
}

// Len returns the number of proxies in the pool.
func (p *Pool) Len() int { return len(p.snapshot()) }

// Available returns the number of proxies that are not cooling down or
// disabled right now.
func (p *Pool) Available() int {
	proxies := p.snapshot()
	now := p.now()
	n := 0
	for _, pr := range proxies {
		if pr.available(now) {
			n++
		}
	}
	return n
}

func (p *Pool) snapshot() []*Proxy {
	p.mu.RLock()
	proxies := p.proxies
	p.mu.RUnlock()
	return proxies
}

// Replace atomically swaps the pool contents. Proxies with the same scheme,
// address and credentials keep their counters and cooldown state. This is used
// by the scraper so verified candidates can be merged without losing health
// history.
func (p *Pool) Replace(proxies []*Proxy) {
	p.mu.Lock()
	existing := make(map[string]*Proxy, len(p.proxies))
	for _, old := range p.proxies {
		if old != nil {
			existing[old.key()] = old
		}
	}
	out := make([]*Proxy, 0, len(proxies))
	seen := make(map[string]struct{}, len(proxies))
	for _, np := range proxies {
		if np == nil {
			continue
		}
		key := np.key()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		if old, ok := existing[key]; ok {
			np = old
		}
		if p.cfg.RateLimit.PerProxyRPS > 0 && np.limiter == nil {
			np.limiter = newTokenBucket(p.cfg.RateLimit.PerProxyRPS, p.cfg.RateLimit.Burst)
		}
		out = append(out, np)
	}
	p.proxies = out
	p.mu.Unlock()
	p.gen.Add(1)

	p.stickyMu.Lock()
	clear(p.sticky)
	p.stickyMu.Unlock()
}

// Close marks the pool as closed. Existing connections are not interrupted.
func (p *Pool) Close() {
	p.closed.Store(true)
	if p.audit != nil {
		_ = p.audit.Close()
	}
}

// WaitGlobal acquires one slot from the pool-wide rate limiter. The returned
// context carries a marker so nested dials do not consume a second slot for the
// same application request. A closed or nil limiter is a no-op.
func (p *Pool) WaitGlobal(ctx context.Context) (context.Context, error) {
	if p == nil || p.globalLimiter == nil {
		return ctx, nil
	}
	if ctx.Value(globalWaitKey{}) != nil {
		return ctx, nil
	}
	if err := p.globalLimiter.wait(ctx); err != nil {
		return ctx, err
	}
	return context.WithValue(ctx, globalWaitKey{}, true), nil
}

type globalWaitKey struct{}

// Allow checks the safety breaker. It returns ErrCircuitOpen while traffic is
// stopped.
func (p *Pool) Allow() error {
	if p == nil {
		return nil
	}
	return p.circuit.Allow()
}

// RecordStatus feeds one target response into the safety breaker.
func (p *Pool) RecordStatus(status int) {
	if p == nil {
		return
	}
	p.circuit.RecordStatus(status)
}

// TripSafety opens the safety breaker immediately.
func (p *Pool) TripSafety(reason string) {
	if p == nil {
		return
	}
	p.circuit.Trip(reason)
}

// ResetSafety closes the safety breaker and clears the window and budget.
func (p *Pool) ResetSafety() {
	if p == nil {
		return
	}
	p.circuit.Reset()
}

// CircuitState returns the current safety breaker state.
func (p *Pool) CircuitState() CircuitState {
	if p == nil {
		return CircuitState{}
	}
	return p.circuit.State()
}

// Audit returns the configured audit logger, or nil when auditing is disabled.
func (p *Pool) Audit() *AuditLogger {
	if p == nil {
		return nil
	}
	return p.audit
}

// Deception returns the response-side deception filter, or nil when disabled.
func (p *Pool) Deception() *DeceptionFilter {
	if p == nil {
		return nil
	}
	return p.deception
}

// HandleDeception applies the configured defensive reaction for a flagged
// deception/tarpit decision. It never bypasses deception; it quarantines/cools
// down/marks depending on config.
func (p *Pool) HandleDeception(pr *Proxy, d DeceptionDecision) {
	if p == nil || !d.Flagged {
		return
	}
	if p.audit != nil {
		proxy := ""
		if pr != nil {
			proxy = pr.Label()
		}
		p.audit.Log(AuditEvent{Kind: "deception", Target: d.Host, Reason: string(d.Kind), Status: 200, Proxy: proxy})
	}
	action := strings.ToLower(strings.TrimSpace(p.cfg.Safety.Deception.Action))
	switch action {
	case "mark":
		// record only
	case "disable":
		if pr != nil {
			pr.markBan(p.now(), "deception:"+string(d.Kind), 24*time.Hour)
		}
	default: // cooldown
		if pr != nil {
			cd := p.cfg.HTTP.BanCooldown.Std()
			if cd <= 0 {
				cd = 5 * time.Minute
			}
			p.Ban(pr, "deception:"+string(d.Kind), cd)
		}
	}
	// Anomalies/tarpit also open circuit in defensive mode to stop the scan node.
	if p.circuit != nil && (d.Kind == DeceptionSynthetic200 || d.Kind == DeceptionTarpit || d.Kind == DeceptionRepeat) {
		p.circuit.Trip("deception:" + string(d.Kind))
	}
}

// SetScraperStats registers a callback that exposes scraper state in the pool
// stats snapshot. It is optional and primarily used by ServeStats.
func (p *Pool) SetScraperStats(fn func() ScraperStats) {
	p.scraperMu.Lock()
	p.scraperStats = fn
	p.scraperMu.Unlock()
}

// Generation increases every time the pool contents are replaced. Transports
// use it to discard cached connections for proxies that left the pool.
func (p *Pool) Generation() uint64 { return p.gen.Load() }

// Ban puts pr into cooldown. It is useful for application-level bans, for
// example when a raw scanner sees HTTP 403/429 on a connection. A zero
// cooldown uses http.ban_cooldown from the config.
func (p *Pool) Ban(pr *Proxy, reason string, cooldown time.Duration) {
	if cooldown <= 0 {
		cooldown = p.cfg.HTTP.BanCooldown.Std()
	}
	pr.markBan(p.now(), reason, cooldown)
}

// Stats is a point-in-time snapshot of the pool.
type Stats struct {
	GeneratedAt time.Time     `json:"generated_at"`
	Total       int           `json:"total"`
	Available   int           `json:"available"`
	InCooldown  int           `json:"in_cooldown"`
	Disabled    int           `json:"disabled"`
	Circuit     *CircuitState `json:"circuit,omitempty"`
	Proxies     []ProxyStats  `json:"proxies"`
	Scraper     *ScraperStats `json:"scraper,omitempty"`
}

// Stats returns a snapshot of all proxies.
func (p *Pool) Stats() Stats {
	proxies := p.snapshot()
	now := p.now()
	s := Stats{
		GeneratedAt: now,
		Total:       len(proxies),
		Proxies:     make([]ProxyStats, 0, len(proxies)),
	}
	if p.circuit != nil {
		cs := p.circuit.State()
		s.Circuit = &cs
	}
	for _, pr := range proxies {
		ps := pr.stats(now)
		s.Proxies = append(s.Proxies, ps)
		if ps.Available {
			s.Available++
		}
		if ps.InCooldown {
			s.InCooldown++
		}
		if ps.Disabled {
			s.Disabled++
		}
	}
	p.scraperMu.RLock()
	fn := p.scraperStats
	p.scraperMu.RUnlock()
	if fn != nil {
		st := fn()
		s.Scraper = &st
	}
	return s
}

func (p *Pool) pick(exclude map[*Proxy]struct{}, key string) (*Proxy, error) {
	if p.closed.Load() {
		return nil, ErrPoolClosed
	}
	proxies := p.snapshot()
	n := len(proxies)
	if n == 0 {
		return nil, ErrNoProxyAvailable
	}
	now := p.now()

	if p.cfg.Strategy == StrategySticky && key != "" {
		p.stickyMu.Lock()
		if e, ok := p.sticky[key]; ok {
			if now.Before(e.expires) && !inSet(exclude, e.proxy) && e.proxy.available(now) {
				p.stickyMu.Unlock()
				e.proxy.uses.Add(1)
				return e.proxy, nil
			}
			delete(p.sticky, key)
		}
		p.stickyMu.Unlock()
	}

	var chosen *Proxy
	switch p.cfg.Strategy {
	case StrategyRandom:
		chosen = p.pickRandom(proxies, now, exclude)
	case StrategyLeastUsed:
		chosen = p.pickLeastUsed(proxies, now, exclude)
	case StrategyLatencyAware:
		chosen = p.pickLatencyAware(proxies, now, exclude)
	case StrategyThompson:
		chosen = p.pickThompson(proxies, now, exclude)
	default:
		chosen = p.pickRoundRobin(proxies, now, exclude)
	}
	if chosen == nil {
		return nil, fmt.Errorf("%w (%d total, %d excluded)", ErrNoProxyAvailable, n, len(exclude))
	}

	if p.cfg.Strategy == StrategySticky && key != "" {
		p.stickyMu.Lock()
		if len(p.sticky) >= maxStickyEntries {
			for k, e := range p.sticky {
				if !now.Before(e.expires) {
					delete(p.sticky, k)
				}
			}
			if len(p.sticky) >= maxStickyEntries {
				clear(p.sticky)
			}
		}
		p.sticky[key] = stickyEntry{proxy: chosen, expires: now.Add(p.cfg.StickyTTL.Std())}
		p.stickyMu.Unlock()
	}
	chosen.uses.Add(1)
	return chosen, nil
}

func (p *Pool) pickRoundRobin(proxies []*Proxy, now time.Time, exclude map[*Proxy]struct{}) *Proxy {
	n := len(proxies)
	start := int((p.rr.Add(1) - 1) % uint64(n))
	for i := 0; i < n; i++ {
		pr := proxies[(start+i)%n]
		if !inSet(exclude, pr) && pr.available(now) {
			return pr
		}
	}
	return nil
}

func (p *Pool) pickRandom(proxies []*Proxy, now time.Time, exclude map[*Proxy]struct{}) *Proxy {
	n := len(proxies)
	start := rand.IntN(n)
	for i := 0; i < n; i++ {
		pr := proxies[(start+i)%n]
		if !inSet(exclude, pr) && pr.available(now) {
			return pr
		}
	}
	return nil
}

func (p *Pool) pickLeastUsed(proxies []*Proxy, now time.Time, exclude map[*Proxy]struct{}) *Proxy {
	var chosen *Proxy
	var least uint64
	for _, pr := range proxies {
		if inSet(exclude, pr) || !pr.available(now) {
			continue
		}
		u := pr.uses.Load()
		if chosen == nil || u < least {
			chosen = pr
			least = u
		}
	}
	return chosen
}

func (p *Pool) pickLatencyAware(proxies []*Proxy, now time.Time, exclude map[*Proxy]struct{}) *Proxy {
	var chosen *Proxy
	var best time.Duration
	for _, pr := range proxies {
		if inSet(exclude, pr) || !pr.available(now) {
			continue
		}
		pr.mu.Lock()
		lat := pr.latency
		pr.mu.Unlock()
		if lat <= 0 {
			lat = 24 * time.Hour // unknown latency: deprioritize vs measured
		}
		if chosen == nil || lat < best {
			chosen = pr
			best = lat
		}
	}
	return chosen
}

func (p *Pool) pickThompson(proxies []*Proxy, now time.Time, exclude map[*Proxy]struct{}) *Proxy {
	var chosen *Proxy
	bestScore := -1.0
	for _, pr := range proxies {
		if inSet(exclude, pr) || !pr.available(now) {
			continue
		}
		alpha := float64(pr.successes.Load()) + 1.0
		beta := float64(pr.failuresTotal.Load()) + 1.0
		sample := sampleBeta(alpha, beta)
		// Latency stability penalty: prefer lower EWMA latency.
		pr.mu.Lock()
		lat := pr.latency
		pr.mu.Unlock()
		latPenalty := 1.0
		if lat > 0 {
			ms := float64(lat.Milliseconds())
			latPenalty = 1.0 / (1.0 + ms/1000.0)
		}
		score := sample * latPenalty
		if chosen == nil || score > bestScore {
			chosen = pr
			bestScore = score
		}
	}
	return chosen
}

func sampleBeta(alpha, beta float64) float64 {
	x := sampleGamma(alpha)
	y := sampleGamma(beta)
	if x+y == 0 {
		return 0
	}
	return x / (x + y)
}

func sampleGamma(alpha float64) float64 {
	if alpha <= 0 {
		return 0
	}
	// Marsaglia and Tsang's method for alpha >= 1, boost for alpha < 1.
	if alpha < 1 {
		return sampleGamma(alpha+1) * math.Pow(rand.Float64(), 1/alpha)
	}
	d := alpha - 1.0/3.0
	c := 1.0 / math.Sqrt(9*d)
	for {
		x := rand.NormFloat64()
		v := 1 + c*x
		if v <= 0 {
			continue
		}
		v = v * v * v
		u := rand.Float64()
		if u < 1-0.0331*(x*x)*(x*x) {
			return d * v
		}
		if math.Log(u) < 0.5*x*x+d*(1-v+math.Log(v)) {
			return d * v
		}
	}
}

func inSet(set map[*Proxy]struct{}, p *Proxy) bool {
	_, ok := set[p]
	return ok
}

// ErrNoSniper is returned when no proxy qualifies for the SniperTier reserve.
var ErrNoSniper = errors.New("omnislash: no sniper-tier proxy available")

// AcquireSniper returns a proxy reserved for final synchronized series and
// cross-proxy verification. It never falls back to Infantry.
func (p *Pool) AcquireSniper(ctx context.Context) (*Proxy, error) {
	if p.closed.Load() {
		return nil, ErrPoolClosed
	}
	if _, err := p.WaitGlobal(ctx); err != nil {
		return nil, err
	}
	if err := p.Allow(); err != nil {
		return nil, err
	}
	now := p.now()
	var candidates []*Proxy
	for _, pr := range p.snapshot() {
		if !pr.available(now) {
			continue
		}
		if pr.tierLocked(now) != TierSniper {
			continue
		}
		candidates = append(candidates, pr)
	}
	if len(candidates) == 0 {
		return nil, ErrNoSniper
	}
	var chosen *Proxy
	switch p.cfg.Strategy {
	case StrategyRandom:
		chosen = p.pickRandom(candidates, now, nil)
	case StrategyLeastUsed:
		chosen = p.pickLeastUsed(candidates, now, nil)
	case StrategyLatencyAware:
		chosen = p.pickLatencyAware(candidates, now, nil)
	case StrategyThompson:
		chosen = p.pickThompson(candidates, now, nil)
	default:
		chosen = p.pickRoundRobin(candidates, now, nil)
	}
	if chosen == nil {
		return nil, ErrNoSniper
	}
	chosen.uses.Add(1)
	return chosen, nil
}

// SniperCount returns the number of currently eligible SniperTier proxies.
func (p *Pool) SniperCount() int {
	now := p.now()
	n := 0
	for _, pr := range p.snapshot() {
		if pr.available(now) && pr.tierLocked(now) == TierSniper {
			n++
		}
	}
	return n
}

// InfantryCount returns the number of available InfantryTier proxies.
func (p *Pool) InfantryCount() int {
	now := p.now()
	n := 0
	for _, pr := range p.snapshot() {
		if pr.available(now) && pr.tierLocked(now) == TierInfantry {
			n++
		}
	}
	return n
}
