package omnislash

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
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

func inSet(set map[*Proxy]struct{}, p *Proxy) bool {
	_, ok := set[p]
	return ok
}
