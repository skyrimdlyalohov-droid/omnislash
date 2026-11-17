package omnislash

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gocolly/colly/v2"
)

var (
	proxyURLPattern      = regexp.MustCompile(`(?i)\b(?:https?|socks5h?)://[^\s"'<>]+`)
	proxyHostPortPattern = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}\b`)
	proxyHostNamePattern = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}:\d{1,5}\b`)
)

// ScraperStats is the point-in-time state of the scraper.
type ScraperStats struct {
	Running      bool       `json:"running"`
	StartedAt    *time.Time `json:"started_at,omitempty"`
	FinishedAt   *time.Time `json:"finished_at,omitempty"`
	DurationMS   float64    `json:"duration_ms"`
	Sources      int        `json:"sources"`
	SourceErrors int        `json:"source_errors"`
	Candidates   int        `json:"candidates"`
	Validated    int        `json:"validated"`
	Accepted     int        `json:"accepted"`
	Rejected     int        `json:"rejected"`
	PoolSize     int        `json:"pool_size"`
	LastError    string     `json:"last_error,omitempty"`
}

// Scraper periodically downloads proxy lists with Colly, validates candidates
// with a browser/mobile TLS fingerprint and atomically replaces the pool. A
// refresh that produces fewer than MinPoolSize verified proxies is discarded so
// a bad scrape never empties a working pool.
type Scraper struct {
	pool      *Pool
	cfg       ScraperConfig
	log       *slog.Logger
	validator *Validator

	runMu sync.Mutex

	statsMu sync.RWMutex
	stats   ScraperStats

	now func() time.Time
}

// NewScraper creates a scraper for pool. It does not start any network activity.
func NewScraper(pool *Pool, cfg ScraperConfig, logger *slog.Logger) (*Scraper, error) {
	if pool == nil {
		return nil, fmt.Errorf("scraper: nil pool")
	}
	if !cfg.Enabled {
		return nil, fmt.Errorf("scraper is disabled")
	}
	if len(cfg.Sources) == 0 {
		return nil, fmt.Errorf("scraper requires at least one source")
	}
	if logger == nil {
		logger = pool.log
	}
	s := &Scraper{
		pool: pool,
		cfg:  cfg,
		log:  logger,
		now:  time.Now,
		stats: ScraperStats{
			Sources:  len(cfg.Sources),
			PoolSize: pool.Len(),
		},
	}
	if cfg.Validation.Enabled {
		v, err := NewValidator(cfg.Validation, logger)
		if err != nil {
			return nil, err
		}
		s.validator = v
	}
	pool.SetScraperStats(s.Stats)
	return s, nil
}

// Stats returns the latest scraper snapshot.
func (s *Scraper) Stats() ScraperStats {
	s.statsMu.RLock()
	defer s.statsMu.RUnlock()
	return s.stats
}

// Refresh downloads all sources, validates candidates and hot-swaps the pool.
// The returned error describes a failed or discarded refresh; the previous pool
// contents are left untouched in that case.
func (s *Scraper) Refresh(ctx context.Context) (ScraperStats, error) {
	s.runMu.Lock()
	defer s.runMu.Unlock()

	started := s.now()
	st := ScraperStats{
		Running:   true,
		StartedAt: &started,
		Sources:   len(s.cfg.Sources),
		PoolSize:  s.pool.Len(),
	}
	s.storeStats(st)
	defer func() {
		finished := s.now()
		st.Running = false
		st.FinishedAt = &finished
		st.DurationMS = float64(finished.Sub(started).Microseconds()) / 1000
		st.PoolSize = s.pool.Len()
		s.storeStats(st)
	}()

	candidates, sourceErrors := s.fetchAll(ctx)
	st.SourceErrors = sourceErrors
	st.Candidates = len(candidates)
	if ctx.Err() != nil {
		st.LastError = ctx.Err().Error()
		return st, ctx.Err()
	}

	shuffleProxies(candidates)
	if max := s.cfg.MaxCandidates; max > 0 && len(candidates) > max {
		candidates = candidates[:max]
		st.Candidates = len(candidates)
	}

	if s.validator != nil && s.cfg.Validation.RequireDistinctFromRealIP {
		if _, err := s.validator.RealIP(ctx); err != nil {
			st.LastError = fmt.Sprintf("determine real IP: %v", err)
			s.log.Warn("scrape discarded: cannot determine real IP", "error", err)
			return st, fmt.Errorf("determine real IP: %w", err)
		}
	}

	accepted, rejected := s.validateAll(ctx, candidates)
	st.Validated = len(candidates)
	st.Accepted = len(accepted)
	st.Rejected = rejected
	s.storeStats(st)

	if ctx.Err() != nil {
		st.LastError = ctx.Err().Error()
		return st, ctx.Err()
	}
	if len(accepted) < s.cfg.MinPoolSize {
		err := fmt.Errorf("verified %d proxies, below min_pool_size %d; keeping the previous pool", len(accepted), s.cfg.MinPoolSize)
		st.LastError = err.Error()
		s.log.Warn("scrape discarded", "verified", len(accepted), "min_pool_size", s.cfg.MinPoolSize)
		return st, err
	}

	s.pool.Replace(accepted)
	s.log.Info("proxy pool refreshed",
		"verified", len(accepted), "rejected", rejected, "candidates", len(candidates),
		"sources", len(s.cfg.Sources), "source_errors", sourceErrors)
	return st, nil
}

// Run performs an optional startup refresh and then periodic refreshes until
// ctx is canceled.
func (s *Scraper) Run(ctx context.Context) {
	if s.cfg.StartupRefresh {
		rctx := ctx
		cancel := func() {}
		if wait := s.cfg.StartupWait.Std(); wait > 0 {
			rctx, cancel = context.WithTimeout(ctx, wait)
		}
		st, err := s.Refresh(rctx)
		cancel()
		if err != nil {
			s.log.Warn("startup scrape failed", "error", err)
		} else {
			s.log.Info("startup scrape finished", "verified", st.Accepted, "pool", st.PoolSize)
		}
	}
	s.RunPeriodic(ctx)
}

// RunPeriodic runs only periodic refreshes. Use it when the startup refresh was
// already performed synchronously.
func (s *Scraper) RunPeriodic(ctx context.Context) {
	ticker := time.NewTicker(s.cfg.RefreshInterval.Std())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := s.Refresh(ctx); err != nil && ctx.Err() == nil {
				s.log.Warn("periodic scrape failed", "error", err)
			}
		}
	}
}

func (s *Scraper) storeStats(st ScraperStats) {
	s.statsMu.Lock()
	s.stats = st
	s.statsMu.Unlock()
}

func (s *Scraper) fetchAll(ctx context.Context) ([]*Proxy, int) {
	type result struct {
		proxies []*Proxy
		err     error
		name    string
	}
	results := make([]result, 0, len(s.cfg.Sources))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, max(1, s.cfg.Concurrency))

	for _, src := range s.cfg.Sources {
		if ctx.Err() != nil {
			break
		}
		src := src
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()

			proxies, err := s.fetchSource(ctx, src)
			mu.Lock()
			results = append(results, result{proxies: proxies, err: err, name: sourceName(src)})
			mu.Unlock()
		}()
	}
	wg.Wait()

	var (
		errs int
		seen = make(map[string]struct{})
		out  []*Proxy
	)
	for _, r := range results {
		if r.err != nil {
			errs++
			if ctx.Err() == nil {
				s.log.Debug("proxy source failed", "source", r.name, "error", r.err)
			}
			continue
		}
		for _, pr := range r.proxies {
			key := pr.key()
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, pr)
		}
	}
	return out, errs
}

func (s *Scraper) fetchSource(ctx context.Context, src SourceConfig) ([]*Proxy, error) {
	rawURL := strings.TrimSpace(src.URL)
	c := colly.NewCollector(
		colly.UserAgent(s.cfg.UserAgent),
		colly.MaxBodySize(int(s.cfg.MaxBodyBytes)),
		colly.MaxDepth(1),
	)
	c.SetRequestTimeout(s.cfg.FetchTimeout.Std())
	c.AllowURLRevisit = true

	var (
		body     []byte
		visitErr error
	)
	c.OnRequest(func(r *colly.Request) {
		if ctx.Err() != nil {
			r.Abort()
			return
		}
		for k, v := range src.Headers {
			r.Headers.Set(k, v)
		}
	})
	c.OnResponse(func(r *colly.Response) {
		body = append([]byte(nil), r.Body...)
	})
	c.OnError(func(_ *colly.Response, err error) {
		visitErr = err
	})
	if err := c.Visit(rawURL); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if visitErr != nil {
			return nil, visitErr
		}
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if visitErr != nil {
		return nil, visitErr
	}

	scheme := strings.ToLower(strings.TrimSpace(src.Scheme))
	typ := strings.ToLower(strings.TrimSpace(src.Type))
	if typ == "" {
		typ = "text"
	}
	return s.extractProxies(body, typ, src.Regex, scheme), nil
}

func (s *Scraper) extractProxies(body []byte, typ, rawRegex, scheme string) []*Proxy {
	var tokens []string
	if typ == "regex" {
		re, err := regexp.Compile(rawRegex)
		if err != nil {
			return nil
		}
		for _, m := range re.FindAllSubmatch(body, -1) {
			if len(m) > 1 && len(m[1]) > 0 {
				tokens = append(tokens, string(m[1]))
			} else {
				tokens = append(tokens, string(m[0]))
			}
		}
	} else {
		tokens = append(tokens, strings.Split(string(body), "\n")...)
		text := string(body)
		tokens = append(tokens, proxyURLPattern.FindAllString(text, -1)...)
		tokens = append(tokens, proxyHostPortPattern.FindAllString(text, -1)...)
		tokens = append(tokens, proxyHostNamePattern.FindAllString(text, -1)...)
	}
	if scheme == "" {
		scheme = s.pool.cfg.DefaultScheme
	}

	seen := make(map[string]struct{}, len(tokens))
	out := make([]*Proxy, 0, len(tokens))
	for _, token := range tokens {
		for _, candidate := range splitProxyCandidates(token) {
			pr, err := NewProxy(candidate, scheme)
			if err != nil {
				continue
			}
			if _, ok := seen[pr.key()]; ok {
				continue
			}
			seen[pr.key()] = struct{}{}
			out = append(out, pr)
		}
	}
	return out
}

func splitProxyCandidates(token string) []string {
	token = strings.TrimSpace(token)
	if token == "" || strings.HasPrefix(token, "#") {
		return nil
	}
	fields := strings.FieldsFunc(token, func(r rune) bool {
		switch r {
		case ' ', '\t', '\r', '\n', ',', ';', '"', '\'', '<', '>', '|':
			return true
		}
		return false
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		f = strings.Trim(f, "(){}.,;:'\"")
		if f == "" {
			continue
		}
		out = append(out, f)
	}
	return out
}

func (s *Scraper) validateAll(ctx context.Context, candidates []*Proxy) ([]*Proxy, int) {
	if s.validator == nil {
		return candidates, 0
	}
	type result struct {
		pr  *Proxy
		res ValidationResult
		err error
	}
	concurrency := s.cfg.Validation.Concurrency
	if concurrency < 1 {
		concurrency = 1
	}
	sem := make(chan struct{}, concurrency)
	results := make(chan result, len(candidates))
	var wg sync.WaitGroup

	for _, pr := range candidates {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(pr *Proxy) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()

			vctx := ctx
			cancel := func() {}
			if timeout := s.cfg.Validation.Timeout.Std(); timeout > 0 {
				vctx, cancel = context.WithTimeout(ctx, timeout)
			}
			res, err := s.validator.Validate(vctx, pr)
			cancel()
			results <- result{pr: pr, res: res, err: err}
		}(pr)
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	accepted := make([]*Proxy, 0, len(candidates))
	rejected := 0
	for r := range results {
		if r.err != nil {
			rejected++
			if ctx.Err() == nil {
				s.log.Debug("proxy rejected", "proxy", r.pr.Label(), "error", r.err)
			}
			continue
		}
		r.pr.setEgress(r.res.EgressIP, r.res.Latency)
		accepted = append(accepted, r.pr)
	}
	return accepted, rejected
}

func sourceName(src SourceConfig) string {
	if src.Name != "" {
		return src.Name
	}
	return src.URL
}

func shuffleProxies(proxies []*Proxy) {
	rand.Shuffle(len(proxies), func(i, j int) {
		proxies[i], proxies[j] = proxies[j], proxies[i]
	})
}
