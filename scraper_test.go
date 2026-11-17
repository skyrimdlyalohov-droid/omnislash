package omnislash

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func scraperTestConfig(sources ...SourceConfig) Config {
	cfg := DefaultConfig()
	cfg.Scraper.Enabled = true
	cfg.Scraper.Sources = sources
	cfg.Scraper.Validation.Enabled = false
	cfg.Scraper.MinPoolSize = 1
	cfg.Scraper.MaxCandidates = 100
	cfg.Scraper.Concurrency = 2
	cfg.Scraper.FetchTimeout = Duration(3 * time.Second)
	cfg.Scraper.RefreshInterval = Duration(time.Hour)
	cfg.Scraper.StartupWait = Duration(5 * time.Second)
	cfg.Scraper.MaxBodyBytes = 1 << 20
	return cfg
}

func TestScraperExtractsTextList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "# free proxies\n1.1.1.1:8080\nhttp://2.2.2.2:3128\n\n")
	}))
	defer srv.Close()

	cfg := scraperTestConfig(SourceConfig{URL: srv.URL, Type: "text", Scheme: "http"})
	pool, err := NewPool(&cfg, nil, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewScraper(pool, cfg.Scraper, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	stats, err := s.Refresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Candidates != 2 || stats.Accepted != 2 {
		t.Fatalf("candidates=%d accepted=%d, want 2/2", stats.Candidates, stats.Accepted)
	}
	if pool.Len() != 2 {
		t.Fatalf("pool len = %d, want 2", pool.Len())
	}
	for _, pr := range pool.Proxies() {
		if pr.Scheme != "http" {
			t.Fatalf("proxy %s has scheme %q, want http", pr.Label(), pr.Scheme)
		}
	}
	if pool.Stats().Scraper == nil {
		t.Fatal("scraper stats are not registered on the pool")
	}
}

func TestScraperExtractsRegexList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `<a data-proxy="3.3.3.3:1080">x</a> <a data-proxy="4.4.4.4:1080">y</a>`)
	}))
	defer srv.Close()

	cfg := scraperTestConfig(SourceConfig{
		URL:    srv.URL,
		Type:   "regex",
		Regex:  `data-proxy="([^"]+)"`,
		Scheme: "socks5",
	})
	pool, err := NewPool(&cfg, nil, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewScraper(pool, cfg.Scraper, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if pool.Len() != 2 {
		t.Fatalf("pool len = %d, want 2", pool.Len())
	}
	for _, pr := range pool.Proxies() {
		if pr.Scheme != "socks5" {
			t.Fatalf("scheme = %q, want socks5", pr.Scheme)
		}
	}
}

func TestScraperKeepsPreviousPoolOnBadRefresh(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "this page has no proxies")
	}))
	defer srv.Close()

	cfg := scraperTestConfig(SourceConfig{URL: srv.URL, Type: "text", Scheme: "http"})
	old := mustProxy(t, "http://127.0.0.1:3128")
	pool, err := NewPool(&cfg, []*Proxy{old}, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewScraper(pool, cfg.Scraper, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	stats, err := s.Refresh(context.Background())
	if err == nil {
		t.Fatal("expected refresh error when no proxies were verified")
	}
	if stats.Accepted != 0 || stats.LastError == "" {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	if pool.Len() != 1 || pool.Proxies()[0] != old {
		t.Fatal("previous pool was not preserved")
	}
}

func TestScraperHotSwapPreservesProxyState(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "5.5.5.5:8080\n")
	}))
	defer srv.Close()

	cfg := scraperTestConfig(SourceConfig{URL: srv.URL, Type: "text", Scheme: "http"})
	old := mustProxy(t, "http://5.5.5.5:8080")
	old.markSuccess(time.Now(), time.Millisecond)
	pool, err := NewPool(&cfg, []*Proxy{old}, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewScraper(pool, cfg.Scraper, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if pool.Len() != 1 || pool.Proxies()[0] != old {
		t.Fatal("existing proxy state was not preserved")
	}
	if pool.Stats().Proxies[0].Successes != 1 {
		t.Fatal("success counter was reset by hot swap")
	}
}

func TestSplitProxyCandidates(t *testing.T) {
	got := splitProxyCandidates(`http://1.2.3.4:8080, 5.6.7.8:1080;`)
	want := []string{"http://1.2.3.4:8080", "5.6.7.8:1080"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %v, want %v", got, want)
	}
}
