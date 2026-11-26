package omnislash

import (
	"context"
	"fmt"
	"net"
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
	// These tests exercise extraction/hot-swap only; the funnel has its own
	// fixtures with real local CONNECT/SOCKS5 listeners.
	cfg.Scraper.Prefilter.Enabled = false
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

func TestScraperPrefilterDropsDeadProxiesBeforeValidation(t *testing.T) {
	// The fast stage only needs a TCP target: no HTTP is sent through it.
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		for {
			conn, err := target.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Read(make([]byte, 1))
			}(conn)
		}
	}()

	live := startConnectProxy(t, "")
	dead := "http://" + freeAddr(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "%s\n%s\n", live.URL(), dead)
	}))
	defer srv.Close()

	cfg := scraperTestConfig(SourceConfig{URL: srv.URL, Type: "text", Scheme: "http"})
	cfg.Scraper.Prefilter.Enabled = true
	cfg.Scraper.Prefilter.Concurrency = 128
	cfg.Scraper.Prefilter.Timeout = Duration(400 * time.Millisecond)
	cfg.Scraper.Validation.Admission.EchoAddr = target.Addr().String()
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
		t.Fatalf("refresh: %v", err)
	}
	if stats.Prefiltered != 1 || stats.Accepted != 1 {
		t.Fatalf("prefiltered=%d accepted=%d, want 1/1", stats.Prefiltered, stats.Accepted)
	}
	if stats.DurationMS <= 0 {
		t.Fatalf("Refresh returned duration %v, want a measured value", stats.DurationMS)
	}
	if stats.Infantry+stats.Sniper != stats.Accepted {
		t.Fatalf("tier counters infantry=%d sniper=%d, want %d accepted", stats.Infantry, stats.Sniper, stats.Accepted)
	}
	if pool.Len() != 1 || pool.Proxies()[0].Addr != live.addr {
		t.Fatalf("pool did not keep only the live proxy: %+v", pool.Proxies())
	}
	if live.connects.Load() != 1 {
		t.Fatalf("live CONNECT count = %d, want 1", live.connects.Load())
	}
}

func TestCachedPoolDoesNotBlockOnStartupRefresh(t *testing.T) {
	hit := make(chan struct{}, 1)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {
		case hit <- struct{}{}:
		default:
		}
		<-release
		_, _ = w.Write([]byte("1.2.3.4:8080"))
	}))
	defer srv.Close()
	defer close(release)

	cfg := scraperTestConfig(SourceConfig{URL: srv.URL, Type: "text", Scheme: "http"})
	cfg.Scraper.StartupWait = Duration(5 * time.Second)
	cached := mustProxy(t, "http://127.0.0.1:3128")
	pool, err := NewPool(&cfg, []*Proxy{cached}, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewScraper(pool, cfg.Scraper, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		s.Run(ctx)
		close(done)
	}()
	select {
	case <-hit:
	case <-time.After(2 * time.Second):
		t.Fatal("background startup refresh was not launched")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("cached startup blocked service on a slow source")
	}
}

func TestSplitProxyCandidates(t *testing.T) {
	got := splitProxyCandidates(`http://1.2.3.4:8080, 5.6.7.8:1080;`)
	want := []string{"http://1.2.3.4:8080", "5.6.7.8:1080"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %v, want %v", got, want)
	}
}
