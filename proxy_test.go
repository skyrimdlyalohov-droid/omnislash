package omnislash

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewProxy(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		defScheme  string
		wantScheme string
		wantAddr   string
		wantUser   string
		wantPass   string
		wantErr    bool
	}{
		{name: "socks", raw: "socks5://127.0.0.1:1080", wantScheme: "socks5", wantAddr: "127.0.0.1:1080"},
		{name: "socks auth", raw: "socks5://u:p%40ss@example.com:1080", wantScheme: "socks5", wantAddr: "example.com:1080", wantUser: "u", wantPass: "p@ss"},
		{name: "default scheme", raw: "example.com:8080", defScheme: "http", wantScheme: "http", wantAddr: "example.com:8080"},
		{name: "ipv6", raw: "http://[::1]:8080", wantScheme: "http", wantAddr: "[::1]:8080"},
		{name: "empty", raw: "", wantErr: true},
		{name: "no port", raw: "socks5://example.com", wantErr: true},
		{name: "bad scheme", raw: "ftp://example.com:21", wantErr: true},
		{name: "path", raw: "socks5://example.com:1080/path", wantErr: true},
		{name: "bad port", raw: "socks5://example.com:99999", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := NewProxy(tt.raw, tt.defScheme)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %+v", p)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if p.Scheme != tt.wantScheme || p.Addr != tt.wantAddr || p.Username != tt.wantUser || p.Password != tt.wantPass {
				t.Fatalf("got %+v", p)
			}
			if strings.Contains(p.Label(), tt.wantPass) && tt.wantPass != "" {
				t.Fatalf("Label leaked password: %q", p.Label())
			}
		})
	}
}

func TestParseProxyList(t *testing.T) {
	list := "# comment\n\nsocks5://127.0.0.1:1080\nhttp://127.0.0.1:8080\n127.0.0.1:1080\n"
	proxies, err := ParseProxyList(strings.NewReader(list), "socks5")
	if err != nil {
		t.Fatal(err)
	}
	if len(proxies) != 2 {
		t.Fatalf("want 2 unique proxies, got %d", len(proxies))
	}
	bad := "socks5://127.0.0.1:1080\nnot a proxy\n"
	if _, err := ParseProxyList(strings.NewReader(bad), "socks5"); err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("want line error, got %v", err)
	}
	if _, err := ParseProxyList(strings.NewReader("# only comments\n"), "socks5"); err == nil {
		t.Fatal("expected empty list error")
	}
}

func TestMarkFailureBackoffAndRecovery(t *testing.T) {
	p := mustProxy(t, "socks5://127.0.0.1:1080")
	now := time.Now()
	cfg := CooldownConfig{
		Initial:                Duration(time.Second),
		Max:                    Duration(4 * time.Second),
		Multiplier:             2,
		FailuresBeforeCooldown: 1,
	}
	if !p.available(now) {
		t.Fatal("new proxy must be available")
	}
	p.markFailure(now, os.ErrDeadlineExceeded, cfg)
	if p.available(now) {
		t.Fatal("failed proxy must be in cooldown")
	}
	st := p.stats(now)
	if st.InCooldown != true || st.ConsecutiveFailures != 1 {
		t.Fatalf("unexpected stats: %+v", st)
	}
	p.markFailure(now, os.ErrDeadlineExceeded, cfg)
	st = p.stats(now)
	if st.ConsecutiveFailures != 2 || st.CooldownUntil == nil || st.CooldownUntil.Sub(now) != 2*time.Second {
		t.Fatalf("unexpected backoff: %+v", st)
	}
	p.markSuccess(now, 10*time.Millisecond)
	st = p.stats(now)
	if !st.Available || st.ConsecutiveFailures != 0 || st.LatencyMS != 10 {
		t.Fatalf("unexpected success stats: %+v", st)
	}
}

func TestConfigDefaultsAndOverride(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	data := `{
		"strategy": "least_used",
		"dial_timeout": "3s",
		"health": {"probe_url": "http://127.0.0.1:1/health"},
		"http": {"max_retries": 7}
	}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Strategy != StrategyLeastUsed || cfg.DialTimeout.Std() != 3*time.Second {
		t.Fatalf("overrides not applied: %+v", cfg)
	}
	if cfg.HandshakeTimeout.Std() != 15*time.Second {
		t.Fatalf("defaults not preserved: %+v", cfg)
	}
	if cfg.HTTP.MaxRetries != 7 || len(cfg.HTTP.BanStatuses) == 0 {
		t.Fatalf("http config not merged: %+v", cfg.HTTP)
	}
	if cfg.Health.Interval.Std() != time.Minute {
		t.Fatalf("health default not preserved: %+v", cfg.Health)
	}
}

func TestConfigRejectsUnknownField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"nope": 1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("expected unknown field error")
	}
}

func TestConfigValidation(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Strategy = "nonsense"
	cfg.Cooldown.Max = Duration(time.Second)
	cfg.Cooldown.Initial = Duration(time.Minute)
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error")
	}
}
