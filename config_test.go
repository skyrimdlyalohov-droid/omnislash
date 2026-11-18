package omnislash

import (
	"strings"
	"testing"
)

func TestStrictTierForbidsDirectFallback(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AllowDirect = true
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "allow_direct is forbidden") {
		t.Fatalf("strict allow_direct validation = %v", err)
	}
	cfg.TrustTier = TrustTierTrusted
	if err := cfg.Validate(); err != nil {
		t.Fatalf("trusted allow_direct rejected: %v", err)
	}
}

func TestStrictConnectForbidsAdmissionSkipVerify(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Scraper.Enabled = true
	cfg.Scraper.Sources = []SourceConfig{{URL: "https://example.com/list.txt", Type: "text"}}
	cfg.Scraper.Validation.Admission.TLSSkipVerify = true
	cfg.Scraper.Validation.Admission.TLSCanaryURL = "https://api.ipify.org"
	cfg.Scraper.Validation.Mode = AdmissionModeConnect
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "tls_skip_verify is forbidden") {
		t.Fatalf("strict admission skip-verify validation = %v", err)
	}
}

func TestHTTPParsingAdmissionRequiresEcho(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Scraper.Enabled = true
	cfg.Scraper.Sources = []SourceConfig{{URL: "https://example.com/list.txt", Type: "text"}}
	cfg.Scraper.Validation.Mode = AdmissionModeHTTPParsing
	cfg.Scraper.Validation.Admission.Enabled = true
	cfg.Scraper.Validation.Admission.EchoAddr = ""
	cfg.Scraper.Validation.Admission.TLSCanaryURL = "https://api.ipify.org"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "requires admission.echo_addr") {
		t.Fatalf("http_parsing echo validation = %v", err)
	}
}

func TestDefaultConfigIsValid(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config is invalid: %v", err)
	}
	if cfg.TrustTier != TrustTierStrict || cfg.AllowDirect {
		t.Fatalf("unsafe defaults: tier=%s allow_direct=%v", cfg.TrustTier, cfg.AllowDirect)
	}
	if cfg.Scraper.Validation.Admission.Timeout <= 0 || cfg.Scraper.Validation.Admission.Hold <= 0 {
		t.Fatal("default admission timings were not normalized")
	}
}

func TestExampleConfigLoads(t *testing.T) {
	cfg, err := LoadConfig("config.example.json")
	if err != nil {
		t.Fatalf("config.example.json: %v", err)
	}
	if cfg.TrustTier != TrustTierStrict {
		t.Fatalf("example trust tier = %q", cfg.TrustTier)
	}
	if !cfg.Scope.Enabled {
		t.Fatal("example must keep scope enabled")
	}
	if cfg.Scraper.Validation.Mode != AdmissionModeConnect {
		t.Fatalf("example validation mode = %q", cfg.Scraper.Validation.Mode)
	}
}
