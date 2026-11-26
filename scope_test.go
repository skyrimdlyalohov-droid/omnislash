package omnislash

import (
	"context"
	"net"
	"strings"
	"testing"
)

func TestScopeDeniesPrivateAndMetadata(t *testing.T) {
	s, err := NewScope(ScopeConfig{
		Enabled:    true,
		AllowHosts: []string{"localhost", "example.com", "10.0.0.1", "169.254.169.254"},
	})
	if err != nil {
		t.Fatal(err)
	}
	s.lookup = func(_ context.Context, host string) ([]net.IP, error) {
		if host == "example.com" {
			return []net.IP{net.ParseIP("93.184.216.34")}, nil
		}
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}
	for _, target := range []string{
		"127.0.0.1:443",
		"localhost:80",
		"10.0.0.1:80",
		"169.254.169.254:80",
		"[::1]:80",
	} {
		if _, err := s.CheckTarget(context.Background(), target); err == nil {
			t.Fatalf("expected %s to be blocked", target)
		}
	}
	if got, err := s.CheckTarget(context.Background(), "example.com:443"); err != nil || got != "example.com:443" {
		t.Fatalf("public host rejected: got %q, err %v", got, err)
	}
}

func TestScopeAllowPrivateStillDeniesMetadata(t *testing.T) {
	s, err := NewScope(ScopeConfig{
		Enabled:      true,
		AllowHosts:   []string{"127.0.0.1", "169.254.169.254"},
		AllowPrivate: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CheckTarget(context.Background(), "127.0.0.1:8080"); err != nil {
		t.Fatalf("allow_private should permit loopback: %v", err)
	}
	if _, err := s.CheckTarget(context.Background(), "169.254.169.254:80"); err == nil {
		t.Fatal("metadata address must stay denied with allow_private")
	}
}

func TestScopeAllowPorts(t *testing.T) {
	s, err := NewScope(ScopeConfig{
		Enabled:    true,
		AllowHosts: []string{"example.com"},
		AllowPorts: []int{443},
	})
	if err != nil {
		t.Fatal(err)
	}
	s.lookup = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("93.184.216.34")}, nil
	}
	if _, err := s.CheckTarget(context.Background(), "example.com:80"); err == nil {
		t.Fatal("port 80 should be rejected")
	}
	if _, err := s.CheckTarget(context.Background(), "example.com:443"); err != nil {
		t.Fatalf("port 443 should be allowed: %v", err)
	}
}

func TestScopeResolveLocallyPinsAllowedAddress(t *testing.T) {
	s, err := NewScope(ScopeConfig{
		Enabled:        true,
		AllowHosts:     []string{"pinned.example"},
		ResolveLocally: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	s.lookup = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("93.184.216.34")}, nil
	}
	got, err := s.CheckTarget(context.Background(), "pinned.example:8443")
	if err != nil {
		t.Fatal(err)
	}
	if got != "93.184.216.34:8443" {
		t.Fatalf("got %q, want pinned address", got)
	}
	// The pinned literal is already approved: a second scope check must not
	// fail with "target IP is not allowed", and TLS must recover the domain.
	if got, err := s.CheckTarget(context.Background(), "93.184.216.34:8443"); err != nil || got != "93.184.216.34:8443" {
		t.Fatalf("pinned IP re-check failed: got %q, err %v", got, err)
	}
	if host := s.OriginalHost("93.184.216.34:8443"); host != "pinned.example" {
		t.Fatalf("OriginalHost = %q, want pinned.example", host)
	}
	if _, err := s.CheckTarget(context.Background(), "93.184.216.34:9443"); err == nil {
		t.Fatal("pinned IP must not approve a different port")
	}
}

func TestScopeRejectsHostnameResolvingToPrivate(t *testing.T) {
	s, err := NewScope(ScopeConfig{
		Enabled:        true,
		AllowHosts:     []string{"evil.example"},
		ResolveLocally: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	s.lookup = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}
	if _, err := s.CheckTarget(context.Background(), "evil.example:443"); err == nil {
		t.Fatal("hostname resolving to loopback must be rejected")
	}
}

func TestScopeAllowCIDROnly(t *testing.T) {
	s, err := NewScope(ScopeConfig{
		Enabled:        true,
		AllowCIDRs:     []string{"93.184.216.0/24"},
		ResolveLocally: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	s.lookup = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("93.184.216.34")}, nil
	}
	if _, err := s.CheckTarget(context.Background(), "any.example:443"); err != nil {
		t.Fatalf("address inside allow_cidrs rejected: %v", err)
	}
	s.lookup = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("10.0.0.1")}, nil
	}
	if _, err := s.CheckTarget(context.Background(), "other.example:443"); err == nil {
		t.Fatal("address outside allow_cidrs must be rejected")
	}
}

func TestDialerScopeRejectsBeforeDial(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Scope = ScopeConfig{Enabled: true, AllowHosts: []string{"allowed.example"}}
	pool := newTestPool(t, cfg, mustProxy(t, "socks5://127.0.0.1:1"))
	d := NewDialer(pool, testLogger())
	_, err := d.DialContext(context.Background(), "tcp", "blocked.example:80")
	if err == nil || !strings.Contains(err.Error(), "scope") {
		t.Fatalf("expected scope rejection, got %v", err)
	}
}
