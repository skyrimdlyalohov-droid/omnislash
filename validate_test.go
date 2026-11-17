package omnislash

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestParseIPFromBody(t *testing.T) {
	cases := []struct {
		body string
		want string
		ok   bool
	}{
		{"1.2.3.4\n", "1.2.3.4", true},
		{`{"ip":"5.6.7.8"}`, "5.6.7.8", true},
		{"Your IP address is 9.10.11.12.", "9.10.11.12", true},
		{"no address here", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		ip, err := parseIPFromBody([]byte(tc.body))
		if tc.ok {
			if err != nil || ip.String() != tc.want {
				t.Fatalf("parseIPFromBody(%q) = %v, %v; want %s", tc.body, ip, err, tc.want)
			}
			continue
		}
		if err == nil {
			t.Fatalf("parseIPFromBody(%q) unexpectedly succeeded", tc.body)
		}
	}
}

func TestProxyURLForKeepsCredentials(t *testing.T) {
	pr := mustProxy(t, "http://user:secret@127.0.0.1:8080")
	if got, want := proxyURLFor(pr), "http://user:secret@127.0.0.1:8080"; got != want {
		t.Fatalf("proxyURLFor = %q, want %q", got, want)
	}
}

func validationTestConfig(canary string, realIP string) ValidationConfig {
	return ValidationConfig{
		Enabled:                   true,
		CanaryURLs:                []string{canary},
		RealIP:                    realIP,
		Timeout:                   Duration(5 * time.Second),
		Concurrency:               1,
		Attempts:                  1,
		MinCanaries:               1,
		RequireSameEgressIP:       true,
		RequireDistinctFromRealIP: realIP != "",
		TLSSkipVerify:             true,
		AllowPrivateEgress:        true,
		Profile:                   "safari_ios_26_0",
		MaxBodyBytes:              1024,
	}
}

func TestValidatorAcceptsWorkingProxy(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "127.0.0.1\n")
	}))
	defer srv.Close()
	proxy := startConnectProxy(t, "")

	v, err := NewValidator(validationTestConfig(srv.URL, ""), testLogger())
	if err != nil {
		t.Fatal(err)
	}
	res, err := v.Validate(context.Background(), mustProxy(t, proxy.URL()))
	if err != nil {
		t.Fatal(err)
	}
	if res.EgressIP != "127.0.0.1" || res.Canaries != 1 {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestValidatorRejectsRealIP(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "9.9.9.9\n")
	}))
	defer srv.Close()
	proxy := startConnectProxy(t, "")

	v, err := NewValidator(validationTestConfig(srv.URL, "9.9.9.9"), testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Validate(context.Background(), mustProxy(t, proxy.URL())); err == nil {
		t.Fatal("expected proxy with the scanner's real IP to be rejected")
	}
}

func TestValidatorRejectsNonPublicEgress(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "10.0.0.5\n")
	}))
	defer srv.Close()
	proxy := startConnectProxy(t, "")

	cfg := validationTestConfig(srv.URL, "")
	cfg.AllowPrivateEgress = false
	v, err := NewValidator(cfg, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Validate(context.Background(), mustProxy(t, proxy.URL())); err == nil {
		t.Fatal("expected private egress to be rejected")
	}
}

func TestValidatorRetriesTransientRealIPFailure(t *testing.T) {
	var calls int
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls == 1 {
			http.Error(w, "temporary", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprint(w, "203.0.113.10\n")
	}))
	defer srv.Close()

	cfg := validationTestConfig("", "")
	cfg.RealIPURL = srv.URL
	cfg.TLSSkipVerify = true
	cfg.AllowPrivateEgress = false
	v, err := NewValidator(cfg, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.RealIP(context.Background()); err == nil {
		t.Fatal("expected the first real IP lookup to fail")
	}
	ip, err := v.RealIP(context.Background())
	if err != nil {
		t.Fatalf("transient failure was cached: %v", err)
	}
	if ip.String() != "203.0.113.10" {
		t.Fatalf("real IP = %s, want 203.0.113.10", ip)
	}
}
