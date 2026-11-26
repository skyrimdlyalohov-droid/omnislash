package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/skyrimdlyalohov-droid/omnislash"
)

// scriptedDoer returns canned responses and refuses any non-GET request, so a
// resolver bug that replays a probe payload is caught immediately.
type scriptedDoer struct {
	t         *testing.T
	responses []scriptedResponse
	requests  int
}

type scriptedResponse struct {
	status   int
	location string
}

func (f *scriptedDoer) Do(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodGet {
		f.t.Errorf("redirect pre-flight used %s, want GET", req.Method)
	}
	f.requests++
	if len(f.responses) == 0 {
		return nil, errors.New("unexpected redirect request")
	}
	next := f.responses[0]
	f.responses = f.responses[1:]
	header := make(http.Header)
	if next.location != "" {
		header.Set("Location", next.location)
	}
	return &http.Response{
		StatusCode: next.status,
		Header:     header,
		Body:       io.NopCloser(strings.NewReader("")),
	}, nil
}

// recordingScope records every URL the resolver submits to scope.go. Its
// allow map is keyed by host:port, matching Scope.CheckTarget's input.
type recordingScope struct {
	mu      sync.Mutex
	checked []string
	allow   map[string]bool
}

func (s *recordingScope) Enabled() bool { return true }

func (s *recordingScope) CheckTarget(_ context.Context, target string) (string, error) {
	s.mu.Lock()
	s.checked = append(s.checked, target)
	s.mu.Unlock()
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return "", err
	}
	if !s.allow[target] && !s.allow[host] {
		return "", fmt.Errorf("scope: %q is not allowed", target)
	}
	return target, nil
}

func (s *recordingScope) targets() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.checked...)
}

func TestRedirectResolverFollowsChainOnSameHost(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, "/step1", http.StatusMovedPermanently)
		case "/step1":
			http.Redirect(w, r, "/final", http.StatusFound)
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("app"))
		}
	}))
	defer server.Close()

	start, err := url.Parse(server.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(start.Port())
	if err != nil {
		t.Fatal(err)
	}
	scope, err := omnislash.NewScope(omnislash.ScopeConfig{
		Enabled:      true,
		AllowHosts:   []string{"127.0.0.1"},
		AllowPorts:   []int{port},
		AllowPrivate: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resolver := newRedirectResolver(client, scope, []string{"127.0.0.1"}, nil)

	got := resolver.Resolve(context.Background(), start)
	if got == nil || got.Path != "/final" {
		t.Fatalf("resolved URL = %v, want path /final", got)
	}
	if hits.Load() != 3 {
		t.Fatalf("requests = %d, want 3 (301 -> 302 -> 200)", hits.Load())
	}
}

func TestRedirectResolverBlocksHostOutsideAllowHosts(t *testing.T) {
	// The scope fake accepts both hosts: the allow_hosts list alone must stop
	// the redirect, while scope.CheckTarget still sees the Location.
	scope := &recordingScope{allow: map[string]bool{
		"allowed.example:443": true,
		"evil.example:443":    true,
	}}
	doer := &scriptedDoer{t: t, responses: []scriptedResponse{
		{status: http.StatusFound, location: "https://evil.example/login"},
	}}
	resolver := newRedirectResolver(doer, scope, []string{"allowed.example"}, nil)
	start, err := url.Parse("https://allowed.example/")
	if err != nil {
		t.Fatal(err)
	}

	got := resolver.Resolve(context.Background(), start)
	if got == nil || got.String() != start.String() {
		t.Fatalf("resolved URL = %v, want original %v", got, start)
	}
	if doer.requests != 1 {
		t.Fatalf("requests = %d, want 1 (no follow to the blocked host)", doer.requests)
	}
	checked := scope.targets()
	if len(checked) != 2 || checked[1] != "evil.example:443" {
		t.Fatalf("scope checks = %v, want start then evil.example:443", checked)
	}
}

func TestRedirectResolverBlocksPrivateNetwork(t *testing.T) {
	scope, err := omnislash.NewScope(omnislash.ScopeConfig{
		Enabled:    true,
		AllowHosts: []string{"93.184.216.34", "10.0.0.44"},
		AllowPorts: []int{443},
	})
	if err != nil {
		t.Fatal(err)
	}
	doer := &scriptedDoer{t: t, responses: []scriptedResponse{
		{status: http.StatusMovedPermanently, location: "https://10.0.0.44:443/internal"},
	}}
	resolver := newRedirectResolver(doer, scope, []string{"93.184.216.34", "10.0.0.44"}, nil)
	start, err := url.Parse("https://93.184.216.34/")
	if err != nil {
		t.Fatal(err)
	}

	got := resolver.Resolve(context.Background(), start)
	if got == nil || got.String() != start.String() {
		t.Fatalf("resolved URL = %v, want original %v", got, start)
	}
	if doer.requests != 1 {
		t.Fatalf("requests = %d, want 1 (private redirect must not be dialed)", doer.requests)
	}
}

func TestRedirectResolverStopsAfterThreeHops(t *testing.T) {
	scope := &recordingScope{allow: map[string]bool{"allowed.example:443": true}}
	doer := &scriptedDoer{t: t, responses: []scriptedResponse{
		{status: http.StatusMovedPermanently, location: "/one"},
		{status: http.StatusFound, location: "/two"},
		{status: http.StatusFound, location: "/three"},
		{status: http.StatusOK, location: "/never-requested"},
	}}
	resolver := newRedirectResolver(doer, scope, []string{"allowed.example"}, nil)
	start, err := url.Parse("https://allowed.example/")
	if err != nil {
		t.Fatal(err)
	}

	got := resolver.Resolve(context.Background(), start)
	if got == nil || got.Path != "/" {
		t.Fatalf("resolved URL = %v, want original path for an unsettled chain", got)
	}
	if doer.requests != maxRedirectHops {
		t.Fatalf("requests = %d, want at most %d hops", doer.requests, maxRedirectHops)
	}
}
