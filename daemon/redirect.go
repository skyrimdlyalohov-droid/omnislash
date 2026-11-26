package daemon

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
)

const (
	// maxRedirectHops bounds the lightweight pre-probe resolution. A chain that
	// has not settled after three hops is treated as a redirect stub: probes
	// stay on the operator's original URL instead of chasing it forever.
	maxRedirectHops = 3
	maxRedirectBody = 64 << 10
)

// httpDoer is the narrow interface used by the redirect resolver. *http.Client
// implements it; tests can supply a deterministic fake.
type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// redirectScope is the subset of omnislash.Scope needed to validate a Location.
// CheckTarget applies allow_hosts, allow_ports and the private/metadata deny
// rules, so an untrusted exit cannot steer us into an internal network.
type redirectScope interface {
	Enabled() bool
	CheckTarget(context.Context, string) (string, error)
}

// redirectResolver follows 301/302 stubs only far enough to find the real
// application path. It never follows redirects itself through http.Client:
// every hop is validated and requested explicitly as GET. Any refusal returns
// the original URL so the caller probes exactly what the operator configured.
type redirectResolver struct {
	client     httpDoer
	scope      redirectScope
	allowHosts []string
	log        *slog.Logger
}

func newRedirectResolver(client httpDoer, scope redirectScope, allowHosts []string, log *slog.Logger) *redirectResolver {
	if client == nil {
		return nil
	}
	return &redirectResolver{client: client, scope: scope, allowHosts: allowHosts, log: log}
}

// Resolve returns the settled URL, or start unchanged on any transport error,
// scope refusal, out-of-scope Location or exhausted hop budget.
func (r *redirectResolver) Resolve(ctx context.Context, start *url.URL) *url.URL {
	if r == nil || start == nil {
		return start
	}
	current := cloneRedirectURL(start)
	if !r.urlAllowed(ctx, current) {
		return start
	}
	for hop := 0; hop < maxRedirectHops; hop++ {
		if err := ctx.Err(); err != nil {
			return start
		}
		// Only GET is ever emitted here: a redirect pre-flight must not replay
		// a state-changing request or a probe payload.
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, current.String(), nil)
		if err != nil {
			return start
		}
		resp, err := r.client.Do(req)
		if err != nil || resp == nil {
			return start
		}
		drainRedirectBody(resp.Body)
		if !isRedirectStatus(resp.StatusCode) {
			return current
		}
		location := strings.TrimSpace(resp.Header.Get("Location"))
		if location == "" {
			return current
		}
		next, err := current.Parse(location)
		if err != nil || next == nil || !r.urlAllowed(ctx, next) {
			if r.log != nil {
				r.log.Debug("redirect target blocked; keeping original URL", "location", location, "hop", hop+1)
			}
			return start
		}
		current = next
	}
	// Still redirecting after the budget: no settled path to hand to the probes.
	return start
}

// urlAllowed applies scope.go first (private networks, ports, DNS pins) and
// then the explicit allow_hosts check, so a disabled scope cannot silently
// widen the redirect surface when the operator configured a host allowlist.
func (r *redirectResolver) urlAllowed(ctx context.Context, u *url.URL) bool {
	if u == nil || !redirectSchemeAllowed(u.Scheme) || u.Hostname() == "" {
		return false
	}
	if r.scope != nil && r.scope.Enabled() {
		addr := urlDialAddr(u)
		if addr == "" {
			return false
		}
		if _, err := r.scope.CheckTarget(ctx, addr); err != nil {
			if r.log != nil {
				r.log.Debug("redirect scope check failed", "target", addr, "error", err)
			}
			return false
		}
	}
	if !redirectHostAllowed(u.Hostname(), r.allowHosts) {
		if r.log != nil {
			r.log.Debug("redirect host outside allow_hosts", "host", u.Hostname())
		}
		return false
	}
	return true
}

func cloneRedirectURL(u *url.URL) *url.URL {
	if u == nil {
		return nil
	}
	clone := *u
	return &clone
}

func isRedirectStatus(code int) bool {
	switch code {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}

func redirectSchemeAllowed(scheme string) bool {
	return strings.EqualFold(scheme, "http") || strings.EqualFold(scheme, "https")
}

// urlDialAddr supplies the explicit host:port that scope.CheckTarget expects.
// net/http's implicit port would make the scope see a different target than
// the dialer and TLS SNI.
func urlDialAddr(u *url.URL) string {
	port := u.Port()
	if port == "" {
		switch {
		case strings.EqualFold(u.Scheme, "https"):
			port = "443"
		case strings.EqualFold(u.Scheme, "http"):
			port = "80"
		default:
			return ""
		}
	}
	return net.JoinHostPort(u.Hostname(), port)
}

// redirectHostAllowed mirrors scope.go's allow_hosts semantics, including a
// leading "*." wildcard. An empty list means the operator did not configure a
// host allowlist; scope.CheckTarget remains authoritative in that case.
func redirectHostAllowed(host string, allowHosts []string) bool {
	if len(allowHosts) == 0 {
		return true
	}
	host = normalizeRedirectHost(host)
	for _, raw := range allowHosts {
		rule := normalizeRedirectHost(raw)
		if rule == "" {
			continue
		}
		if strings.HasPrefix(rule, "*.") {
			suffix := rule[1:] // ".example.com"
			if strings.HasSuffix(host, suffix) && len(host) > len(suffix) {
				return true
			}
		} else if host == rule {
			return true
		}
	}
	return false
}

func normalizeRedirectHost(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	h = strings.TrimSuffix(h, ".")
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		h = strings.Trim(h, "[]")
	}
	return h
}

func drainRedirectBody(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(body, maxRedirectBody))
	_ = body.Close()
}
