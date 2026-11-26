package omnislash

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/networkpolicy"
)

type scopeHostRule struct {
	host     string
	wildcard bool
}

type scopeDNSEntry struct {
	ips     []net.IP
	expires time.Time
}

// scopePinnedEntry remembers which approved hostname produced a literal IP
// target. It lets a second scope check accept the already validated address
// (no "target IP is not allowed" after resolve_locally) and lets TLS keep the
// certificate identity of the original domain instead of the pinned IP.
type scopePinnedEntry struct {
	host    string
	port    string
	expires time.Time
}

// Scope is a fail-closed target allowlist. It is intentionally independent
// from proxy health: health probes and scraper validation use raw proxy dials
// and bypass the scope, while every application dial is checked.
type Scope struct {
	cfg       ScopeConfig
	hosts     []scopeHostRule
	allowNets []*net.IPNet
	policy    *networkpolicy.NetworkPolicy
	ports     map[int]struct{}
	allPorts  bool

	resolver *net.Resolver
	lookup   func(context.Context, string) ([]net.IP, error)

	mu     sync.Mutex
	cache  map[string]scopeDNSEntry
	pinned map[string]scopePinnedEntry
	now    func() time.Time
}

// metadataCIDRs are denied even when allow_private is enabled: reaching a cloud
// metadata service through a proxy can leak credentials.
var metadataCIDRs = mustCIDRs(
	"169.254.169.254/32", // AWS, GCP, Azure, OpenStack
	"169.254.170.2/32",   // AWS ECS task metadata
	"100.100.100.200/32", // Alibaba Cloud
	"fd00:ec2::254/128",  // AWS IPv6 metadata
)

// nonPublicCIDRs complements the standard library checks for addresses such as
// carrier-grade NAT, benchmark networks and reserved space.
var nonPublicCIDRs = mustCIDRs(
	"0.0.0.0/8",
	"100.64.0.0/10", // carrier-grade NAT
	"192.0.0.0/24",
	"198.18.0.0/15",
	"240.0.0.0/4",
)

// NewScope compiles a ScopeConfig. CIDRs must be valid; a bare IP is accepted
// as a single-address CIDR. NewScope does not change the config.
func NewScope(cfg ScopeConfig) (*Scope, error) {
	s := &Scope{
		cfg:      cfg,
		ports:    make(map[int]struct{}, len(cfg.AllowPorts)),
		allPorts: len(cfg.AllowPorts) == 0,
		cache:    make(map[string]scopeDNSEntry),
		pinned:   make(map[string]scopePinnedEntry),
		resolver: net.DefaultResolver,
		now:      time.Now,
	}
	if s.cfg.DNSCacheTTL <= 0 {
		s.cfg.DNSCacheTTL = Duration(5 * time.Minute)
	}
	if s.cfg.DNSTimeout <= 0 {
		s.cfg.DNSTimeout = Duration(3 * time.Second)
	}
	for _, raw := range cfg.AllowPorts {
		if raw < 1 || raw > 65535 {
			return nil, fmt.Errorf("invalid allow port %d", raw)
		}
		s.ports[raw] = struct{}{}
	}
	for _, raw := range cfg.AllowHosts {
		rule, err := parseScopeHost(raw)
		if err != nil {
			return nil, err
		}
		s.hosts = append(s.hosts, rule)
	}
	var err error
	s.allowNets, err = parseCIDRList(cfg.AllowCIDRs)
	if err != nil {
		return nil, fmt.Errorf("allow_cidrs: %w", err)
	}
	if _, err := parseCIDRList(cfg.DenyCIDRs); err != nil {
		return nil, fmt.Errorf("deny_cidrs: %w", err)
	}

	// networkpolicy owns the hardened deny logic (legacy IPv4 forms, IPv4-mapped
	// IPv6, unspecified address, metadata ranges) and the port allowlist. The
	// allow CIDRs remain separate so an allow_hosts match is not forced to also
	// be inside allow_cidrs.
	deny := make([]string, 0, len(networkpolicy.DefaultIPv4DenylistRanges)+len(networkpolicy.DefaultIPv6DenylistRanges)+len(cfg.DenyCIDRs)+len(metadataCIDRs))
	if !cfg.AllowPrivate {
		deny = append(deny, networkpolicy.DefaultIPv4DenylistRanges...)
		deny = append(deny, networkpolicy.DefaultIPv4Denylist...)
		deny = append(deny, networkpolicy.DefaultIPv6DenylistRanges...)
		deny = append(deny, networkpolicy.DefaultIPv6Denylist...)
	}
	for _, n := range metadataCIDRs {
		deny = append(deny, n.String())
	}
	deny = append(deny, cfg.DenyCIDRs...)
	s.policy, err = networkpolicy.New(networkpolicy.Options{
		DenyList:      deny,
		AllowPortList: append([]int(nil), cfg.AllowPorts...),
	})
	if err != nil {
		return nil, fmt.Errorf("scope policy: %w", err)
	}

	s.lookup = func(ctx context.Context, host string) ([]net.IP, error) {
		addrs, err := s.resolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		ips := make([]net.IP, 0, len(addrs))
		for _, addr := range addrs {
			if addr.IP != nil {
				ips = append(ips, addr.IP)
			}
		}
		return ips, nil
	}
	return s, nil
}

// CheckTarget validates target and returns the address that must be passed to
// the proxy. When resolve_locally is enabled, hostnames are replaced with a
// validated literal IP to prevent proxy-side DNS rebinding.
func (s *Scope) CheckTarget(ctx context.Context, target string) (string, error) {
	if s == nil || !s.cfg.Enabled {
		return target, nil
	}
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return "", fmt.Errorf("scope: target %q must be host:port", target)
	}
	host = strings.Trim(host, "[]")
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("scope: invalid target port %q", portText)
	}
	if !s.portAllowed(port) {
		return "", fmt.Errorf("scope: port %d is not in allow_ports", port)
	}

	if ip := net.ParseIP(host); ip != nil {
		if err := s.checkIP(ip); err != nil {
			return "", fmt.Errorf("scope: target %s: %w", target, err)
		}
		// A literal produced by resolve_locally was already checked against
		// allow_hosts/CIDRs together with its original hostname. Accept the
		// same host:port on re-check; a different port still needs its own
		// allow decision. Deny rules above always apply.
		if s.pinnedTarget(target, portText) {
			return target, nil
		}
		if !s.hostAllowed(host) && !s.cidrAllowed(ip) {
			return "", fmt.Errorf("scope: target IP %s is not allowed", ip)
		}
		return target, nil
	}

	hostAllowed := s.hostAllowed(host)
	if !hostAllowed && len(s.allowNets) == 0 {
		return "", fmt.Errorf("scope: host %q is not in allow_hosts", host)
	}
	// Always resolve locally so a proxy cannot rebind an approved hostname to a
	// private address. resolve_locally additionally pins the first validated IP
	// as the CONNECT target.
	ips, err := s.resolve(ctx, host)
	if err != nil {
		return "", fmt.Errorf("scope: resolve %q: %w", host, err)
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("scope: %q resolved to no addresses", host)
	}
	for _, ip := range ips {
		if err := s.checkIP(ip); err != nil {
			return "", fmt.Errorf("scope: %s resolves to blocked address %s: %w", host, ip, err)
		}
		if !hostAllowed && !s.cidrAllowed(ip) {
			return "", fmt.Errorf("scope: %s resolves to %s, outside allow_cidrs", host, ip)
		}
	}
	if s.cfg.ResolveLocally {
		pinned := net.JoinHostPort(ips[0].String(), portText)
		s.rememberPin(pinned, host, portText)
		return pinned, nil
	}
	return target, nil
}

func (s *Scope) pinnedTarget(addr, port string) bool {
	if s == nil || s.pinned == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	pin, ok := s.pinned[strings.TrimSpace(addr)]
	return ok && pin.port == port && s.now().Before(pin.expires)
}

func (s *Scope) rememberPin(addr, host, port string) {
	if s == nil || s.pinned == nil {
		return
	}
	ttl := s.cfg.DNSCacheTTL.Std()
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pinned) > 4096 {
		clear(s.pinned)
	}
	s.pinned[strings.TrimSpace(addr)] = scopePinnedEntry{
		host: normalizeScopeHost(host), port: port, expires: s.now().Add(ttl),
	}
}

// OriginalHost returns the hostname that resolve_locally pinned to addr. TLS
// must use it for SNI and certificate verification even though CONNECT uses
// the literal IP returned by CheckTarget. An unknown or expired address yields
// an empty string so callers can fall back to the address itself.
func (s *Scope) OriginalHost(addr string) string {
	if s == nil || s.pinned == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	pin, ok := s.pinned[strings.TrimSpace(addr)]
	if !ok || !s.now().Before(pin.expires) {
		return ""
	}
	return pin.host
}

// Enabled reports whether target checks are active.
func (s *Scope) Enabled() bool { return s != nil && s.cfg.Enabled }

func (s *Scope) portAllowed(port int) bool {
	if s.allPorts {
		return true
	}
	if s.policy != nil {
		return s.policy.ValidatePort(port)
	}
	_, ok := s.ports[port]
	return ok
}

func (s *Scope) hostAllowed(host string) bool {
	host = normalizeScopeHost(host)
	for _, rule := range s.hosts {
		if rule.wildcard {
			if strings.HasSuffix(host, rule.host) && len(host) > len(rule.host) {
				return true
			}
		} else if host == rule.host {
			return true
		}
	}
	return false
}

func (s *Scope) cidrAllowed(ip net.IP) bool {
	for _, n := range s.allowNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *Scope) checkIP(ip net.IP) error {
	if ip == nil {
		return fmt.Errorf("empty IP")
	}
	for _, n := range metadataCIDRs {
		if n.Contains(ip) {
			return fmt.Errorf("cloud metadata addresses are always denied")
		}
	}
	if s.policy != nil && !s.policy.ValidateAddress(ip.String()) {
		if s.cfg.AllowPrivate {
			return fmt.Errorf("address %s is in deny_cidrs", ip)
		}
		return fmt.Errorf("address %s is private, loopback, link-local or otherwise non-public (set allow_private to override)", ip)
	}
	return nil
}

func (s *Scope) resolve(ctx context.Context, host string) ([]net.IP, error) {
	key := normalizeScopeHost(host)
	now := s.now()
	s.mu.Lock()
	if e, ok := s.cache[key]; ok && now.Before(e.expires) {
		ips := append([]net.IP(nil), e.ips...)
		s.mu.Unlock()
		return ips, nil
	}
	s.mu.Unlock()

	cctx := ctx
	cancel := func() {}
	if timeout := s.cfg.DNSTimeout.Std(); timeout > 0 {
		cctx, cancel = context.WithTimeout(ctx, timeout)
	}
	ips, err := s.lookup(cctx, host)
	cancel()
	if err != nil {
		return nil, err
	}
	ips = append([]net.IP(nil), ips...)
	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses")
	}
	if ttl := s.cfg.DNSCacheTTL.Std(); ttl > 0 {
		s.mu.Lock()
		if len(s.cache) > 4096 {
			clear(s.cache)
		}
		s.cache[key] = scopeDNSEntry{ips: append([]net.IP(nil), ips...), expires: now.Add(ttl)}
		s.mu.Unlock()
	}
	return ips, nil
}

func parseScopeHost(raw string) (scopeHostRule, error) {
	h := normalizeScopeHost(raw)
	if h == "" {
		return scopeHostRule{}, fmt.Errorf("empty allow host")
	}
	if h == "*" || h == "*." || h == "." {
		return scopeHostRule{}, fmt.Errorf("global wildcard %q is refused", raw)
	}
	if strings.ContainsAny(h, " \t\r\n/") || strings.Contains(h, "://") {
		return scopeHostRule{}, fmt.Errorf("%q must be a hostname or IP", raw)
	}
	if strings.HasPrefix(h, "*.") {
		suffix := strings.TrimPrefix(h, "*")
		if suffix == "." || strings.Contains(suffix[1:], "*") {
			return scopeHostRule{}, fmt.Errorf("invalid wildcard host %q", raw)
		}
		return scopeHostRule{host: suffix, wildcard: true}, nil
	}
	if strings.Contains(h, "*") {
		return scopeHostRule{}, fmt.Errorf("wildcard is only supported as a leading '*.' in %q", raw)
	}
	return scopeHostRule{host: h}, nil
}

func normalizeScopeHost(raw string) string {
	h := strings.ToLower(strings.TrimSpace(raw))
	h = strings.TrimSuffix(h, ".")
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		h = strings.Trim(h, "[]")
	}
	return h
}

func parseCIDRList(raw []string) ([]*net.IPNet, error) {
	out := make([]*net.IPNet, 0, len(raw))
	for _, item := range raw {
		item = strings.TrimSpace(item)
		if item == "" {
			return nil, fmt.Errorf("empty CIDR")
		}
		if !strings.Contains(item, "/") {
			ip := net.ParseIP(item)
			if ip == nil {
				return nil, fmt.Errorf("invalid IP %q", item)
			}
			bits := 128
			if ip.To4() != nil {
				ip = ip.To4()
				bits = 32
			}
			out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		_, n, err := net.ParseCIDR(item)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q", item)
		}
		out = append(out, n)
	}
	return out, nil
}

func mustCIDRs(raw ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(raw))
	for _, item := range raw {
		_, n, err := net.ParseCIDR(item)
		if err != nil {
			panic(err)
		}
		out = append(out, n)
	}
	return out
}

func isNonPublicIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return true
	}
	if ip.Equal(net.IPv4bcast) {
		return true
	}
	for _, n := range nonPublicCIDRs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
