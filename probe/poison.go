package probe

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	rawhttp "github.com/projectdiscovery/rawhttp/client"
)

// CachePoisonProbe sends a "poisoner" request and then a "victim" request for
// the same path on the same connection. One connection matters here: the two
// requests must reach the same cache node, and a new connection could be routed
// to a different edge and a different cache.
//
// The probe only reports that the victim response reflected poisoner-controlled
// data. Whether that is exploitable depends on the cache key, cache TTL and
// downstream consumers, which this layer cannot know.
type CachePoisonProbe struct {
	Path string
	// PoisonHeaders are added to the poisoner request only.
	PoisonHeaders []rawhttp.Header
	// VictimHeaders are added to the victim request only.
	VictimHeaders []rawhttp.Header

	Timeout   time.Duration
	Idle      time.Duration
	MaxHeader int64
	MaxBody   int64
}

func (p *CachePoisonProbe) Name() string { return "cache-poison" }

// Execute performs poisoner -> victim on one conn and compares the responses.
func (p *CachePoisonProbe) Execute(ctx context.Context, target Target, conn net.Conn) (*Result, error) {
	e := newExec(ctx, p.Name(), target, conn, p.Timeout, p.MaxHeader, p.MaxBody)
	nonce := newNonce()
	marker := "omnislash-" + nonce + ".invalid"
	path := p.Path
	if path == "" {
		path = target.RequestPath()
	}

	poisonHeaders := []rawhttp.Header{
		{Key: "Host", Value: target.HostHeader()},
		{Key: "User-Agent", Value: "omnislash-probe/1"},
		{Key: "X-Forwarded-Host", Value: marker},
		{Key: "X-Omnislash-Poison", Value: nonce},
		{Key: "Connection", Value: "keep-alive"},
	}
	poisonHeaders = append(poisonHeaders, p.PoisonHeaders...)

	poisoner, err := render(requestSpec{Method: "GET", Path: path, Headers: poisonHeaders})
	if err != nil {
		return e.finish(), fmt.Errorf("probe: render poisoner: %w", err)
	}
	if err := e.write(poisoner); err != nil {
		return e.finish(), fmt.Errorf("probe: poisoner write: %w", err)
	}
	first, err := e.read()
	if err != nil && !isTimeout(err) && first == nil {
		return e.finish(), fmt.Errorf("probe: poisoner read: %w", err)
	}
	_ = first

	victimHeaders := []rawhttp.Header{
		{Key: "Host", Value: target.HostHeader()},
		{Key: "User-Agent", Value: "omnislash-probe/1"},
		{Key: "Connection", Value: "keep-alive"},
	}
	victimHeaders = append(victimHeaders, p.VictimHeaders...)
	victim, err := render(requestSpec{Method: "GET", Path: path, Headers: victimHeaders})
	if err != nil {
		return e.finish(), fmt.Errorf("probe: render victim: %w", err)
	}
	if err := e.write(victim); err != nil {
		return e.finish(), fmt.Errorf("probe: victim write: %w", err)
	}
	after := e.readUntilIdle(orDuration(p.Idle, 500*time.Millisecond))

	for _, r := range after {
		if strings.Contains(r.Body, marker) || strings.Contains(r.Body, nonce) {
			e.addFinding(Finding{
				Kind:       "cache_poisoned",
				Confidence: ConfidenceHigh,
				Detail:     "victim response contained poisoner-controlled data from the same cache path",
				Response:   r.Seq,
			})
			continue
		}
		for _, h := range r.Headers {
			if strings.Contains(h.Value, marker) || strings.Contains(h.Value, nonce) {
				e.addFinding(Finding{
					Kind:       "cache_poisoned",
					Confidence: ConfidenceHigh,
					Detail:     "victim response header contained poisoner-controlled data",
					Response:   r.Seq,
				})
				break
			}
		}
		if r.hasHeader("X-Cache", "HIT") {
			e.addFinding(Finding{
				Kind:       "cache_hit",
				Confidence: ConfidenceLow,
				Detail:     "victim response was served from cache but did not reflect the poison marker",
				Response:   r.Seq,
			})
		}
	}
	return e.finish(), nil
}
