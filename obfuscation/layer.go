// Package obfuscation provides the composable transport layer model for
// Omnislash's traffic path (Pre-Flight OSINT & 4-Layer Obfuscation Architecture).
//
// Layer contract: a Layer wraps an upstream http.RoundTripper and provides
// optional behavior. Rate-limit / circuit-breaker / audit semantics are owned
// EXCLUSIVELY by the gateway/pool layer and must not be consumed here.
//
// NOTE (working-boundary): Layers 2–4 as specified for evasion (TLS ClientHello /
// JA3 spoofing via utls, HTTP/2 frame ordering, behavioral jitter/warm-up/
// adaptive backoff) are DESIGN-TIME only within the approved working process.
// They are modeled here as interfaces but are not implemented as functional
// evasion until explicit scope confirmation.
package obfuscation

import (
	"context"
	"net/http"
)

// Layer is a composable transport behavior applied around an upstream
// RoundTripper.
type Layer interface {
	// RoundTrip executes req through the wrapped chain.
	RoundTrip(ctx context.Context, rt http.RoundTripper, req *http.Request) (*http.Response, error)
}

// Chain composes multiple layers in order (outermost first).
type Chain struct {
	layers []Layer
}

// NewChain returns a new Chain with the given layers.
func NewChain(layers ...Layer) *Chain {
	return &Chain{layers: layers}
}

// RoundTrip applies the composed layers to the upstream transport.
func (c *Chain) RoundTrip(ctx context.Context, rt http.RoundTripper, req *http.Request) (*http.Response, error) {
	cur := rt
	for i := len(c.layers) - 1; i >= 0; i-- {
		inner := cur
		next := c.layers[i]
		cur = &layerWrapper{layer: next, next: inner}
	}
	return cur.RoundTrip(req)
}

// layerWrapper adapts a Layer to http.RoundTripper.
type layerWrapper struct {
	layer Layer
	next  http.RoundTripper
}

// RoundTrip forwards through the composed layer chain.
func (w *layerWrapper) RoundTrip(req *http.Request) (*http.Response, error) {
	return w.layer.RoundTrip(context.Background(), w.next, req)
}

var (
	_ http.RoundTripper = (*layerWrapper)(nil)
	_ Layer             = (*Chain)(nil)
	_ Layer             = (*LocalGatewayLayer)(nil)
)

// LocalGatewayLayer routes requests through the local Omnislash gateway
// transport (which already enforces global rate limit, fail-closed scope,
// circuit breaker and JSONL audit). This is the compliant L1-style transport
// anchor for the local pipeline; no third-party proxy rotation is performed.
type LocalGatewayLayer struct {
	client *http.Client
}

// NewLocalGatewayLayer builds a Layer that forwards through the provided
// gateway-bound http.Client.
func NewLocalGatewayLayer(client *http.Client) *LocalGatewayLayer {
	return &LocalGatewayLayer{client: client}
}

// RoundTrip executes the request via the local gateway client.
func (l *LocalGatewayLayer) RoundTrip(ctx context.Context, rt http.RoundTripper, req *http.Request) (*http.Response, error) {
	_ = rt // gateway semantics are owned by LocalGatewayLayer configuration
	return l.client.Do(req)
}

// NewHTTPClient returns a default http.Client using the local gateway transport.
func NewHTTPClient(transport http.RoundTripper) *http.Client {
	return &http.Client{Transport: transport}
}
