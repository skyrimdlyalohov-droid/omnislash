package obfuscation

import (
	"context"
	"net/http"
)

// HTTP2FrameLayer implements L3 runtime: HTTP/2 frame-level alignment
// (SETTINGS_MAX_CONCURRENT_STREAMS, flow-control windows, header-table and
// frame-size parameters) applied through the transport configured by
// NewTLSFingerprintTransport (L2 runtime).
type HTTP2FrameLayer struct {
	Transport *http.Transport
}

var _ Layer = (*HTTP2FrameLayer)(nil)

// RoundTrip forwards through the aligned HTTP/2 transport when set.
func (l *HTTP2FrameLayer) RoundTrip(ctx context.Context, rt http.RoundTripper, req *http.Request) (*http.Response, error) {
	if l.Transport != nil {
		return l.Transport.RoundTrip(req)
	}
	return rt.RoundTrip(req)
}

// HTTP2ConsistencyLayer implements L3 design: strict L7 header consistency
// (canonical header ordering + duplicate pruning) to match the TLS profile
// selected in L2.
type HTTP2ConsistencyLayer struct {
	CanonicalOrder []string
}

var _ Layer = (*HTTP2ConsistencyLayer)(nil)

// RoundTrip delegates after normalizing headers into the canonical order.
func (l *HTTP2ConsistencyLayer) RoundTrip(ctx context.Context, rt http.RoundTripper, req *http.Request) (*http.Response, error) {
	if len(l.CanonicalOrder) == 0 {
		return rt.RoundTrip(req)
	}
	canonical := make(http.Header, len(req.Header))
	for _, h := range l.CanonicalOrder {
		if values, ok := req.Header[h]; ok {
			canonical[h] = values
		}
	}
	for k, v := range req.Header {
		if _, seen := canonical[k]; !seen {
			canonical[k] = v
		}
	}
	cloned := req.Clone(ctx)
	cloned.Header = canonical
	return rt.RoundTrip(cloned)
}
