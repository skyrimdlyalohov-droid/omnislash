package obfuscation

import (
	"context"
	"net/http"
)

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
