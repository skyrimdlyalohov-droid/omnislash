package obfuscation

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// captureRT records the last forwarded request.
type captureRT struct {
	req    *http.Request
	calls  int
	status int
}

func (c *captureRT) RoundTrip(req *http.Request) (*http.Response, error) {
	c.req = req
	c.calls++
	return &http.Response{
		StatusCode: c.status,
		Header:     make(http.Header),
		Body:       http.NoBody,
	}, nil
}

func TestTLSFingerprintLayerFallsBackToUpstreamWithoutTransport(t *testing.T) {
	inner := &captureRT{status: http.StatusOK}
	l := &TLSFingerprintLayer{Fingerprint: "Chrome_131"}

	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:8080/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	req = req.WithContext(context.Background())

	resp, err := l.RoundTrip(context.Background(), inner, req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if inner.calls != 1 {
		t.Fatalf("upstream calls = %d, want 1", inner.calls)
	}
}

func TestNewTLSFingerprintTransportBuildsUtlTransport(t *testing.T) {
	tr, err := NewTLSFingerprintTransport("Chrome_131", nil, nil)
	if err != nil {
		t.Fatalf("NewTLSFingerprintTransport: %v", err)
	}
	if tr == nil {
		t.Fatal("transport is nil")
	}
	if tr.DialTLSContext == nil {
		t.Fatal("transport has no DialTLSContext")
	}
	if !tr.ForceAttemptHTTP2 {
		t.Fatal("ForceAttemptHTTP2 should be true")
	}
}

func TestNewTLSFingerprintTransportRejectsUnknownClient(t *testing.T) {
	if _, err := NewTLSFingerprintTransport("Chrome_999", nil, nil); err == nil {
		t.Fatal("expected error for unknown ClientHelloID, got nil")
	}
}

func TestHTTP2ConsistencyLayerPreservesCanonicalHeaders(t *testing.T) {
	inner := &captureRT{}
	l := &HTTP2ConsistencyLayer{CanonicalOrder: []string{"User-Agent", "Sec-Fetch-Dest", "Accept-Encoding"}}

	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:8080/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	req = req.WithContext(context.Background())
	req.Header.Set("User-Agent", "probe-agent")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("X-Omnislash-Custom", "keep-me")

	if _, err := l.RoundTrip(context.Background(), inner, req); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if got := inner.req.Header.Get("User-Agent"); got != "probe-agent" {
		t.Fatalf("User-Agent = %q, want %q", got, "probe-agent")
	}
	if got := inner.req.Header.Get("Sec-Fetch-Dest"); got != "empty" {
		t.Fatalf("Sec-Fetch-Dest = %q, want %q", got, "empty")
	}
	if got := inner.req.Header.Get("Accept-Encoding"); got != "gzip" {
		t.Fatalf("Accept-Encoding = %q, want %q", got, "gzip")
	}
	if got := inner.req.Header.Get("X-Omnislash-Custom"); got != "keep-me" {
		t.Fatalf("X-Omnislash-Custom = %q, want %q", got, "keep-me")
	}
}

func TestHTTP2ConsistencyLayerPassthroughWhenNoOrder(t *testing.T) {
	inner := &captureRT{}
	l := &HTTP2ConsistencyLayer{}

	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:8080/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	req = req.WithContext(context.Background())

	if _, err := l.RoundTrip(context.Background(), inner, req); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if inner.calls != 1 {
		t.Fatalf("upstream calls = %d, want 1", inner.calls)
	}
}

func TestBehavioralTimingLayerAppliesJitter(t *testing.T) {
	inner := &captureRT{status: http.StatusOK}
	l := &BehavioralTimingLayer{Jitter: func() time.Duration { return 100 * time.Millisecond }}

	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:8080/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	req = req.WithContext(context.Background())

	start := time.Now()
	resp, err := l.RoundTrip(context.Background(), inner, req)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if elapsed < 80*time.Millisecond {
		t.Fatalf("jitter not applied: elapsed = %v, want >= ~100ms", elapsed)
	}
}

func TestBehavioralTimingLayerWarmUpAddsIdle(t *testing.T) {
	inner := &captureRT{}
	l := &BehavioralTimingLayer{WarmUp: true, LongIdle: 120 * time.Millisecond}

	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:8080/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	req = req.WithContext(context.Background())

	start := time.Now()
	if _, err := l.RoundTrip(context.Background(), inner, req); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
		t.Fatalf("warm-up idle not applied: elapsed = %v, want >= ~120ms", elapsed)
	}
}

func TestBehavioralTimingLayerAdaptiveBackoffOn429(t *testing.T) {
	inner := &captureRT{status: http.StatusTooManyRequests}
	l := &BehavioralTimingLayer{Adaptive: true}

	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:8080/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	req = req.WithContext(context.Background())

	resp, err := l.RoundTrip(context.Background(), inner, req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusTooManyRequests)
	}
}
