package obfuscation

import (
	"context"
	"net/http"
	"testing"
)

type fakeRoundTripper struct {
	called bool
	status int
}

func (f *fakeRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	f.called = true
	return &http.Response{
		StatusCode: f.status,
		Header:     make(http.Header),
		Body:       http.NoBody,
	}, nil
}

func TestLocalGatewayLayerForwardsThroughGatewayClient(t *testing.T) {
	inner := &fakeRoundTripper{status: http.StatusOK}
	client := NewHTTPClient(inner)
	layer := NewLocalGatewayLayer(client)

	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:8080/healthz", nil)
	if err != nil {
		t.Fatal(err)
	}
	req = req.WithContext(context.Background())

	resp, err := layer.RoundTrip(context.Background(), nil, req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if !inner.called {
		t.Fatal("gateway transport was not used")
	}
}

func TestChainForwardsThroughLayersToUpstream(t *testing.T) {
	inner := &fakeRoundTripper{status: http.StatusOK}
	client := NewHTTPClient(inner)
	chain := NewChain(&LocalGatewayLayer{client: client})

	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:8080/blocked", nil)
	if err != nil {
		t.Fatal(err)
	}
	req = req.WithContext(context.Background())

	resp, err := chain.RoundTrip(context.Background(), inner, req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if !inner.called {
		t.Fatal("upstream transport was not reached through the chain")
	}
}
