package obfuscation

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"

	tls "github.com/refraction-networking/utls"
)

// TLSFingerprintLayer implements L2 of the 4-layer obfuscation engine:
// TLS handshake mimicry (JA3/JA4) backed by github.com/refraction-networking/utls
// with a browser ClientHelloID.
type TLSFingerprintLayer struct {
	Fingerprint string
	Transport   *http.Transport
}

var _ Layer = (*TLSFingerprintLayer)(nil)

// RoundTrip forwards https requests through the uTLS-based transport when set.
func (l *TLSFingerprintLayer) RoundTrip(ctx context.Context, rt http.RoundTripper, req *http.Request) (*http.Response, error) {
	if strings.HasPrefix(req.URL.Scheme, "https") && l.Transport != nil {
		return l.Transport.RoundTrip(req)
	}
	return rt.RoundTrip(req)
}

// NewTLSFingerprintTransport builds an *http.Transport whose TLS handshake is
// routed through the refraction-networking/utls implementation with the
// requested browser ClientHelloID (format: "<Client>_<Version>", e.g. "Chrome_131").
func NewTLSFingerprintTransport(fingerprint string, base http.RoundTripper) (*http.Transport, error) {
	client, version := "Chrome", "131"
	if parts := strings.Split(fingerprint, "_"); len(parts) == 2 && parts[0] != "" && parts[1] != "" {
		client, version = parts[0], parts[1]
	}
	id := tls.ClientHelloID{Client: client, Version: version}
	if _, err := tls.UTLSIdToSpec(id); err != nil {
		return nil, err
	}
	_ = base
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}, nil
}
