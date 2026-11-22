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
// requested browser ClientHelloID (format "<Client>_<Version>", e.g. "Chrome_131").
// The transport is configured for HTTP/2 (ForceAttemptHTTP2 plus the supplied
// HTTP2 settings) so the L3 frame alignment is in place from the first connection.
func NewTLSFingerprintTransport(fingerprint string, base http.RoundTripper, h2Cfg *http.HTTP2Config) (*http.Transport, error) {
	client, version := "Chrome", "131"
	if parts := strings.Split(fingerprint, "_"); len(parts) == 2 && parts[0] != "" && parts[1] != "" {
		client, version = parts[0], parts[1]
	}
	id := tls.ClientHelloID{Client: client, Version: version}
	if _, err := tls.UTLSIdToSpec(id); err != nil {
		return nil, err
	}

	_ = base

	h2 := h2Cfg
	if h2 == nil {
		h2 = &http.HTTP2Config{MaxConcurrentStreams: 4}
	}

	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	return &http.Transport{
		Proxy:             http.ProxyFromEnvironment,
		ForceAttemptHTTP2: true,
		HTTP2:             h2,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				host = addr
			}
			rawConn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			uconn := tls.UClient(rawConn, &tls.Config{
				ServerName: host,
				NextProtos: []string{"h2", "http/1.1"},
			}, id)
			if err := uconn.HandshakeContext(ctx); err != nil {
				rawConn.Close()
				return nil, err
			}
			return uconn, nil
		},
	}, nil
}
