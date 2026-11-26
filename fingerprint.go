package omnislash

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

// TLSFingerprint profiles are used to make a pinned Session present a coherent
// browser/mobile ClientHello. This is a correctness tool for protocol research
// (a Go ClientHello changes how intermediaries parse the exchange), not an
// anonymity tool. The socket is still dialled by Session.DialContext, so the
// pinned proxy and its exit IP are never bypassed.
const (
	FingerprintChrome133 = "chrome_133"
	FingerprintChrome131 = "chrome_131"
	FingerprintSafariIOS = "safari_ios"
	FingerprintOkHttp    = "okhttp"
)

// DefaultFingerprints rotate per session: desktop Chrome, iOS Safari, Android
// OkHttp. The order is fixed so an experiment remains reproducible with a seed.
var DefaultFingerprints = []string{
	FingerprintChrome133,
	FingerprintSafariIOS,
	FingerprintOkHttp,
}

// ParseFingerprint resolves a profile name to a utls ClientHelloID. Unknown
// names are an error: silently falling back to Go or to Chrome would defeat
// the purpose of an explicit fingerprint and could leak a real egress through
// a different transport.
func ParseFingerprint(name string) (utls.ClientHelloID, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "chrome", FingerprintChrome133, "chrome-133":
		return utls.HelloChrome_133, nil
	case FingerprintChrome131, "chrome-131":
		return utls.HelloChrome_131, nil
	case "ios", "safari", "safari_ios", "safari-ios", "safari_ios_26_0", "ios_14":
		return utls.HelloIOS_14, nil
	case "android", "okhttp", "okhttp4_android_13", "okhttp_android":
		return utls.HelloAndroid_11_OkHttp, nil
	default:
		return utls.ClientHelloID{}, fmt.Errorf("omnislash: unknown TLS fingerprint %q", name)
	}
}

// fingerprintName returns the same stable label used in configuration, so logs
// and status output match tls_fingerprints entries.
func fingerprintName(id utls.ClientHelloID) string {
	switch strings.ToLower(id.Client) + "_" + id.Version {
	case "chrome_133":
		return FingerprintChrome133
	case "chrome_131":
		return FingerprintChrome131
	case "ios_14":
		return FingerprintSafariIOS
	case "android_11", "android_11_okhttp":
		return FingerprintOkHttp
	default:
		return strings.ToLower(id.Client) + "_" + id.Version
	}
}

// utlsConfig maps the caller's crypto/tls settings onto utls.Config. All fields
// that affect SNI, ALPN and certificate verification are preserved, so a
// fingerprinted session has exactly the same trust behaviour as a stdlib one.
// VerifyConnection has a different callback type in utls and is intentionally
// not carried over; callers that need it should dial raw and wrap themselves.
func utlsConfig(cfg *tls.Config, addr string) *utls.Config {
	if cfg == nil {
		cfg = &tls.Config{}
	} else {
		cfg = cfg.Clone()
	}
	if cfg.ServerName == "" {
		if host, _, err := net.SplitHostPort(addr); err == nil {
			cfg.ServerName = host
		} else {
			cfg.ServerName = addr
		}
	}
	return &utls.Config{
		ServerName:            cfg.ServerName,
		InsecureSkipVerify:    cfg.InsecureSkipVerify,
		NextProtos:            append([]string(nil), cfg.NextProtos...),
		RootCAs:               cfg.RootCAs,
		CipherSuites:          append([]uint16(nil), cfg.CipherSuites...),
		MinVersion:            cfg.MinVersion,
		MaxVersion:            cfg.MaxVersion,
		VerifyPeerCertificate: cfg.VerifyPeerCertificate,
	}
}

// openTLSWithFingerprint wraps an already established, proxy-pinned connection
// with uTLS and completes the handshake. It never opens a socket: the caller
// owns dialling, scope checks and egress attribution. A failed handshake closes
// exactly that connection.
func openTLSWithFingerprint(ctx context.Context, raw net.Conn, addr string, cfg *tls.Config, id utls.ClientHelloID, handshakeTimeout time.Duration) (net.Conn, error) {
	if raw == nil {
		return nil, fmt.Errorf("omnislash: fingerprinted TLS requires an existing connection")
	}
	// uTLS gets its own deadline: a tunnel that stalled during ClientHello must
	// not be confused with a slow target response.
	if handshakeTimeout > 0 {
		deadline := time.Now().Add(handshakeTimeout)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		_ = raw.SetDeadline(deadline)
	}
	uc := utls.UClient(raw, utlsConfig(cfg, addr), id)
	if err := uc.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, markProxyTransport(fmt.Errorf("utls handshake with %s (%s): %w", addr, fingerprintName(id), err))
	}
	_ = raw.SetDeadline(time.Time{})
	return uc, nil
}

// dialTLSWithFingerprint is the session path: handshake, then the split TTFB
// guard. Hedged dials use openTLSWithFingerprint directly so they can verify
// the chain before handing the socket to a race winner.
func dialTLSWithFingerprint(ctx context.Context, raw net.Conn, addr string, cfg *tls.Config, id utls.ClientHelloID, handshakeTimeout, ttfbTimeout time.Duration) (net.Conn, error) {
	uc, err := openTLSWithFingerprint(ctx, raw, addr, cfg, id, handshakeTimeout)
	if err != nil {
		return nil, err
	}
	return newTTFBConn(uc, ttfbTimeout), nil
}

// connVerifiedChains unwraps the tracked/TLS layers used by uTLS and stdlib
// dials. uTLS exposes its own ConnectionState type, so both variants must be
// recognised before a public proxy is allowed to win a hedged race.
func connVerifiedChains(conn net.Conn) int {
	if conn == nil {
		return 0
	}
	switch c := conn.(type) {
	case interface{ ConnectionState() tls.ConnectionState }:
		return len(c.ConnectionState().VerifiedChains)
	case interface{ ConnectionState() utls.ConnectionState }:
		return len(c.ConnectionState().VerifiedChains)
	}
	if c, ok := conn.(interface{ NetConn() net.Conn }); ok {
		return connVerifiedChains(c.NetConn())
	}
	return 0
}
