package omnislash

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// admit runs the strict, mode-specific raw admission probes. It deliberately
// bypasses the pool's scope: these are fixed operator-configured canaries, not
// scanner targets. Trusted pools skip admission and rely on health plus egress
// checks; the caller still gets the egress canary suite.
//
// This entry point keeps the strict historical contract: a failure rejects the
// proxy. The pool uses admitTiered, which degrades a failed strict echo to
// Infantry instead of discarding a proxy that already passed base admission.
func (v *Validator) admit(ctx context.Context, pr *Proxy) error {
	if !v.cfg.Admission.Enabled || v.tier == TrustTierTrusted {
		return nil
	}
	ad := v.cfg.Admission
	mode := v.cfg.Mode
	if mode == "" {
		mode = AdmissionModeConnect
	}
	switch mode {
	case AdmissionModeConnect:
		if strings.TrimSpace(ad.TLSCanaryURL) == "" {
			return fmt.Errorf("admission: connect mode requires tls_canary_url")
		}
		if err := v.admitConnect(ctx, pr, ad); err != nil {
			return fmt.Errorf("admission connect: %w", err)
		}
		if strings.TrimSpace(ad.EchoAddr) != "" {
			if err := v.admitStrict(ctx, pr, ad, admissionBytes(ad.EchoBytes)); err != nil {
				return fmt.Errorf("admission echo: %w", err)
			}
		}
	case AdmissionModeHTTPParsing:
		if strings.TrimSpace(ad.EchoAddr) == "" {
			return fmt.Errorf("admission: http_parsing mode requires echo_addr")
		}
		if err := v.admitStrict(ctx, pr, ad, admissionHTTPPayload(ad.EchoBytes)); err != nil {
			return fmt.Errorf("admission http_parsing: %w", err)
		}
	default:
		return fmt.Errorf("admission: unsupported mode %q", mode)
	}
	return nil
}

// admitTiered runs the two-level funnel:
//
//  1. Base CONNECT + verified TLS canary. Only proxies that pass this stage
//     become eligible for the pool; they start as InfantryTier.
//  2. Byte-exact http_parsing echo, repeated admission.samples times. Stable
//     latency (IQR < 20ms) promotes the proxy to SniperTier. A proxy that fails
//     the echo still stays in the pool as InfantryTier.
//
// With an echo-only configuration (no TLS canary) the strict echo is mandatory,
// which preserves the fail-closed behaviour of older configurations.
func (v *Validator) admitTiered(ctx context.Context, pr *Proxy) error {
	ad := v.cfg.Admission
	if !ad.Enabled || v.tier == TrustTierTrusted {
		return nil
	}
	mode := v.cfg.Mode
	if mode == "" {
		mode = AdmissionModeConnect
	}
	baseOK := false
	if strings.TrimSpace(ad.TLSCanaryURL) != "" {
		if err := v.admitConnect(ctx, pr, ad); err != nil {
			return markProxyTransport(fmt.Errorf("base admission: %w", err))
		}
		pr.setAdmissionMode(AdmissionModeConnect)
		baseOK = true
	}
	var strictErr error
	switch {
	case strings.TrimSpace(ad.EchoAddr) != "":
		payload := admissionBytes(ad.EchoBytes)
		if mode == AdmissionModeHTTPParsing {
			payload = admissionHTTPPayload(ad.EchoBytes)
		}
		strictErr = v.admitStrict(ctx, pr, ad, payload)
	case strings.TrimSpace(ad.TLSCanaryURL) != "":
		// No external echo endpoint: use the verified canary tunnel itself as
		// a self-contained HTTP parsing oracle. See admitSelfContained.
		strictErr = v.admitSelfContained(ctx, pr, ad)
	}
	if strictErr == nil && (strings.TrimSpace(ad.EchoAddr) != "" || strings.TrimSpace(ad.TLSCanaryURL) != "") {
		pr.setAdmissionMode(AdmissionModeHTTPParsing)
	} else if strictErr != nil && v.log != nil {
		v.log.Debug("proxy kept in infantry tier after strict admission failure",
			"proxy", pr.Label(), "error", strictErr)
	}
	if !baseOK && strictErr != nil {
		return strictErr
	}
	if mode == AdmissionModeConnect && strings.TrimSpace(ad.TLSCanaryURL) == "" {
		return fmt.Errorf("admission: connect mode requires tls_canary_url")
	}
	if mode == AdmissionModeHTTPParsing && strings.TrimSpace(ad.EchoAddr) == "" && strings.TrimSpace(ad.TLSCanaryURL) == "" {
		return fmt.Errorf("admission: http_parsing mode requires echo_addr or tls_canary_url")
	}
	return nil
}

func (v *Validator) connectTimeout(ad AdmissionConfig) time.Duration {
	if v != nil && v.connectTimeoutValue > 0 {
		return v.connectTimeoutValue
	}
	if ad.Timeout > 0 {
		return ad.Timeout.Std()
	}
	return 10 * time.Second
}

func (v *Validator) handshakeTimeout(ad AdmissionConfig) time.Duration {
	if v != nil && v.handshakeTimeoutValue > 0 {
		return v.handshakeTimeoutValue
	}
	if ad.Timeout > 0 {
		return ad.Timeout.Std()
	}
	return 10 * time.Second
}

func (v *Validator) ttfbTimeout(ad AdmissionConfig) time.Duration {
	if v != nil && v.ttfbTimeoutValue > 0 {
		return v.ttfbTimeoutValue
	}
	if ad.Timeout > 0 {
		return ad.Timeout.Std()
	}
	return 10 * time.Second
}

// strictVerify reports whether this validator must validate the target chain.
// A public pool never accepts a substituted certificate, even when a caller
// constructs a Validator directly and forgets to run Config.Validate.
func (v *Validator) strictVerify(ad AdmissionConfig) bool {
	return v == nil || !strings.EqualFold(strings.TrimSpace(v.tier), TrustTierTrusted) || !ad.TLSSkipVerify
}

// canaryTLS opens a CONNECT/SOCKS5 tunnel to the configured HTTPS canary and
// completes a certificate-verified handshake. SNI and verification both use
// the hostname from the URL; the proxy never sees that as a TLS identity.
func (v *Validator) canaryTLS(ctx context.Context, pr *Proxy, ad AdmissionConfig) (net.Conn, string, error) {
	u, err := url.Parse(strings.TrimSpace(ad.TLSCanaryURL))
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, "", fmt.Errorf("invalid TLS canary %q", ad.TLSCanaryURL)
	}
	host := u.Hostname()
	target := u.Host
	if u.Port() == "" {
		target = net.JoinHostPort(host, "443")
	}
	timeout := ad.Timeout.Std()
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	base := &net.Dialer{Timeout: v.connectTimeout(ad)}
	raw, err := dialThroughProxy(ctx, base, pr, target, v.connectTimeout(ad), v.handshakeTimeout(ad), false)
	if err != nil {
		return nil, "", err
	}

	verify := v.strictVerify(ad)
	cfg := &tls.Config{
		ServerName:         host,
		RootCAs:            v.admitRoot,
		InsecureSkipVerify: !verify,
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"http/1.1"},
	}
	_ = raw.SetDeadline(time.Now().Add(v.handshakeTimeout(ad)))
	tc := tls.Client(raw, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, "", fmt.Errorf("target certificate/TLS handshake: %w", err)
	}
	if verify && len(tc.ConnectionState().VerifiedChains) == 0 {
		_ = raw.Close()
		return nil, "", fmt.Errorf("target certificate was not verified")
	}
	_ = raw.SetDeadline(time.Now().Add(timeout))
	return tc, host, nil
}

// admitConnect proves three things at once: the proxy establishes a CONNECT
// tunnel, the target certificate verifies against the configured trust roots,
// and the tunnel survives a pause followed by a second HTTP request.
func (v *Validator) admitConnect(ctx context.Context, pr *Proxy, ad AdmissionConfig) error {
	tc, host, err := v.canaryTLS(ctx, pr, ad)
	if err != nil {
		return err
	}
	defer tc.Close()
	timeout := ad.Timeout.Std()
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	firstByte := newTTFBConnWithFallback(tc, v.ttfbTimeout(ad), time.Now().Add(timeout))
	br := bufio.NewReader(firstByte)
	if err := writeAdmissionGET(tc, host, true); err != nil {
		return err
	}
	if err := readAdmissionOK(br); err != nil {
		return fmt.Errorf("first keep-alive request: %w", err)
	}
	if hold := ad.Hold.Std(); hold > 0 {
		timer := time.NewTimer(hold)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	_ = tc.SetDeadline(time.Now().Add(timeout))
	if err := writeAdmissionGET(tc, host, false); err != nil {
		return fmt.Errorf("second request after pause: %w", err)
	}
	if err := readAdmissionOK(br); err != nil {
		return fmt.Errorf("second request after pause: %w", err)
	}
	return nil
}

func writeAdmissionGET(w io.Writer, host string, keepAlive bool) error {
	connHeader := "close"
	if keepAlive {
		connHeader = "keep-alive"
	}
	req := "GET / HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: omnislash-admission/1\r\nConnection: " + connHeader + "\r\n\r\n"
	_, err := io.WriteString(w, req)
	return err
}

func readAdmissionOK(br *bufio.Reader) error {
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

// admitStrict repeats a byte-exact echo and records each successful round as a
// latency sample. A proxy that fails here is not necessarily dead: it simply
// lacks the byte transparency required for SniperTier.
func (v *Validator) admitStrict(ctx context.Context, pr *Proxy, ad AdmissionConfig, payload []byte) error {
	samples := ad.Samples
	if samples < 1 {
		samples = 1
	}
	for i := 0; i < samples; i++ {
		latency, err := v.admitEchoOnce(ctx, pr, ad, payload)
		if err != nil {
			return fmt.Errorf("echo %d/%d: %w", i+1, samples, err)
		}
		pr.addLatencySample(latency)
	}
	return nil
}

// admitSelfContained is the http_parsing funnel for pools without a dedicated
// echo endpoint. It sends two pipelined HTTP/1.1 requests over the same
// CONNECT+TLS tunnel: one with Content-Length: 0, one with a chunked body.
// A proxy that buffers, rewrites or drops either framing field breaks the
// response sequence and stays in InfantryTier. Repeated rounds feed the same
// IQR gate as a byte-external echo, so a stable fast public proxy can actually
// be promoted to SniperTier.
func (v *Validator) admitSelfContained(ctx context.Context, pr *Proxy, ad AdmissionConfig) error {
	samples := ad.Samples
	if samples < 1 {
		samples = 1
	}
	for i := 0; i < samples; i++ {
		latency, err := v.admitFramingOnce(ctx, pr, ad)
		if err != nil {
			return fmt.Errorf("http_parsing %d/%d: %w", i+1, samples, err)
		}
		pr.addLatencySample(latency)
	}
	return nil
}

func (v *Validator) admitFramingOnce(ctx context.Context, pr *Proxy, ad AdmissionConfig) (time.Duration, error) {
	tc, host, err := v.canaryTLS(ctx, pr, ad)
	if err != nil {
		return 0, err
	}
	defer tc.Close()
	timeout := ad.Timeout.Std()
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	fallback := time.Now().Add(timeout)
	guarded := newTTFBConnWithFallback(tc, v.ttfbTimeout(ad), fallback)
	_ = tc.SetDeadline(fallback)
	br := bufio.NewReader(guarded)

	ua := strings.TrimSpace(v.cfg.UserAgent)
	if ua == "" {
		ua = defaultMobileUserAgent
	}
	nonce := v.now().UnixNano()
	payload := fmt.Sprintf(
		"GET /?omnislash=%d&stage=content-length HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nContent-Length: 0\r\n\r\n"+
			"POST /?omnislash=%d&stage=chunked HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
		nonce, host, ua, nonce, host, ua,
	)
	started := v.now()
	if _, err := io.WriteString(guarded, payload); err != nil {
		return v.now().Sub(started), fmt.Errorf("write framing payload: %w", err)
	}
	for i, method := range []string{http.MethodGet, http.MethodPost} {
		resp, err := http.ReadResponse(br, &http.Request{Method: method})
		if err != nil {
			return v.now().Sub(started), fmt.Errorf("framing response %d/2: %w", i+1, err)
		}
		if i == 0 && (resp.StatusCode < 200 || resp.StatusCode >= 300) {
			_ = resp.Body.Close()
			return v.now().Sub(started), fmt.Errorf("framing canary answered HTTP %d", resp.StatusCode)
		}
		if err := readBoundedAdmissionBody(resp, v.cfg.MaxBodyBytes); err != nil {
			return v.now().Sub(started), fmt.Errorf("framing response %d/2: %w", i+1, err)
		}
	}
	// The second request asks for Connection: close. Trailing bytes mean the
	// proxy rewrote framing and desynchronised the target's parser.
	var extra [1]byte
	if n, err := br.Read(extra[:]); n > 0 || !errors.Is(err, io.EOF) {
		return v.now().Sub(started), fmt.Errorf("framing responses left %d extra bytes (err %v)", n, err)
	}
	return v.now().Sub(started), nil
}

func readBoundedAdmissionBody(resp *http.Response, max int64) error {
	defer resp.Body.Close()
	if max <= 0 {
		max = 1 << 20
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return err
	}
	if int64(len(body)) > max {
		return fmt.Errorf("framing response body exceeded %d bytes", max)
	}
	if resp.ContentLength >= 0 && resp.ContentLength != int64(len(body)) {
		return fmt.Errorf("framing response Content-Length %d, read %d bytes", resp.ContentLength, len(body))
	}
	return nil
}

func (v *Validator) admitEchoOnce(ctx context.Context, pr *Proxy, ad AdmissionConfig, payload []byte) (time.Duration, error) {
	if len(payload) == 0 {
		return 0, fmt.Errorf("empty echo payload")
	}
	timeout := v.connectTimeout(ad)
	base := &net.Dialer{Timeout: timeout}
	conn, err := dialThroughProxy(ctx, base, pr, ad.EchoAddr, timeout, v.handshakeTimeout(ad), false)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	fallback := time.Now().Add(timeout)
	guarded := newTTFBConnWithFallback(conn, v.ttfbTimeout(ad), fallback)
	_ = conn.SetDeadline(fallback)
	started := v.now()
	if _, err := guarded.Write(payload); err != nil {
		return 0, fmt.Errorf("write echo payload: %w", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(guarded, got); err != nil {
		return v.now().Sub(started), fmt.Errorf("read echo payload: %w", err)
	}
	if !bytes.Equal(payload, got) {
		return v.now().Sub(started), fmt.Errorf("echo payload was modified (%d bytes out, mismatch back)", len(payload))
	}
	return v.now().Sub(started), nil
}

func admissionBytes(n int) []byte {
	if n < 1 {
		n = 256
	}
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i*37 + 11)
	}
	return out
}

// admissionHTTPPayload exercises framing fields that commodity HTTP proxies
// like to normalize. An echo endpoint reflects it byte-for-byte; any rewrite of
// Content-Length, Transfer-Encoding or header order is visible immediately.
func admissionHTTPPayload(n int) []byte {
	if n < 64 {
		n = 64
	}
	body := "5\r\nhello\r\n0\r\n\r\n"
	pad := n - len(body)
	if pad < 0 {
		pad = 0
	}
	var b strings.Builder
	b.WriteString("POST /admission HTTP/1.1\r\n")
	b.WriteString("Host: admission.invalid\r\n")
	b.WriteString("Content-Length: 5\r\n")
	b.WriteString("Transfer-Encoding: chunked\r\n")
	b.WriteString("X-Omnislash-Pad: ")
	b.WriteString(strings.Repeat("x", pad))
	b.WriteString("\r\n\r\n")
	b.WriteString(body)
	return []byte(b.String())
}
