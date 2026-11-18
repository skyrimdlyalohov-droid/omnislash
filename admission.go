package omnislash

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// admit runs the mode-specific, raw admission probes. It deliberately bypasses
// the pool's scope: these are fixed operator-configured canaries, not scanner
// targets. Trusted pools skip admission and rely on health plus egress checks;
// the caller still gets the egress canary suite.
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
			if err := v.admitEcho(ctx, pr, ad, admissionBytes(ad.EchoBytes)); err != nil {
				return fmt.Errorf("admission echo: %w", err)
			}
		}
	case AdmissionModeHTTPParsing:
		if strings.TrimSpace(ad.EchoAddr) == "" {
			return fmt.Errorf("admission: http_parsing mode requires echo_addr")
		}
		if err := v.admitEcho(ctx, pr, ad, admissionHTTPPayload(ad.EchoBytes)); err != nil {
			return fmt.Errorf("admission http_parsing: %w", err)
		}
	default:
		return fmt.Errorf("admission: unsupported mode %q", mode)
	}
	return nil
}

// admitConnect proves three things at once: the proxy establishes a CONNECT
// tunnel, the target certificate verifies against the configured trust roots,
// and the tunnel survives a pause followed by a second HTTP request.
func (v *Validator) admitConnect(ctx context.Context, pr *Proxy, ad AdmissionConfig) error {
	u, err := url.Parse(strings.TrimSpace(ad.TLSCanaryURL))
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("invalid TLS canary %q", ad.TLSCanaryURL)
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
	base := &net.Dialer{Timeout: timeout}
	raw, err := dialThroughProxy(ctx, base, pr, target, timeout, false)
	if err != nil {
		return err
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(timeout))

	cfg := &tls.Config{
		ServerName:         host,
		RootCAs:            v.admitRoot,
		InsecureSkipVerify: ad.TLSSkipVerify,
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"http/1.1"},
	}
	tc := tls.Client(raw, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("target certificate/TLS handshake: %w", err)
	}
	if !ad.TLSSkipVerify {
		state := tc.ConnectionState()
		if len(state.VerifiedChains) == 0 {
			return fmt.Errorf("target certificate was not verified")
		}
	}
	br := bufio.NewReader(tc)
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

// admitEcho sends payload and requires the exact same bytes back. A normal
// tunnel passes; a proxy that buffers, rewrites framing, reorders or truncates
// bytes fails. The echoed bytes are never interpreted as HTTP by omnislash.
func (v *Validator) admitEcho(ctx context.Context, pr *Proxy, ad AdmissionConfig, payload []byte) error {
	if len(payload) == 0 {
		return fmt.Errorf("empty echo payload")
	}
	timeout := ad.Timeout.Std()
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	base := &net.Dialer{Timeout: timeout}
	conn, err := dialThroughProxy(ctx, base, pr, ad.EchoAddr, timeout, false)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(payload); err != nil {
		return fmt.Errorf("write echo payload: %w", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		return fmt.Errorf("read echo payload: %w", err)
	}
	if !bytes.Equal(payload, got) {
		return fmt.Errorf("echo payload was modified (%d bytes out, mismatch back)", len(payload))
	}
	return nil
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
