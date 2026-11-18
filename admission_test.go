package omnislash

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// startEchoTunnelProxy accepts CONNECT and then echoes post-CONNECT bytes. It
// is the positive/negative admission fixture: mutate==nil is a transparent
// tunnel, while buffer/drop/mutate model real proxy failure modes.
type echoTunnelProxy struct {
	ln     net.Listener
	addr   string
	mutate func([]byte) []byte
	buffer bool
	drop   bool
}

func startEchoTunnelProxy(t *testing.T, mutate func([]byte) []byte, buffer, drop bool) *echoTunnelProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &echoTunnelProxy{ln: ln, addr: ln.Addr().String(), mutate: mutate, buffer: buffer, drop: drop}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handle(conn)
		}
	}()
	return p
}

func (p *echoTunnelProxy) URL() string { return "http://" + p.addr }

func (p *echoTunnelProxy) handle(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil || req.Method != http.MethodConnect {
		return
	}
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if p.drop {
		return
	}
	if p.buffer {
		// The classic bufferer: it waits for EOF before answering. A client that
		// writes N bytes and waits for N bytes back times out.
		data, _ := io.ReadAll(br)
		_, _ = conn.Write(data)
		return
	}
	buf := make([]byte, 4096)
	for {
		n, err := br.Read(buf)
		if n > 0 {
			out := append([]byte(nil), buf[:n]...)
			if p.mutate != nil {
				out = p.mutate(out)
			}
			if _, werr := conn.Write(out); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func TestAdmissionEchoRejectsBufferingProxy(t *testing.T) {
	proxy := startEchoTunnelProxy(t, nil, true, false)
	cfg := validationTestConfig("", "")
	cfg.Mode = AdmissionModeHTTPParsing
	cfg.Admission = AdmissionConfig{
		Enabled:   true,
		EchoAddr:  proxy.addr,
		EchoBytes: 128,
		Timeout:   Duration(250 * time.Millisecond),
	}
	v, err := NewValidator(cfg, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if err := v.admit(context.Background(), mustProxy(t, proxy.URL())); err == nil {
		t.Fatal("buffering proxy passed byte-transparency admission")
	}
}

func TestAdmissionEchoRejectsFramingRewriter(t *testing.T) {
	proxy := startEchoTunnelProxy(t, func(in []byte) []byte {
		out := append([]byte(nil), in...)
		if len(out) > 0 {
			out[0] ^= 0x01
		}
		return out
	}, false, false)
	cfg := validationTestConfig("", "")
	cfg.Mode = AdmissionModeHTTPParsing
	cfg.Admission = AdmissionConfig{
		Enabled:   true,
		EchoAddr:  proxy.addr,
		EchoBytes: 128,
		Timeout:   Duration(time.Second),
	}
	v, err := NewValidator(cfg, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if err := v.admit(context.Background(), mustProxy(t, proxy.URL())); err == nil {
		t.Fatal("byte-rewriting proxy passed byte-transparency admission")
	}
}

func TestAdmissionEchoRejectsDroppingProxy(t *testing.T) {
	proxy := startEchoTunnelProxy(t, nil, false, true)
	cfg := validationTestConfig("", "")
	cfg.Mode = AdmissionModeHTTPParsing
	cfg.Admission = AdmissionConfig{
		Enabled:   true,
		EchoAddr:  proxy.addr,
		EchoBytes: 128,
		Timeout:   Duration(250 * time.Millisecond),
	}
	v, err := NewValidator(cfg, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if err := v.admit(context.Background(), mustProxy(t, proxy.URL())); err == nil {
		t.Fatal("dropping proxy passed byte-transparency admission")
	}
}

func TestAdmissionEchoAcceptsTransparentTunnel(t *testing.T) {
	proxy := startEchoTunnelProxy(t, nil, false, false)
	cfg := validationTestConfig("", "")
	cfg.Mode = AdmissionModeHTTPParsing
	cfg.Admission = AdmissionConfig{
		Enabled:   true,
		EchoAddr:  proxy.addr,
		EchoBytes: 512,
		Timeout:   Duration(time.Second),
	}
	v, err := NewValidator(cfg, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if err := v.admit(context.Background(), mustProxy(t, proxy.URL())); err != nil {
		t.Fatalf("transparent tunnel rejected: %v", err)
	}
}

func TestAdmissionConnectVerifiesCertificateAndLongLivedTunnel(t *testing.T) {
	var requests atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		fmt.Fprint(w, "ok\n")
	}))
	defer srv.Close()
	proxy := startConnectProxy(t, "")

	cfg := validationTestConfig("", "")
	cfg.Mode = AdmissionModeConnect
	cfg.Admission = AdmissionConfig{
		Enabled:      true,
		TLSCanaryURL: srv.URL,
		Hold:         Duration(20 * time.Millisecond),
		EchoBytes:    64,
		Timeout:      Duration(2 * time.Second),
	}
	v, err := NewValidator(cfg, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	v.admitRoot = certPoolFor(srv.Certificate())
	if err := v.admit(context.Background(), mustProxy(t, proxy.URL())); err != nil {
		t.Fatalf("valid CONNECT canary rejected: %v", err)
	}
	if got := requests.Load(); got < 2 {
		t.Fatalf("long-lived canary made %d requests, want >= 2", got)
	}
}

// startMITMProxy terminates TLS itself instead of tunneling, modelling a
// malicious or broken CONNECT proxy with a substituted certificate.
func startMITMProxy(t *testing.T, cert tls.Certificate) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil || req.Method != http.MethodConnect {
					return
				}
				if _, err := io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
					return
				}
				tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
				if err := tc.Handshake(); err != nil {
					return
				}
				_, _ = http.ReadRequest(bufio.NewReader(tc))
				_, _ = io.WriteString(tc, "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok\n")
			}(conn)
		}
	}()
	return "http://" + ln.Addr().String()
}

func TestAdmissionConnectRejectsMITMCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "ok\n")
	}))
	defer srv.Close()
	mitm := startMITMProxy(t, srv.TLS.Certificates[0])

	cfg := validationTestConfig("", "")
	cfg.Mode = AdmissionModeConnect
	cfg.Admission = AdmissionConfig{
		Enabled:      true,
		TLSCanaryURL: "https://example.com:443",
		Hold:         0,
		EchoBytes:    64,
		Timeout:      Duration(time.Second),
	}
	v, err := NewValidator(cfg, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	// No roots are installed, so the substituted certificate must fail.
	if err := v.admit(context.Background(), mustProxy(t, mitm)); err == nil {
		t.Fatal("MITM certificate was accepted")
	}
}

func TestTrustTierSwitchesAdmissionPolicy(t *testing.T) {
	proxy := startEchoTunnelProxy(t, func(in []byte) []byte {
		out := append([]byte(nil), in...)
		if len(out) > 0 {
			out[0] ^= 1
		}
		return out
	}, false, false)
	cfg := validationTestConfig("", "")
	cfg.Mode = AdmissionModeHTTPParsing
	cfg.Admission = AdmissionConfig{
		Enabled:   true,
		EchoAddr:  proxy.addr,
		EchoBytes: 128,
		Timeout:   Duration(time.Second),
	}
	pr := mustProxy(t, proxy.URL())

	strict, err := NewValidatorForTier(cfg, TrustTierStrict, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if err := strict.admit(context.Background(), pr); err == nil {
		t.Fatal("strict tier skipped admission")
	}
	trusted, err := NewValidatorForTier(cfg, TrustTierTrusted, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if err := trusted.admit(context.Background(), pr); err != nil {
		t.Fatalf("trusted tier should skip admission: %v", err)
	}
}

func TestAdmissionHTTPPayloadKeepsConflictingFraming(t *testing.T) {
	payload := string(admissionHTTPPayload(128))
	if !strings.Contains(payload, "Content-Length: 5\r\n") {
		t.Fatal("payload lost Content-Length")
	}
	if !strings.Contains(payload, "Transfer-Encoding: chunked\r\n") {
		t.Fatal("payload lost Transfer-Encoding")
	}
	if !bytes.Contains([]byte(payload), []byte("\r\n\r\n5\r\nhello")) {
		t.Fatal("payload framing was reordered")
	}
}

func certPoolFor(cert *x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool
}
