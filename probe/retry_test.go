package probe

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skyrimdlyalohov-droid/omnislash"
)

// retryConnectProxy either tunnels to CONNECT target or drops the tunnel
// immediately after the 200. The latter produces the EOF that used to poison
// learning instead of selecting a different exit.
type retryConnectProxy struct {
	ln    net.Listener
	addr  string
	drop  bool
	conns atomic.Int64
}

func startRetryConnectProxy(t *testing.T, drop bool) *retryConnectProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &retryConnectProxy{ln: ln, addr: ln.Addr().String(), drop: drop}
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

func (p *retryConnectProxy) URL() string { return "http://" + p.addr }

func (p *retryConnectProxy) handle(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil || req.Method != http.MethodConnect {
		return
	}
	p.conns.Add(1)
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if p.drop {
		return
	}
	upstream, err := net.Dial("tcp", req.Host)
	if err != nil {
		return
	}
	defer upstream.Close()
	go func() { _, _ = io.Copy(upstream, br) }()
	_, _ = io.Copy(conn, upstream)
}

func startRawHTTPTarget(t *testing.T) string {
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
				if _, err := http.ReadRequest(br); err != nil {
					return
				}
				_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
			}(conn)
		}
	}()
	return ln.Addr().String()
}

type readOnceProbe struct {
	attempts atomic.Int64
}

func (p *readOnceProbe) Name() string { return "read-once" }

func (p *readOnceProbe) Execute(_ context.Context, _ Target, conn net.Conn) (*Result, error) {
	n := p.attempts.Add(1)
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: target.test\r\nConnection: close\r\n\r\n"); err != nil {
		return &Result{}, fmt.Errorf("payload write (attempt %d): %w", n, err)
	}
	body, err := io.ReadAll(io.LimitReader(conn, 4096))
	if err != nil {
		return &Result{}, fmt.Errorf("payload read (attempt %d): %w", n, err)
	}
	if len(body) == 0 {
		return &Result{}, fmt.Errorf("payload read (attempt %d): %w", n, io.EOF)
	}
	return &Result{Responses: []Response{{Status: http.StatusOK, Body: string(body)}}}, nil
}

func mustProbeProxy(t *testing.T, raw string) *omnislash.Proxy {
	t.Helper()
	pr, err := omnislash.NewProxy(raw, "http")
	if err != nil {
		t.Fatalf("NewProxy(%q): %v", raw, err)
	}
	return pr
}

func TestRunnerRetriesEOFThroughAnotherProxy(t *testing.T) {
	bad := startRetryConnectProxy(t, true)
	good := startRetryConnectProxy(t, false)
	target := startRawHTTPTarget(t)

	cfg := omnislash.DefaultConfig()
	cfg.Health.Enabled = false
	cfg.Strategy = omnislash.StrategyRoundRobin
	proxies := []*omnislash.Proxy{
		mustProbeProxy(t, bad.URL()),
		mustProbeProxy(t, good.URL()),
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	pool, err := omnislash.NewPool(&cfg, proxies, logger)
	if err != nil {
		t.Fatal(err)
	}
	runner := NewRunner(omnislash.NewDialer(pool, logger))
	runner.ProxyRetries = 1
	p := &readOnceProbe{}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := runner.Run(ctx, Target{Addr: target, Host: "target.test", Path: "/"}, p)
	if err != nil {
		t.Fatalf("EOF was not retried: %v", err)
	}
	if got := p.attempts.Load(); got != 2 {
		t.Fatalf("probe attempts = %d, want 2", got)
	}
	if bad.conns.Load() != 1 || good.conns.Load() != 1 {
		t.Fatalf("CONNECT counts bad=%d good=%d, want 1/1", bad.conns.Load(), good.conns.Load())
	}
	if len(res.Responses) != 1 || !strings.Contains(res.Responses[0].Body, "\r\n\r\nok") {
		t.Fatalf("unexpected result: %+v", res.Responses)
	}
}

func TestIsRetryableProxyFailureClassification(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{name: "EOF before a response", err: fmt.Errorf("payload read (attempt 1): %w", io.EOF), want: true},
		{name: "reset", err: fmt.Errorf("tunnel: %w", io.ErrUnexpectedEOF), want: true},
		{name: "marked transport", err: fmt.Errorf("wrapped: %w", omnislash.ErrProxyTransport), want: true},
		{name: "target parser error", err: fmt.Errorf("parser reject: invalid request"), want: false},
	}
	for _, tc := range cases {
		if got := isRetryableProxyFailure(&Result{}, tc.err); got != tc.want {
			t.Errorf("%s: retryable = %v, want %v", tc.name, got, tc.want)
		}
	}
}
