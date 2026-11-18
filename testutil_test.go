package omnislash

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func mustProxy(t *testing.T, raw string) *Proxy {
	t.Helper()
	p, err := NewProxy(raw, "socks5")
	if err != nil {
		t.Fatalf("NewProxy(%q): %v", raw, err)
	}
	return p
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// fakeConnectProxy is a minimal HTTP CONNECT proxy for tests.
type fakeConnectProxy struct {
	ln       net.Listener
	addr     string
	auth     string
	connects atomic.Int64
}

func startConnectProxy(t *testing.T, auth string) *fakeConnectProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeConnectProxy{ln: ln, addr: ln.Addr().String(), auth: auth}
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

func (p *fakeConnectProxy) URL() string { return "http://" + p.addr }

func (p *fakeConnectProxy) handle(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method != http.MethodConnect {
		_, _ = io.WriteString(conn, "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
		return
	}
	if p.auth != "" && req.Header.Get("Proxy-Authorization") != p.auth {
		_, _ = io.WriteString(conn, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
		return
	}
	p.connects.Add(1)
	upstream, err := net.Dial("tcp", req.Host)
	if err != nil {
		_, _ = io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer upstream.Close()
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	client := &bufferedConn{Conn: conn, r: br}
	go func() {
		_, _ = io.Copy(upstream, client)
		if cw, ok := upstream.(*net.TCPConn); ok {
			_ = cw.CloseWrite()
		}
	}()
	_, _ = io.Copy(conn, upstream)
	if cw, ok := conn.(*net.TCPConn); ok {
		_ = cw.CloseWrite()
	}
}

// startSocks5Proxy starts a tiny SOCKS5 server. If username is non-empty it
// requires RFC 1929 authentication.
func startSocks5Proxy(t *testing.T, username, password string) string {
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
			go serveSocks5(conn, username, password)
		}
	}()
	return ln.Addr().String()
}

func serveSocks5(conn net.Conn, username, password string) {
	defer conn.Close()
	var head [2]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil || head[0] != 5 {
		return
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	method := byte(0)
	if username != "" {
		method = 2
	}
	if _, err := conn.Write([]byte{5, method}); err != nil {
		return
	}
	if method == 2 {
		var v [2]byte
		if _, err := io.ReadFull(conn, v[:]); err != nil || v[0] != 1 {
			return
		}
		u := make([]byte, v[1])
		if _, err := io.ReadFull(conn, u); err != nil {
			return
		}
		var pl [1]byte
		if _, err := io.ReadFull(conn, pl[:]); err != nil {
			return
		}
		p := make([]byte, pl[0])
		if _, err := io.ReadFull(conn, p); err != nil {
			return
		}
		if string(u) != username || string(p) != password {
			_, _ = conn.Write([]byte{1, 1})
			return
		}
		_, _ = conn.Write([]byte{1, 0})
	}

	var req [4]byte
	if _, err := io.ReadFull(conn, req[:]); err != nil || req[0] != 5 || req[1] != 1 {
		return
	}
	target, err := readSocksTarget(conn, req[3])
	if err != nil {
		return
	}
	upstream, err := net.Dial("tcp", target)
	if err != nil {
		_, _ = conn.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer upstream.Close()
	if _, err := conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	go func() {
		_, _ = io.Copy(upstream, conn)
		if cw, ok := upstream.(*net.TCPConn); ok {
			_ = cw.CloseWrite()
		}
	}()
	_, _ = io.Copy(conn, upstream)
	if cw, ok := conn.(*net.TCPConn); ok {
		_ = cw.CloseWrite()
	}
}

func readSocksTarget(conn net.Conn, atyp byte) (string, error) {
	var host string
	switch atyp {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case 4:
		b := make([]byte, 16)
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case 3:
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return "", err
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", err
		}
		host = string(b)
	default:
		return "", fmt.Errorf("bad atyp %d", atyp)
	}
	var pb [2]byte
	if _, err := io.ReadFull(conn, pb[:]); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(pb[:])))), nil
}

func startEchoServer(t *testing.T) string {
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
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String()
}
