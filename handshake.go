package omnislash

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

// bufferedConn preserves bytes already read by a bufio.Reader, which is
// essential for CONNECT tunnels: a client may pipeline data immediately after
// the CONNECT request.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.r.Read(b) }

func (c *bufferedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Close()
}

func (c *bufferedConn) CloseRead() error {
	if cr, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
}

func dialThroughProxy(
	ctx context.Context,
	base *net.Dialer,
	p *Proxy,
	target string,
	handshakeTimeout time.Duration,
	tlsSkipVerify bool,
) (net.Conn, error) {
	conn, err := base.DialContext(ctx, "tcp", p.Addr)
	if err != nil {
		return nil, fmt.Errorf("dial proxy: %w", err)
	}

	deadline := time.Now().Add(handshakeTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Now())
	})

	var out net.Conn = conn
	switch p.Scheme {
	case "socks5", "socks5h":
		err = socks5Connect(conn, p, target)
	case "http":
		out, err = httpConnect(conn, p, target)
	case "https":
		host, _, splitErr := net.SplitHostPort(p.Addr)
		if splitErr != nil {
			err = fmt.Errorf("invalid proxy address: %w", splitErr)
			break
		}
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: tlsSkipVerify,
			MinVersion:         tls.VersionTLS12,
		})
		if err = tlsConn.HandshakeContext(ctx); err == nil {
			out, err = httpConnect(tlsConn, p, target)
		} else {
			out = tlsConn
		}
	default:
		err = fmt.Errorf("unsupported proxy scheme %q", p.Scheme)
	}

	if !stop() {
		if out != nil {
			_ = out.Close()
		} else {
			_ = conn.Close()
		}
		return nil, ctx.Err()
	}
	if err != nil {
		if out != nil {
			_ = out.Close()
		} else {
			_ = conn.Close()
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	if err := out.SetDeadline(time.Time{}); err != nil {
		_ = out.Close()
		return nil, fmt.Errorf("clear proxy deadline: %w", err)
	}
	return out, nil
}

// httpConnect performs an HTTP CONNECT handshake and returns a connection that
// reads through the response reader so no pipelined bytes are lost.
func httpConnect(conn net.Conn, p *Proxy, target string) (net.Conn, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if p.Username != "" || p.Password != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(p.Username + ":" + p.Password))
		fmt.Fprintf(&b, "Proxy-Authorization: Basic %s\r\n", auth)
	}
	b.WriteString("Proxy-Connection: Keep-Alive\r\n\r\n")
	if _, err := io.WriteString(conn, b.String()); err != nil {
		return nil, fmt.Errorf("write CONNECT: %w", err)
	}

	br := bufio.NewReader(conn)
	tp := textproto.NewReader(br)
	line, err := tp.ReadLine()
	if err != nil {
		return nil, fmt.Errorf("read CONNECT status: %w", err)
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return nil, fmt.Errorf("malformed CONNECT status %q", line)
	}
	code, err := strconv.Atoi(fields[1])
	if err != nil {
		return nil, fmt.Errorf("malformed CONNECT status %q: %w", line, err)
	}
	if _, err := tp.ReadMIMEHeader(); err != nil {
		return nil, fmt.Errorf("read CONNECT headers: %w", err)
	}
	if code < 200 || code > 299 {
		return nil, fmt.Errorf("proxy CONNECT failed: %s", strings.TrimSpace(line))
	}
	return &bufferedConn{Conn: conn, r: br}, nil
}
