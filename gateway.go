package omnislash

import (
	"bufio"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Gateway is a local HTTP CONNECT proxy that tunnels each connection through a
// rotating upstream proxy. Point any raw TCP/TLS scanner at it and every new
// CONNECT gets the next source IP. CONNECT is byte-transparent, so malformed
// HTTP requests used by request-smuggling scanners are not rewritten.
type Gateway struct {
	listener net.Listener
	dialer   *Dialer
	token    string
	log      *slog.Logger

	wg    sync.WaitGroup
	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

// NewGateway starts listening on addr ("127.0.0.1:0" picks a free port).
func NewGateway(addr string, dialer *Dialer, token string, logger *slog.Logger) (*Gateway, error) {
	if logger == nil {
		logger = dialer.log
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &Gateway{
		listener: ln,
		dialer:   dialer,
		token:    token,
		log:      logger,
		conns:    make(map[net.Conn]struct{}),
	}, nil
}

// Addr returns the actual listening address.
func (g *Gateway) Addr() net.Addr { return g.listener.Addr() }

// Serve accepts connections until ctx is canceled or the listener fails.
func (g *Gateway) Serve(ctx context.Context) error {
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = g.listener.Close()
			g.closeAll()
		case <-done:
		}
	}()
	for {
		conn, err := g.listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				break
			}
			g.closeAll()
			g.wg.Wait()
			return err
		}
		g.track(conn)
		g.wg.Add(1)
		go func() {
			defer g.wg.Done()
			defer g.untrack(conn)
			g.handle(ctx, conn)
		}()
	}
	g.wg.Wait()
	return nil
}

// Close stops the listener and all active tunnels.
func (g *Gateway) Close() error {
	err := g.listener.Close()
	g.closeAll()
	return err
}

func (g *Gateway) track(conn net.Conn) {
	g.mu.Lock()
	g.conns[conn] = struct{}{}
	g.mu.Unlock()
}

func (g *Gateway) untrack(conn net.Conn) {
	g.mu.Lock()
	delete(g.conns, conn)
	g.mu.Unlock()
	_ = conn.Close()
}

func (g *Gateway) closeAll() {
	g.mu.Lock()
	conns := make([]net.Conn, 0, len(g.conns))
	for conn := range g.conns {
		conns = append(conns, conn)
	}
	g.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

func (g *Gateway) handle(ctx context.Context, conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		writeHTTPError(conn, http.StatusBadRequest, "Bad Request", "malformed proxy request")
		return
	}
	if req.Method != http.MethodConnect {
		writeHTTPError(conn, http.StatusMethodNotAllowed, "Method Not Allowed", "only CONNECT is supported")
		return
	}
	if !g.authorized(req.Header.Get("Proxy-Authorization")) {
		writeProxyAuthRequired(conn)
		return
	}

	target := req.Host
	if target == "" {
		target = req.URL.Host
	}
	if target == "" {
		target = req.RequestURI
	}
	if target == "" {
		writeHTTPError(conn, http.StatusBadRequest, "Bad Request", "CONNECT target is missing")
		return
	}
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(strings.Trim(target, "[]"), "443")
	}

	// Reject out-of-scope targets with a distinct status. Otherwise a policy
	// violation and a dead proxy both surface as 502 and are impossible to tell
	// apart from the client side. The dialer checks again; this is not a
	// substitute for that check.
	if _, err := g.dialer.pool.scope.CheckTarget(ctx, target); err != nil {
		g.log.Debug("gateway target rejected by scope", "target", target, "error", err)
		writeHTTPError(conn, http.StatusForbidden, "Forbidden", "target is outside the configured scope")
		return
	}

	upstream, err := g.dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		g.log.Debug("gateway dial failed", "target", target, "error", err)
		writeHTTPError(conn, http.StatusBadGateway, "Bad Gateway", "upstream connection failed")
		return
	}
	defer upstream.Close()

	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	clientConn := &bufferedConn{Conn: conn, r: br}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstream, clientConn)
		closeWrite(upstream)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(clientConn, upstream)
		closeWrite(clientConn)
	}()
	wg.Wait()
}

func (g *Gateway) authorized(header string) bool {
	if g.token == "" {
		return true
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	got := []byte(strings.TrimSpace(strings.TrimPrefix(header, prefix)))
	return subtle.ConstantTimeCompare(got, []byte(g.token)) == 1
}

func closeWrite(conn net.Conn) {
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

func writeHTTPError(conn net.Conn, code int, reason, msg string) {
	body := msg + "\n"
	_, _ = fmt.Fprintf(conn,
		"HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, reason, len(body), body)
}

func writeProxyAuthRequired(conn net.Conn) {
	_, _ = io.WriteString(conn,
		"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Bearer\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
}
