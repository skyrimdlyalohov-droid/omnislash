// Command rawdial shows how a request-smuggling scanner can use the rotator to
// obtain a raw TLS connection through a rotating proxy. It deliberately does
// not use net/http for the target request: smuggling tests need byte-exact
// control over the request line, headers and body framing.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/veter/omnislash"
)

func main() {
	proxiesPath := flag.String("proxies", "proxies.txt", "proxy list file")
	configPath := flag.String("config", "", "optional JSON config")
	target := flag.String("target", "example.com:443", "target host:port")
	serverName := flag.String("sni", "", "TLS SNI (defaults to target host)")
	path := flag.String("path", "/", "request path")
	insecure := flag.Bool("insecure", true, "skip target certificate verification")
	flag.Parse()

	cfg, err := omnislash.LoadConfig(*configPath)
	if err != nil {
		fail(err)
	}
	cfg.Health.Enabled = false // no background checks for a one-shot example
	proxies, err := omnislash.LoadProxyFile(*proxiesPath, cfg.DefaultScheme)
	if err != nil {
		fail(err)
	}
	pool, err := omnislash.NewPool(cfg, proxies, nil)
	if err != nil {
		fail(err)
	}
	dialer := omnislash.NewDialer(pool, nil)

	host, _, err := net.SplitHostPort(*target)
	if err != nil {
		fail(err)
	}
	sni := *serverName
	if sni == "" {
		sni = host
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := dialer.DialTLSContext(ctx, "tcp", *target, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: *insecure,
		NextProtos:         []string{"http/1.1"},
	})
	if err != nil {
		fail(err)
	}
	defer conn.Close()

	// This is the place where a real scanner writes its probes. Replace the
	// request below with the exact malformed bytes from the test case.
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", *path, sni)
	if _, err := io.WriteString(conn, req); err != nil {
		fail(err)
	}
	resp, err := io.ReadAll(io.LimitReader(conn, 1<<20))
	if err != nil && !strings.Contains(err.Error(), "EOF") {
		fail(err)
	}
	_, _ = os.Stdout.Write(resp)

	stats := pool.Stats()
	fmt.Fprintf(os.Stderr, "\nproxies=%d available=%d\n", stats.Total, stats.Available)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
