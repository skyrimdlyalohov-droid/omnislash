// Command dialer is the minimal 20-line pattern for plugging a raw scanner
// into omnislash: one pinned session, one exit IP, no net/http on the target.
package main

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"os"
	"time"

	"github.com/skyrimdlyalohov-droid/omnislash"
)

func main() {
	must := func(err error) {
		if err != nil {
			log.Fatal(err)
		}
	}
	cfg, err := omnislash.LoadConfig("")
	must(err)
	proxies, err := omnislash.LoadProxyFile("proxies.txt", cfg.DefaultScheme)
	must(err)
	pool, err := omnislash.NewPool(cfg, proxies, nil)
	must(err)
	session, err := omnislash.NewDialer(pool, nil).NewSession(10 * time.Minute)
	must(err)
	defer session.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := session.DialTLSContext(ctx, "tcp", "example.com:443", &tls.Config{
		ServerName: "example.com", NextProtos: []string{"http/1.1"},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	_, _ = io.Copy(os.Stdout, conn)
}
