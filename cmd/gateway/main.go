// Command gateway starts only the local rotating HTTP gateway. It is the
// integration point for tools that cannot be rebuilt in Go: point their
// HTTP_PROXY at the listener for plain HTTP, or HTTPS_PROXY for CONNECT, and
// every new upstream connection gets the next exit IP.
package main

import (
	"context"
	"flag"
	"log"
	"os/signal"
	"syscall"

	"github.com/skyrimdlyalohov-droid/omnislash"
)

func main() {
	configPath := flag.String("config", "", "JSON config (defaults are used when empty)")
	proxiesPath := flag.String("proxies", "proxies.txt", "proxy list file")
	listen := flag.String("listen", "", "gateway listen address (default from config)")
	statsAddr := flag.String("stats", "", "stats listen address (default from config)")
	token := flag.String("token", "", "optional Bearer token for CONNECT")
	flag.Parse()

	cfg, err := omnislash.LoadConfig(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	proxies, err := omnislash.LoadProxyFile(*proxiesPath, cfg.DefaultScheme)
	if err != nil {
		log.Fatal(err)
	}
	pool, err := omnislash.NewPool(cfg, proxies, nil)
	if err != nil {
		log.Fatal(err)
	}
	dialer := omnislash.NewDialer(pool, nil)

	addr := cfg.Gateway.Listen
	if *listen != "" {
		addr = *listen
	}
	if *token != "" {
		cfg.Gateway.Token = *token
	}
	gw, err := omnislash.NewGateway(addr, dialer, cfg.Gateway.Token, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer gw.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if *statsAddr != "" {
		cfg.Stats.Listen = *statsAddr
	}
	if cfg.Stats.Listen != "" {
		go func() {
			if err := omnislash.ServeStats(ctx, cfg.Stats.Listen, pool, nil); err != nil {
				log.Printf("stats: %v", err)
			}
		}()
	}
	log.Printf("omnislash HTTP gateway on %s (proxies=%d)", gw.Addr(), pool.Len())
	if err := gw.Serve(ctx); err != nil {
		log.Fatal(err)
	}
}
