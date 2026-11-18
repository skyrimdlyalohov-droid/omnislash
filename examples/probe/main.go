// Command probe runs one probe module through an omnislash session.
//
// The point of the example is the split of responsibilities: the runner opens a
// pinned session (one proxy, one exit IP), hands the raw net.Conn to a Probe,
// and the Probe writes bytes with conn.Write. Nothing in this path builds an
// http.Client or dials a second connection.
//
//	go run ./examples/probe -probe race -target api.ipify.org:443 -host api.ipify.org -path '/?format=json'
//	go run ./examples/probe -probe smuggle -target example.test:443 -host example.test
//	go run ./examples/probe -probe h2race -target example.test:443 -host example.test
//	go run ./examples/probe -probe gadgets -target example.test:443 -host example.test
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/skyrimdlyalohov-droid/omnislash"
	"github.com/skyrimdlyalohov-droid/omnislash/probe"
)

func main() {
	var (
		kind      = flag.String("probe", "race", "smuggle | race | h2race | gadgets")
		addr      = flag.String("target", "", "host:port to dial")
		host      = flag.String("host", "", "Host header and :authority (default: target)")
		path      = flag.String("path", "/", "request path")
		count     = flag.Int("count", 10, "requests in a burst or number of gadgets")
		timeout   = flag.Duration("timeout", 10*time.Second, "per read/write timeout")
		idle      = flag.Duration("idle", 2*time.Second, "how long to wait for late responses")
		singleUse = flag.Bool("single-use", false, "assert that the action must succeed at most once")
		proxies   = flag.String("proxies", "proxies.txt", "proxy list file")
	)
	flag.Parse()
	if *addr == "" {
		log.Fatal("-target is required")
	}
	if *host == "" {
		*host = *addr
	}
	target := probe.Target{Addr: *addr, Host: *host, Path: *path}

	cfg, err := omnislash.LoadConfig("")
	if err != nil {
		log.Fatal(err)
	}
	list, err := omnislash.LoadProxyFile(*proxies, cfg.DefaultScheme)
	if err != nil {
		log.Fatal(err)
	}
	pool, err := omnislash.NewPool(cfg, list, nil)
	if err != nil {
		log.Fatal(err)
	}
	runner := probe.NewRunner(omnislash.NewDialer(pool, nil))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	switch *kind {
	case "smuggle":
		runner.TLS = &tls.Config{NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12}
		res, err := runner.Run(ctx, target, &probe.SmugglingProbe{Variant: probe.VariantCLTE, Timeout: *timeout})
		emit(res, err)
	case "race":
		runner.TLS = &tls.Config{NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12}
		res, err := runner.Run(ctx, target, &probe.RaceProbe{
			Count:     *count,
			Method:    "GET",
			Timeout:   *timeout,
			Idle:      *idle,
			SingleUse: *singleUse,
		})
		emit(res, err)
	case "h2race":
		runner.TLS = &tls.Config{NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS12}
		res, err := runner.Run(ctx, target, &probe.H2RaceProbe{Count: *count, Method: "GET", Timeout: *timeout, Idle: *idle, SingleUse: *singleUse})
		emit(res, err)
	case "gadgets":
		// One gadget per fresh session: Runner.Rotate gives every gadget its own
		// exit IP, which is how a WAF keyed on the client address is bypassed.
		runner.TLS = &tls.Config{NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12}
		gadgets := probe.Gadgets()
		if *count > 0 && *count < len(gadgets) {
			gadgets = gadgets[:*count]
		}
		probes := make([]probe.Probe, 0, len(gadgets))
		for _, g := range gadgets {
			probes = append(probes, &probe.GadgetProbe{Gadget: g, Timeout: *timeout})
		}
		for _, out := range runner.Rotate(ctx, target, probes) {
			emit(out.Result, out.Err)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown -probe %q\n", *kind)
		os.Exit(2)
	}
}

func emit(res *probe.Result, err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
	}
	if res == nil {
		return
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(res)
}
