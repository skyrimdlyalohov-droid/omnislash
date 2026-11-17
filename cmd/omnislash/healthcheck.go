package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"time"
)

// cmdHealthcheck is a dependency-free probe for container healthchecks. It
// talks only to the local stats server and never touches target traffic.
func cmdHealthcheck(args []string) error {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	url := fs.String("url", "http://127.0.0.1:9090/readyz", "health endpoint")
	timeout := fs.Duration("timeout", 3*time.Second, "request timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	client := &http.Client{Timeout: *timeout}
	resp, err := client.Get(*url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned HTTP %d", *url, resp.StatusCode)
	}
	return nil
}
