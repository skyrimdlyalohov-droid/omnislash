// Command fallback-target is a tiny, deliberately boring HTTP server used when
// Docker is unavailable. It is not a vulnerable application; it only exposes
// stable markers and a /blocked endpoint so the lab can verify the safety
// gateway (scope, global rate limit, circuit breaker, audit log) without
// pulling container images.
//
// Real Juice Shop and DVWA targets are defined in lab/docker-compose.yml.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:3000", "listen address")
	name := flag.String("name", "juice", "target profile: juice or dvwa")
	flag.Parse()

	logger := log.New(os.Stderr, "fallback-target ", log.LstdFlags|log.Lmsgprefix)
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		logger.Printf("%s %s", r.Method, r.URL.Path)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, "<!doctype html><html><head><title>OWASP Juice Shop Lab</title></head><body>")
		fmt.Fprint(w, "<h1>OWASP Juice Shop</h1><p>Local fallback target for the omnislash safety lab.</p>")
		fmt.Fprint(w, "</body></html>")
	})

	mux.HandleFunc("/login.php", func(w http.ResponseWriter, r *http.Request) {
		logger.Printf("%s %s", r.Method, r.URL.Path)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, "<!doctype html><html><head><title>Damn Vulnerable Web Application (DVWA)</title></head><body>")
		fmt.Fprint(w, "<h1>Damn Vulnerable Web Application (DVWA)</h1><p>Local fallback target for the omnislash safety lab.</p>")
		fmt.Fprint(w, "</body></html>")
	})

	// Reflected query parameter, intentionally unescaped so the lab XSS
	// template has something deterministic to match.
	mux.HandleFunc("/rest/products/search", func(w http.ResponseWriter, r *http.Request) {
		logger.Printf("%s %s", r.Method, r.URL.Path)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<html><body><p>Search results for: %s</p></body></html>", r.URL.Query().Get("q"))
	})

	mux.HandleFunc("/.git/config", func(w http.ResponseWriter, r *http.Request) {
		logger.Printf("%s %s", r.Method, r.URL.Path)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n")
	})

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "ok")
	})

	mux.HandleFunc("/blocked", func(w http.ResponseWriter, r *http.Request) {
		logger.Printf("%s %s -> 403", r.Method, r.URL.Path)
		http.Error(w, "lab block status", http.StatusForbidden)
	})

	mux.HandleFunc("/throttle", func(w http.ResponseWriter, r *http.Request) {
		logger.Printf("%s %s -> 429", r.Method, r.URL.Path)
		http.Error(w, "lab throttle status", http.StatusTooManyRequests)
	})

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	logger.Printf("profile=%s listening on http://%s", *name, *addr)
	if err := srv.ListenAndServe(); err != nil {
		logger.Fatal(err)
	}
}
