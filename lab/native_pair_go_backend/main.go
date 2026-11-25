// Command native_pair_go_backend is a tiny localhost-only net/http backend used
// by research/native_pair_corpus.py for native (Docker-free) calibration.
//
// It listens on 127.0.0.1:0, prints the chosen address on stdout, and serves
// deterministic CL/TE, header-whitespace, redirect, 400 and 502 variants. It
// uses only the Go standard library; no modules are downloaded. The Python
// corpus generator terminates it (SIGTERM) after collecting examples.
package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const cleanBody = "<html><body><h1>Lab</h1><p>ok</p></body></html>"

func main() {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintln(os.Stderr, "native_pair_go_backend listen:", err)
		os.Exit(1)
	}
	fmt.Println(listener.Addr().String())

	server := &http.Server{
		Handler:           http.HandlerFunc(handle),
		ReadHeaderTimeout: 2 * time.Second,
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()

	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(os.Stderr, "native_pair_go_backend serve:", err)
		os.Exit(1)
	}
}

func handle(w http.ResponseWriter, r *http.Request) {
	scenario := strings.TrimPrefix(r.URL.Path, "/scenario/")
	if scenario == r.URL.Path {
		scenario = strings.Trim(r.URL.Path, "/")
	}

	switch scenario {
	case "go-redirect":
		w.Header().Set("Location", "https://exploit.invalid/resources/")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusFound)
	case "go-strict-cl":
		writeJSON(w, http.StatusBadRequest, `{"error":"Invalid request"}`)
	case "go-400":
		writeJSON(w, http.StatusBadRequest, `{"error":"Bad request"}`)
	case "go-502":
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("Bad Gateway"))
	case "go-clean":
		w.Header().Set("Server", "lab-backend")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(cleanBody))
	case "go-ws-before-colon":
		body := cleanBody
		rawResponse(w, "200 OK", []string{
			"Content-Type: text/html",
			fmt.Sprintf("Content-Length : %d", len(body)),
			"Transfer-Encoding : chunked",
			"Connection: close",
		}, body)
	case "go-ws-leading":
		body := cleanBody
		rawResponse(w, "200 OK", []string{
			"Content-Type: text/html",
			fmt.Sprintf(" Content-Length: %d", len(body)),
			" Transfer-Encoding: chunked",
			"Connection: close",
		}, body)
	case "go-clte":
		body := cleanBody
		rawResponse(w, "200 OK", []string{
			"Content-Type: text/html",
			fmt.Sprintf("Content-Length: %d", len(body)),
			"Transfer-Encoding: chunked",
			"Connection: close",
		}, body)
	case "go-dup-cl":
		body := `{"error":"Invalid request"}`
		rawResponse(w, "400 Bad Request", []string{
			"Content-Type: application/json",
			fmt.Sprintf("Content-Length: %d", len(body)),
			"Content-Length: 0",
			"Connection: close",
		}, body)
	default:
		writeJSON(w, http.StatusNotFound, `{"error":"unknown scenario"}`)
	}
}

func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

// rawResponse bypasses net/http header sanitisation so the corpus can exercise
// literal whitespace before/after header colons and duplicate CL values.
func rawResponse(w http.ResponseWriter, status string, headers []string, body string) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	conn, buf, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	_, _ = fmt.Fprintf(buf, "HTTP/1.1 %s\r\n", status)
	for _, header := range headers {
		_, _ = fmt.Fprintf(buf, "%s\r\n", header)
	}
	_, _ = fmt.Fprint(buf, "\r\n")
	_, _ = fmt.Fprint(buf, body)
	_ = buf.Flush()
}
