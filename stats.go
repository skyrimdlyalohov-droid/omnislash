package omnislash

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// ServeStats exposes /stats, /healthz, /readyz, /status and /experience plus
// the embedded dashboard until ctx is canceled. It returns nil on a clean
// shutdown. The variadic UI options keep existing callers source-compatible.
func ServeStats(ctx context.Context, addr string, pool *Pool, logger *slog.Logger, ui ...UIOptions) error {
	if addr == "" {
		return nil
	}
	if logger == nil {
		logger = pool.log
	}
	var uiOpts UIOptions
	if len(ui) > 0 {
		uiOpts = ui[0]
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(pool.Stats())
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if pool.Available() == 0 {
			http.Error(w, "no available proxies", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ready\n"))
	})
	// These two routes originate from the daemon control server. Registering
	// them here as well keeps one control port for both entrypoints.
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		value := any(map[string]any{"jobs": []any{}})
		if uiOpts.Status != nil {
			value = uiOpts.Status()
		}
		_ = enc.Encode(value)
	})
	mux.HandleFunc("/experience", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		value := any(map[string]any{"enabled": false, "cells": []any{}})
		if uiOpts.Experience != nil {
			value = uiOpts.Experience()
		}
		_ = enc.Encode(value)
	})

	RegisterUI(mux, uiOpts.withDefaults(pool))

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = srv.Shutdown(shutdownCtx)
		case <-done:
		}
	}()
	logger.Info("stats endpoint listening", "addr", ln.Addr().String(), "stats", "http://"+ln.Addr().String()+"/stats", "ui", "http://"+ln.Addr().String()+"/")
	err = srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
