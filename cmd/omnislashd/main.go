// Command omnislashd runs probe jobs as a daemon.
//
// It loads an omnislash transport config, a scheduler config and, for every
// attempt, executes one probe through a pinned session. The daemon never dials
// a target itself: the probes own the request bytes, omnislash owns the socket.
//
//	omnislashd -config examples/daemon/daemon.json
//	omnislashd -config examples/daemon/daemon.json -once
//	omnislashd -config examples/daemon/daemon.json -job lab-clte-gpost
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/skyrimdlyalohov-droid/omnislash"
	"github.com/skyrimdlyalohov-droid/omnislash/daemon"
	"github.com/skyrimdlyalohov-droid/omnislash/probe"
)

var version = "0.1.0"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		configPath = flag.String("config", "", "daemon config file")
		once       = flag.Bool("once", false, "run every job once and exit")
		jobName    = flag.String("job", "", "run only this job once and exit")
		logLevel   = flag.String("log-level", "info", "debug|info|warn|error")
		versionOut = flag.Bool("version", false, "print version")
	)
	flag.Parse()
	if *versionOut {
		fmt.Println("omnislashd", version)
		return nil
	}
	if *configPath == "" {
		return errors.New("omnislashd: -config is required")
	}

	logger := newLogger(*logLevel)
	cfg, err := daemon.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	transport, err := omnislash.LoadConfig(cfg.OmnislashConfig)
	if err != nil {
		return fmt.Errorf("omnislashd: transport config: %w", err)
	}
	var proxies []*omnislash.Proxy
	if cfg.Proxies != "" {
		proxies, err = omnislash.LoadProxyFile(cfg.Proxies, transport.DefaultScheme)
		if err != nil {
			return fmt.Errorf("omnislashd: proxies: %w", err)
		}
	}
	pool, err := omnislash.NewPool(transport, proxies, logger)
	if err != nil {
		return fmt.Errorf("omnislashd: pool: %w", err)
	}
	dialer := omnislash.NewDialer(pool, logger)
	runners := daemon.NewRunnerSet(dialer)
	runners.H1.TLS = &tls.Config{NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12}
	runners.H2.TLS = &tls.Config{NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS12}

	audit, closeAudit, err := openAudit(cfg.LogFile)
	if err != nil {
		return err
	}
	defer closeAudit()

	d, err := daemon.New(cfg, runners, logger, audit)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *jobName != "" || *once {
		var outcomes []daemon.Outcome
		if *jobName != "" {
			out, err := d.RunJob(ctx, *jobName)
			if err != nil {
				return err
			}
			outcomes = []daemon.Outcome{out}
		} else {
			outcomes = d.RunOnce(ctx)
		}
		emit(outcomes)
		for _, out := range outcomes {
			if !out.Success {
				return fmt.Errorf("job %s did not reach its goal", out.Job)
			}
		}
		return nil
	}

	logger.Info("daemon starting", "version", version, "jobs", len(cfg.Jobs), "control", cfg.ControlAddr)
	return d.Run(ctx)
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}

func openAudit(path string) (*os.File, func(), error) {
	if path == "" {
		return nil, func() {}, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, nil, fmt.Errorf("omnislashd: open audit log: %w", err)
	}
	return f, func() { _ = f.Close() }, nil
}

// emit prints a compact view of every outcome. The full evidence is in the
// audit log; this is the operator-facing summary.
func emit(outcomes []daemon.Outcome) {
	type view struct {
		Job         string            `json:"job"`
		Success     bool              `json:"success"`
		Error       string            `json:"error,omitempty"`
		DurationMS  float64           `json:"duration_ms,omitempty"`
		Attribution probe.Attribution `json:"attribution"`
		Findings    []probe.Finding   `json:"findings,omitempty"`
		Statuses    []int             `json:"statuses,omitempty"`
		Exchanges   int               `json:"writes,omitempty"`
		Responses   int               `json:"responses,omitempty"`
	}
	out := make([]view, 0, len(outcomes))
	for _, o := range outcomes {
		v := view{Job: o.Job, Success: o.Success}
		if o.Err != nil {
			v.Error = o.Err.Error()
		}
		if r := o.Result; r != nil {
			v.DurationMS = float64(r.Duration.Microseconds()) / 1000
			v.Attribution = r.Attribution
			v.Findings = r.Findings
			v.Exchanges = len(r.Exchanges)
			v.Responses = len(r.Responses)
			for _, resp := range r.Responses {
				v.Statuses = append(v.Statuses, resp.Status)
			}
		}
		out = append(out, v)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}
