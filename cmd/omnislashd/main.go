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
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/skyrimdlyalohov-droid/omnislash"
	"github.com/skyrimdlyalohov-droid/omnislash/daemon"
	"github.com/skyrimdlyalohov-droid/omnislash/playbook"
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
		configPath    = flag.String("config", "", "daemon config file")
		once          = flag.Bool("once", false, "run every job once and exit")
		jobName       = flag.String("job", "", "run only this job once and exit")
		logLevel      = flag.String("log-level", "info", "debug|info|warn|error")
		versionOut    = flag.Bool("version", false, "print version")
		onlineFlag    = flag.String("online-learning", "", "override config online_learning (true|false)")
		orchestrator  = flag.Bool("orchestrator", false, "enable the top-level Go FSM / Thompson orchestrator")
		fullAuto      = flag.Bool("full-auto", false, "run the safety-gated recon -> learn -> controlled attack pipeline")
		forceImpact   = flag.Bool("force-impact", false, "allow full-auto escalation to impact paths such as /pay or /admin")
		playbookPaths []string
	)
	flag.Func("playbook", "curated playbook case JSON; seeds experience with a provenance-tagged prior (repeatable)", func(path string) error {
		playbookPaths = append(playbookPaths, path)
		return nil
	})
	flag.Parse()
	if *versionOut {
		fmt.Println("omnislashd", version)
		return nil
	}
	if *configPath == "" {
		return errors.New("omnislashd: -config is required")
	}
	if *fullAuto && (*jobName != "" || *once) {
		return errors.New("omnislashd: -full-auto cannot be combined with -job or -once")
	}
	if *forceImpact && !*fullAuto {
		return errors.New("omnislashd: -force-impact requires -full-auto")
	}

	logger := newLogger(*logLevel)
	cfg, err := daemon.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	if *fullAuto {
		cfg.FullAuto.Enabled = true
	}
	if *forceImpact {
		cfg.FullAuto.ForceImpact = true
	}
	if value := strings.TrimSpace(*onlineFlag); value != "" {
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("omnislashd: invalid -online-learning value %q: %w", value, err)
		}
		cfg.OnlineLearning = &enabled
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
	runners.SetLimits(transport.Probe)
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
	ui := omnislash.UIOptions{
		Config:     transport,
		Pool:       pool,
		Scope:      pool.Scope(),
		ConfigPath: cfg.OmnislashConfig,
	}
	if cfg.LogFile != "" {
		ui.AuditPaths = []string{cfg.LogFile}
	}
	d.SetUI(ui)
	if *orchestrator {
		d.EnableOrchestrator()
		logger.Info("top-level orchestrator enabled", "beta_source", cfg.OnlinePaths.WeightsPath)
	}
	for _, path := range playbookPaths {
		caseFile, err := playbook.Load(path)
		if err != nil {
			return err
		}
		d.Learn(caseFile.Seeds())
		logger.Info("playbook loaded", "path", path, "id", caseFile.ID, "provenance", caseFile.Provenance.Kind)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Warm the exit pool before any heavy probe. Without this sweep a stale
	// proxy file turns the first gadget/differential job into an i/o timeout
	// instead of a target response, and the run never reaches the targets.
	if transport.Health.Enabled {
		checker, err := omnislash.NewHealthChecker(pool, dialer, logger)
		if err != nil {
			return err
		}
		if transport.Health.StartupCheck {
			sctx := ctx
			cancel := func() {}
			if wait := transport.Health.StartupWait.Std(); wait > 0 {
				sctx, cancel = context.WithTimeout(ctx, wait)
			}
			summary := checker.CheckAll(sctx)
			cancel()
			logger.Info("startup proxy check finished",
				"checked", summary.Checked, "healthy", summary.Healthy, "failed", summary.Failed,
				"duration", summary.FinishedAt.Sub(summary.StartedAt).Round(time.Millisecond))
			if len(proxies) > 0 && summary.Healthy == 0 {
				return errors.New("omnislashd: no healthy proxies after startup check; refresh the pool before the active run")
			}
		}
		go checker.RunPeriodic(ctx)
	}

	if transport.Safety.Deception.Enabled && transport.Safety.Deception.SemanticService {
		semantic, err := omnislash.StartSemanticService(ctx, transport.Safety.Deception.SemanticAddr, ".", logger)
		if err != nil {
			if transport.Safety.Deception.SemanticRequired {
				pool.Audit().Log(omnislash.AuditEvent{
					Kind:               "deception",
					Reason:             "deception_uncertain",
					DeceptionUncertain: true,
				})
				return fmt.Errorf("semantic skeleton service is required: %w", err)
			}
			logger.Warn("semantic skeleton service did not start; NCD will use raw samples", "error", err)
		} else {
			defer semantic.Close()
			logger.Info("semantic skeleton service started", "addr", transport.Safety.Deception.SemanticAddr)
		}
	}

	if *fullAuto {
		if err := d.EnableFullAuto(); err != nil {
			return err
		}
		results, err := d.RunFullAuto(ctx)
		emitFullAuto(results)
		if err != nil {
			return err
		}
		return nil
	}

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

// emitFullAuto prints the safe-pipeline verdicts. A result in
// AWAITING_HUMAN_VERIFICATION is a stop condition, not an escalation.
func emitFullAuto(results []daemon.FullAutoResult) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(results)
}
