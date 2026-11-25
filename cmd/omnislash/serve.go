package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/skyrimdlyalohov-droid/omnislash"
	"github.com/skyrimdlyalohov-droid/omnislash/daemon"
	"github.com/skyrimdlyalohov-droid/omnislash/probe"
)

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	common := addCommonFlags(fs)
	listen := fs.String("listen", "", "адрес локального HTTP-шлюза (off — выключить)")
	statsAddr := fs.String("stats", "", "адрес stats-сервера (off — выключить)")
	token := fs.String("token", "", "Bearer-токен для HTTP-шлюза")
	noHealth := fs.Bool("no-health", false, "не запускать health-check")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, proxies, logger, err := common.load()
	if err != nil {
		return err
	}
	cfg.Gateway.Listen = resolveAddr(*listen, cfg.Gateway.Listen)
	cfg.Stats.Listen = resolveAddr(*statsAddr, cfg.Stats.Listen)
	if *token != "" {
		cfg.Gateway.Token = *token
	}
	if *noHealth {
		cfg.Health.Enabled = false
	}
	if err := cfg.Validate(); err != nil {
		return err
	}

	pool, err := omnislash.NewPool(cfg, proxies, logger)
	if err != nil {
		return err
	}
	dialer := omnislash.NewDialer(pool, logger)

	// The control UI reuses the same pinned transport as the daemon. TLS is
	// configured here so Quick Run can select h1/h2 without opening raw sockets.
	runners := daemon.NewRunnerSet(dialer)
	runners.H1.TLS = &tls.Config{NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12}
	runners.H2.TLS = &tls.Config{NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS12}

	ctx, stop := signalContext()
	defer stop()

	// One loopback Python child supplies value-free skeletons for NCD. It is
	// started once; no os/exec happens per HTTP response.
	if cfg.Safety.Deception.Enabled && cfg.Safety.Deception.SemanticService {
		if _, err := omnislash.StartSemanticService(ctx, cfg.Safety.Deception.SemanticAddr, ".", logger); err != nil {
			logger.Warn("semantic skeleton service did not start; NCD will use raw samples", "error", err)
		} else {
			logger.Info("semantic skeleton service started", "addr", cfg.Safety.Deception.SemanticAddr)
		}
	}

	// The same control process owns the streaming feedback worker. It tails the
	// configured audit from a persisted offset, so restarting serve never
	// replays old attempts or breaks the active transport sessions.
	if cfg.IsOnlineLearningEnabled() && cfg.Audit.Path != "" {
		opts := omnislash.DefaultOnlineLoopOptions(".")
		opts.AuditPath = cfg.Audit.Path
		if _, err := omnislash.StartOnlineLoop(ctx, opts, logger); err != nil {
			logger.Warn("online feedback loop could not start", "error", err)
		} else {
			logger.Info("online feedback loop starting", "audit", cfg.Audit.Path)
		}
	}

	var scraper *omnislash.Scraper
	if cfg.Scraper.Enabled {
		scraper, err = omnislash.NewScraper(pool, cfg.Scraper, logger)
		if err != nil {
			return err
		}
		if cfg.Scraper.StartupRefresh {
			sctx := ctx
			cancel := func() {}
			if wait := cfg.Scraper.StartupWait.Std(); wait > 0 {
				sctx, cancel = context.WithTimeout(ctx, wait)
			}
			stats, scrapeErr := scraper.Refresh(sctx)
			cancel()
			if scrapeErr != nil {
				logger.Warn("startup scrape failed", "error", scrapeErr)
			} else {
				logger.Info("startup scrape finished",
					"verified", stats.Accepted, "candidates", stats.Candidates,
					"sources", stats.Sources, "source_errors", stats.SourceErrors)
			}
		}
		go scraper.RunPeriodic(ctx)
	}

	if cfg.Health.Enabled {
		checker, err := omnislash.NewHealthChecker(pool, dialer, logger)
		if err != nil {
			return err
		}
		if cfg.Health.StartupCheck {
			sctx := ctx
			cancel := func() {}
			if cfg.Health.StartupWait.Std() > 0 {
				sctx, cancel = context.WithTimeout(ctx, cfg.Health.StartupWait.Std())
			}
			summary := checker.CheckAll(sctx)
			cancel()
			logger.Info("startup proxy check finished",
				"checked", summary.Checked, "healthy", summary.Healthy, "failed", summary.Failed)
			if summary.Healthy == 0 {
				logger.Warn("no healthy proxies after startup check; gateway will return 502 until a proxy recovers")
			}
		}
		go checker.RunPeriodic(ctx)
	}

	var gateway *omnislash.Gateway
	if cfg.Gateway.Listen != "" {
		gateway, err = omnislash.NewGateway(cfg.Gateway.Listen, dialer, cfg.Gateway.Token, logger)
		if err != nil {
			return fmt.Errorf("start gateway: %w", err)
		}
		defer gateway.Close()
	}
	if gateway == nil && cfg.Stats.Listen == "" {
		return fmt.Errorf("и шлюз, и stats выключены — нечего запускать")
	}

	errCh := make(chan error, 2)
	var wg sync.WaitGroup
	if gateway != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := gateway.Serve(ctx); err != nil {
				errCh <- fmt.Errorf("gateway: %w", err)
			}
		}()
		logger.Info("rotating HTTP gateway listening",
			"addr", gateway.Addr().String(), "proxies", pool.Len(), "available", pool.Available())
	}
	if cfg.Stats.Listen != "" {
		uiOpts := omnislash.UIOptions{
			Config:     cfg,
			Pool:       pool,
			Scope:      pool.Scope(),
			ConfigPath: common.config,
			Scraper:    scraper,
			Run:        uiQuickRunner(runners),
		}
		if cfg.Audit.Path != "" {
			uiOpts.AuditPaths = []string{cfg.Audit.Path}
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := omnislash.ServeStats(ctx, cfg.Stats.Listen, pool, logger, uiOpts); err != nil {
				errCh <- fmt.Errorf("stats: %w", err)
			}
		}()
	}

	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-errCh:
		stop()
	}
	wg.Wait()
	return serveErr
}

func resolveAddr(flagValue, cfgValue string) string {
	switch strings.ToLower(strings.TrimSpace(flagValue)) {
	case "":
		return cfgValue
	case "off", "none", "-":
		return ""
	default:
		return flagValue
	}
}

// uiQuickRunner maps the dashboard's small probe menu onto the same RunnerSet
// used by omnislashd. The target has already passed scope validation in the UI
// handler, and the underlying dialer applies the scope again before dialing.
func uiQuickRunner(runners *daemon.RunnerSet) func(context.Context, omnislash.UIRunRequest) (omnislash.UIRunResult, error) {
	return func(ctx context.Context, req omnislash.UIRunRequest) (omnislash.UIRunResult, error) {
		if runners == nil {
			return omnislash.UIRunResult{}, fmt.Errorf("quick run: no probe runners configured")
		}
		var p probe.Probe
		tlsMode := "h1"
		switch req.Probe {
		case "adaptive":
			p = &probe.DifferentialFuzzProbe{
				Pairs:            3,
				Timeout:          10 * time.Second,
				NeighborShiftNCD: 0.6,
			}
		case "smuggle-chain":
			p = &probe.SmuggleChainProbe{
				Variant:      probe.VariantCLTE,
				VictimMethod: "GET",
				VictimPath:   req.Path,
				Attempts:     1,
				Timeout:      10 * time.Second,
			}
		case "h2-cl":
			tlsMode = "h2"
			p = &probe.H2CLProbe{
				Method:         "GET",
				Path:           req.Path,
				DeclaredLength: 0,
				VictimMethod:   "GET",
				VictimPath:     req.Path,
				Attempts:       1,
				Timeout:        10 * time.Second,
			}
		case "raw-replay":
			return omnislash.UIRunResult{}, fmt.Errorf("quick run: raw-replay needs a payload; use a configured daemon job")
		default:
			return omnislash.UIRunResult{}, fmt.Errorf("quick run: unsupported probe %q", req.Probe)
		}
		target := probe.Target{Addr: req.Target, Host: uiHostHeader(req), Path: req.Path}
		res, err := runners.Run(ctx, target, p, tlsMode)
		out := omnislash.UIRunResult{
			Job:     "ui-quick-run",
			Probe:   req.Probe,
			Target:  req.Target,
			Success: err == nil,
		}
		if err != nil {
			out.Error = err.Error()
			out.Message = "quick run failed"
		} else {
			out.Message = "quick run completed"
		}
		if res != nil {
			for _, finding := range res.Findings {
				out.Findings = append(out.Findings, finding.Kind+" ("+finding.Confidence+")")
			}
			for _, response := range res.Responses {
				out.Statuses = append(out.Statuses, response.Status)
			}
		}
		return out, nil
	}
}

func uiHostHeader(req omnislash.UIRunRequest) string {
	original := strings.TrimSpace(req.Original)
	if original != "" {
		if host, _, err := net.SplitHostPort(original); err == nil {
			return host
		}
		if !strings.Contains(original, "://") {
			return strings.Trim(original, "[]")
		}
	}
	if host, _, err := net.SplitHostPort(req.Target); err == nil {
		return strings.Trim(host, "[]")
	}
	return req.Target
}
