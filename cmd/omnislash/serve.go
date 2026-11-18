package main

import (
	"context"
	"flag"
	"fmt"
	"strings"
	"sync"

	"github.com/skyrimdlyalohov-droid/omnislash"
)

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	common := addCommonFlags(fs)
	listen := fs.String("listen", "", "адрес локального CONNECT-шлюза (off — выключить)")
	statsAddr := fs.String("stats", "", "адрес stats-сервера (off — выключить)")
	token := fs.String("token", "", "Bearer-токен для CONNECT-шлюза")
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

	ctx, stop := signalContext()
	defer stop()

	if cfg.Scraper.Enabled {
		scraper, err := omnislash.NewScraper(pool, cfg.Scraper, logger)
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
		logger.Info("rotating CONNECT gateway listening",
			"addr", gateway.Addr().String(), "proxies", pool.Len(), "available", pool.Available())
	}
	if cfg.Stats.Listen != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := omnislash.ServeStats(ctx, cfg.Stats.Listen, pool, logger); err != nil {
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
