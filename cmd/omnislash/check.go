package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/skyrimdlyalohov-droid/omnislash"
)

func cmdCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	common := addCommonFlags(fs)
	jsonOut := fs.Bool("json", false, "вывести JSON")
	timeout := fs.Duration("timeout", 0, "таймаут одной проверки (переопределяет конфиг)")
	concurrency := fs.Int("concurrency", 0, "параллельных проверок (переопределяет конфиг)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, proxies, logger, err := common.load()
	if err != nil {
		return err
	}
	if *timeout > 0 {
		cfg.Health.Timeout = omnislash.Duration(*timeout)
	}
	if *concurrency > 0 {
		cfg.Health.Concurrency = *concurrency
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	pool, err := omnislash.NewPool(cfg, proxies, logger)
	if err != nil {
		return err
	}
	dialer := omnislash.NewDialer(pool, logger)
	checker, err := omnislash.NewHealthChecker(pool, dialer, logger)
	if err != nil {
		return err
	}

	ctx, stop := signalContext()
	defer stop()
	summary := checker.CheckAll(ctx)

	if *jsonOut {
		out := struct {
			Summary omnislash.HealthSummary `json:"summary"`
			Pool    omnislash.Stats         `json:"pool"`
		}{Summary: summary, Pool: pool.Stats()}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			return err
		}
	} else {
		fmt.Printf("Проверено: %d, живых: %d, ошибок: %d, время: %s\n\n",
			summary.Checked, summary.Healthy, summary.Failed,
			summary.FinishedAt.Sub(summary.StartedAt).Round(time.Millisecond))
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "ПРОКСИ\tСТАТУС\tЗАДЕРЖКА\tОШИБКА")
		for _, ps := range pool.Stats().Proxies {
			status := "unknown"
			switch {
			case ps.Disabled:
				status = "disabled"
			case ps.InCooldown:
				status = "cooldown"
			case ps.Alive:
				status = "ok"
			case ps.LastError != "":
				status = "fail"
			}
			lat := "-"
			if ps.LatencyMS > 0 {
				lat = fmt.Sprintf("%.0fms", ps.LatencyMS)
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", ps.Proxy, status, lat, ps.LastError)
		}
		_ = w.Flush()
	}

	if summary.Healthy == 0 {
		return fmt.Errorf("ни один прокси не прошёл проверку")
	}
	return nil
}
