package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/skyrimdlyalohov-droid/omnislash"
)

var version = "1.0.0"

func main() {
	if err := run(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		printUsage()
		return nil
	}
	switch args[0] {
	case "check":
		return cmdCheck(args[1:])
	case "fetch":
		return cmdFetch(args[1:])
	case "serve":
		return cmdServe(args[1:])
	case "scrape":
		return cmdScrape(args[1:])
	case "healthcheck":
		return cmdHealthcheck(args[1:])
	case "faq":
		return cmdFaq(args[1:])
	case "version", "-version", "--version":
		fmt.Println("omnislash", version)
		return nil
	case "help", "-h", "--help":
		printUsage()
		return nil
	default:
		printUsage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `omnislash %s — пул прокси и ротация IP для сканеров

Использование:
  omnislash check  [флаги]   проверить прокси из файла
  omnislash scrape [флаги]   собрать, проверить и показать живые прокси
  omnislash fetch  [флаги]   сделать N запросов через разные IP (демо)
  omnislash serve  [флаги]   поднять локальный HTTP-шлюз + stats

Команды:
  omnislash faq [флаги]   показать FAQ (опционально -topic <ключ>)

Служебное:
  omnislash healthcheck [флаги]  проверить /readyz (для Docker healthcheck)

Общие флаги:
  -config string     JSON-конфиг (по умолчанию встроенные значения)
  -proxies string    файл со списком прокси (env OMNISLASH_PROXIES, по умолчанию proxies.txt)
  -log-level string  debug|info|warn|error

Примеры:
  omnislash check -proxies proxies.txt
  omnislash scrape -config config.json -write live.txt
  omnislash fetch -url https://api.ipify.org -n 10
  omnislash serve -listen 127.0.0.1:3128
`, version)
}

type commonFlags struct {
	config            string
	proxies           string
	logLevel          string
	allowEmptyProxies bool
}

func addCommonFlags(fs *flag.FlagSet) *commonFlags {
	c := &commonFlags{}
	defaultProxies := os.Getenv("OMNISLASH_PROXIES")
	if defaultProxies == "" {
		defaultProxies = "proxies.txt"
	}
	fs.StringVar(&c.config, "config", "", "путь к JSON-конфигу")
	fs.StringVar(&c.proxies, "proxies", defaultProxies, "файл со списком прокси")
	fs.StringVar(&c.logLevel, "log-level", "", "debug|info|warn|error")
	return c
}

func (c *commonFlags) load() (*omnislash.Config, []*omnislash.Proxy, *slog.Logger, error) {
	cfg, err := omnislash.LoadConfig(c.config)
	if err != nil {
		return nil, nil, nil, err
	}
	if c.logLevel != "" {
		cfg.LogLevel = c.logLevel
		if err := cfg.Validate(); err != nil {
			return nil, nil, nil, err
		}
	}
	logger := newLogger(cfg.LogLevel)

	proxies, err := omnislash.LoadProxyFile(c.proxies, cfg.DefaultScheme)
	if err != nil {
		missing := errors.Is(err, fs.ErrNotExist)
		if missing && (cfg.AllowDirect || cfg.Scraper.Enabled || c.allowEmptyProxies) {
			logger.Warn("proxy list not found; starting with an empty pool", "path", c.proxies)
		} else {
			return nil, nil, nil, err
		}
	}
	return cfg, proxies, logger, nil
}

func newLogger(level string) *slog.Logger {
	var lv slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lv = slog.LevelDebug
	case "warn", "warning":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lv}))
}

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}
