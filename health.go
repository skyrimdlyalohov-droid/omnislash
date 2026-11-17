package omnislash

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// HealthChecker probes proxies by opening a tunnel and performing a small
// HTTP request to a known endpoint.
type HealthChecker struct {
	pool   *Pool
	dialer *Dialer
	cfg    HealthConfig
	log    *slog.Logger
	probe  *url.URL
}

// NewHealthChecker creates a checker. The probe URL is validated here.
func NewHealthChecker(pool *Pool, dialer *Dialer, logger *slog.Logger) (*HealthChecker, error) {
	if logger == nil {
		logger = pool.log
	}
	cfg := pool.cfg.Health
	u, err := url.Parse(cfg.ProbeURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("invalid health probe URL %q", cfg.ProbeURL)
	}
	return &HealthChecker{pool: pool, dialer: dialer, cfg: cfg, log: logger, probe: u}, nil
}

// HealthSummary reports the result of a full pool sweep.
type HealthSummary struct {
	Checked    int       `json:"checked"`
	Healthy    int       `json:"healthy"`
	Failed     int       `json:"failed"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
}

// CheckAll probes every proxy in parallel. Proxies that fail are put into
// cooldown with exponential backoff.
func (h *HealthChecker) CheckAll(ctx context.Context) HealthSummary {
	start := time.Now()
	summary := HealthSummary{StartedAt: start}
	proxies := h.pool.Proxies()
	sem := make(chan struct{}, h.cfg.Concurrency)
	var wg sync.WaitGroup
	var healthy, failed atomic.Int64

	for _, pr := range proxies {
		if ctx.Err() != nil {
			break
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(pr *Proxy) {
			defer wg.Done()
			defer func() { <-sem }()
			began := time.Now()
			err := h.checkOne(ctx, pr)
			now := h.pool.now()
			if err != nil {
				if ctx.Err() == nil {
					pr.markHealthFailure(now, err, h.pool.cfg.Cooldown)
					failed.Add(1)
					h.log.Debug("proxy health check failed", "proxy", pr.Label(), "error", err)
				}
				return
			}
			pr.markSuccess(now, time.Since(began))
			healthy.Add(1)
		}(pr)
	}
	wg.Wait()
	summary.Healthy = int(healthy.Load())
	summary.Failed = int(failed.Load())
	summary.Checked = summary.Healthy + summary.Failed
	summary.FinishedAt = time.Now()
	return summary
}

// Run performs an optional startup sweep and then runs periodic checks until
// ctx is canceled.
func (h *HealthChecker) Run(ctx context.Context) {
	if !h.cfg.Enabled {
		return
	}
	if h.cfg.StartupCheck {
		sctx := ctx
		var cancel context.CancelFunc
		if h.cfg.StartupWait.Std() > 0 {
			sctx, cancel = context.WithTimeout(ctx, h.cfg.StartupWait.Std())
		}
		s := h.CheckAll(sctx)
		if cancel != nil {
			cancel()
		}
		h.log.Info("startup proxy check finished",
			"checked", s.Checked, "healthy", s.Healthy, "failed", s.Failed,
			"duration", s.FinishedAt.Sub(s.StartedAt).Round(time.Millisecond))
	}
	h.RunPeriodic(ctx)
}

// RunPeriodic runs only the periodic checks. Use it when the startup sweep was
// already performed synchronously.
func (h *HealthChecker) RunPeriodic(ctx context.Context) {
	if !h.cfg.Enabled {
		return
	}
	ticker := time.NewTicker(h.cfg.Interval.Std())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s := h.CheckAll(ctx)
			if s.Checked == 0 {
				continue
			}
			h.log.Info("proxy health check finished",
				"checked", s.Checked, "healthy", s.Healthy, "failed", s.Failed,
				"duration", s.FinishedAt.Sub(s.StartedAt).Round(time.Millisecond))
		}
	}
}

func (h *HealthChecker) checkOne(ctx context.Context, pr *Proxy) error {
	timeout := h.cfg.Timeout.Std()
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	hostport := h.probe.Host
	if h.probe.Port() == "" {
		port := "80"
		if h.probe.Scheme == "https" {
			port = "443"
		}
		hostport = net.JoinHostPort(h.probe.Hostname(), port)
	}
	conn, err := h.dialer.dialProxyRaw(cctx, pr, hostport)
	if err != nil {
		return err
	}
	defer conn.Close()

	var rw net.Conn = conn
	if h.probe.Scheme == "https" {
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         h.probe.Hostname(),
			InsecureSkipVerify: h.cfg.TLSSkipVerify,
			MinVersion:         tls.VersionTLS12,
		})
		if err := tlsConn.HandshakeContext(cctx); err != nil {
			return fmt.Errorf("probe TLS handshake: %w", err)
		}
		rw = tlsConn
	}

	path := h.probe.RequestURI()
	if path == "" {
		path = "/"
	}
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: omnislash-health/1\r\nConnection: close\r\n\r\n", path, h.probe.Host)
	if _, err := io.WriteString(rw, req); err != nil {
		return fmt.Errorf("probe request: %w", err)
	}

	tp := textproto.NewReader(bufio.NewReader(rw))
	line, err := tp.ReadLine()
	if err != nil {
		return fmt.Errorf("probe response: %w", err)
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return fmt.Errorf("malformed probe status %q", line)
	}
	code, err := strconv.Atoi(fields[1])
	if err != nil {
		return fmt.Errorf("malformed probe status %q", line)
	}
	if _, err := tp.ReadMIMEHeader(); err != nil {
		return fmt.Errorf("probe headers: %w", err)
	}
	if code < 200 || code >= 400 {
		return fmt.Errorf("probe returned HTTP %d", code)
	}
	return nil
}
