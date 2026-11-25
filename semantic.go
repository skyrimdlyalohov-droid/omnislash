package omnislash

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

// SemanticClient talks to the loopback structural skeleton service. It is
// intelligence-only: it receives a body sample that the Go side already owns,
// and it never dials a target. The transport DialContext is restricted to
// loopback addresses even if the configured address is changed at runtime.
type SemanticClient struct {
	addr    string
	timeout time.Duration
	client  *http.Client
}

// NewSemanticClient validates addr and builds a loopback-only HTTP client.
func NewSemanticClient(addr string) (*SemanticClient, error) {
	if err := validateLoopbackAddr(addr); err != nil {
		return nil, fmt.Errorf("semantic service: %w", err)
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, target string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(target)
			if err != nil {
				return nil, err
			}
			ip := net.ParseIP(host)
			if ip == nil || !ip.IsLoopback() {
				return nil, fmt.Errorf("semantic service forbids non-loopback dial %q", target)
			}
			return (&net.Dialer{Timeout: 250 * time.Millisecond}).DialContext(ctx, network, target)
		},
		MaxIdleConns:      4,
		DisableKeepAlives: false,
	}
	return &SemanticClient{
		addr:    addr,
		timeout: 200 * time.Millisecond,
		client:  &http.Client{Transport: transport, Timeout: 200 * time.Millisecond},
	}, nil
}

type semanticRequest struct {
	Body        string `json:"body"`
	ContentType string `json:"content_type,omitempty"`
}

type semanticResponse struct {
	Status   string `json:"status"`
	Skeleton string `json:"skeleton"`
	Error    string `json:"error,omitempty"`
}

// Skeleton returns a value-free canonical skeleton of body. Callers cap the
// sample before calling so a hostile response cannot make NCD expensive.
func (c *SemanticClient) Skeleton(body []byte, contentType string) (string, error) {
	if c == nil {
		return "", fmt.Errorf("semantic service: nil client")
	}
	payload, err := json.Marshal(semanticRequest{Body: string(body), ContentType: contentType})
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"http://"+c.addr+"/skeleton", bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		var failure semanticResponse
		_ = json.Unmarshal(raw, &failure)
		if failure.Error != "" {
			return "", fmt.Errorf("semantic service: HTTP %d: %s", resp.StatusCode, failure.Error)
		}
		return "", fmt.Errorf("semantic service: HTTP %d", resp.StatusCode)
	}
	var out semanticResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("semantic service: decode: %w", err)
	}
	if out.Skeleton == "" {
		return "", fmt.Errorf("semantic service: empty skeleton")
	}
	return out.Skeleton, nil
}

// semanticRestartDelay is intentionally a code-level constant. A crashed
// analyzer must not be restarted in a tight loop, and a restart must not race
// the previous child's listening socket.
const semanticRestartDelay = 2 * time.Second

// SemanticProcess owns the single Python analyzer child and supervises it.
// Starting one process per response with os/exec would cost 50-100 ms each;
// this starts it once and restarts it after a crash.
type SemanticProcess struct {
	addr    string
	workDir string
	script  string
	log     *slog.Logger
	ctx     context.Context
	cancel  context.CancelFunc
	done    chan struct{}

	mu       sync.Mutex
	cmd      *exec.Cmd
	restarts int
}

// StartSemanticService launches research/semantic_service.py bound strictly to
// addr and keeps it alive with a supervisor: Wait -> 2 s pause -> restart. It is
// local only: no CDN, no virtualenv, no outbound socket.
func StartSemanticService(ctx context.Context, addr, workDir string, logger *slog.Logger) (*SemanticProcess, error) {
	if err := validateLoopbackAddr(addr); err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if workDir == "" {
		workDir = "."
	}
	script := filepath.Join(workDir, "research", "semantic_service.py")
	if _, err := os.Stat(script); err != nil {
		return nil, fmt.Errorf("semantic service: %w", err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	p := &SemanticProcess{
		addr:    addr,
		workDir: workDir,
		script:  script,
		log:     logger,
		ctx:     runCtx,
		cancel:  cancel,
		done:    make(chan struct{}),
	}
	if err := p.start(); err != nil {
		cancel()
		return nil, err
	}
	go p.supervise()
	if err := p.waitHealthy(runCtx, 2*time.Second); err != nil {
		p.Close()
		return nil, err
	}
	return p, nil
}

func (p *SemanticProcess) start() error {
	cmd := exec.CommandContext(p.ctx, "python3", p.script, "--addr", p.addr)
	cmd.Dir = p.workDir
	cmd.Env = append(os.Environ(), "PYTHONUNBUFFERED=1")
	sink := io.Writer(io.Discard)
	if p.log != nil {
		sink = &onlineLogWriter{logger: p.log}
	}
	cmd.Stdout = sink
	cmd.Stderr = sink
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("semantic service: start python: %w", err)
	}
	p.mu.Lock()
	p.cmd = cmd
	p.mu.Unlock()
	return nil
}

// supervise is the only goroutine that calls Wait. It restarts the child after
// a fixed 2 s pause, so a crashing analyzer cannot spin or leave two children
// competing for the loopback port.
func (p *SemanticProcess) supervise() {
	defer close(p.done)
	for {
		p.mu.Lock()
		cmd := p.cmd
		p.mu.Unlock()
		if cmd == nil {
			if err := p.start(); err != nil {
				if p.log != nil {
					p.log.Warn("semantic service restart failed", "error", err)
				}
				if !p.sleep(semanticRestartDelay) {
					return
				}
			}
			continue
		}
		err := cmd.Wait()
		p.mu.Lock()
		if p.cmd == cmd {
			p.cmd = nil
		}
		p.mu.Unlock()
		if p.ctx.Err() != nil {
			return
		}
		p.mu.Lock()
		p.restarts++
		p.mu.Unlock()
		if p.log != nil {
			p.log.Warn("semantic service exited; restarting", "error", err, "delay", semanticRestartDelay)
		}
		if !p.sleep(semanticRestartDelay) {
			return
		}
		if err := p.start(); err != nil {
			if p.log != nil {
				p.log.Warn("semantic service restart failed", "error", err)
			}
			if !p.sleep(semanticRestartDelay) {
				return
			}
		}
	}
}

func (p *SemanticProcess) sleep(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-p.ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func (p *SemanticProcess) waitHealthy(ctx context.Context, timeout time.Duration) error {
	client, err := NewSemanticClient(p.addr)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(timeout)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("semantic service: health check timed out")
		}
		probeCtx, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
		req, reqErr := http.NewRequestWithContext(probeCtx, http.MethodGet, "http://"+p.addr+"/healthz", nil)
		if reqErr == nil {
			resp, doErr := client.client.Do(req)
			if doErr == nil {
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<10))
				_ = resp.Body.Close()
				cancel()
				return nil
			}
		}
		cancel()
		t := time.NewTimer(20 * time.Millisecond)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}

// Close stops the supervisor and the child. It is synchronous: a one-shot
// command can call it and then exit immediately without leaving an orphaned
// analyzer bound to the loopback port. It is safe to call more than once.
func (p *SemanticProcess) Close() {
	if p == nil {
		return
	}
	if p.cancel != nil {
		p.cancel()
	}
	select {
	case <-p.done:
		return
	case <-time.After(3 * time.Second):
	}
	// CommandContext kills the child asynchronously. If the process is about
	// to exit (os.Exit in -job/-once mode), the killer goroutine may never get
	// scheduled, so kill directly and give Wait a bounded chance to finish.
	p.mu.Lock()
	cmd := p.cmd
	p.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	select {
	case <-p.done:
	case <-time.After(time.Second):
	}
}

// Done is closed when the supervisor stops, either because the context was
// cancelled or because Close was called.
func (p *SemanticProcess) Done() <-chan struct{} {
	if p == nil {
		return nil
	}
	return p.done
}

// Restarts reports how many times the child was restarted after a crash.
func (p *SemanticProcess) Restarts() int {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.restarts
}
