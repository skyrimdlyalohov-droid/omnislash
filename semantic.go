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

// SemanticProcess owns the single Python analyzer child. Starting one process
// per response with os/exec would cost 50-100 ms each; this starts it once.
type SemanticProcess struct {
	cmd  *exec.Cmd
	done chan struct{}
}

// StartSemanticService launches research/semantic_service.py bound strictly to
// addr. It is local only: no CDN, no virtualenv, no outbound socket.
func StartSemanticService(ctx context.Context, addr, workDir string, logger *slog.Logger) (*SemanticProcess, error) {
	if err := validateLoopbackAddr(addr); err != nil {
		return nil, err
	}
	if workDir == "" {
		workDir = "."
	}
	script := filepath.Join(workDir, "research", "semantic_service.py")
	if _, err := os.Stat(script); err != nil {
		return nil, fmt.Errorf("semantic service: %w", err)
	}
	cmd := exec.CommandContext(ctx, "python3", script, "--addr", addr)
	cmd.Dir = workDir
	cmd.Env = append(os.Environ(), "PYTHONUNBUFFERED=1")
	sink := io.Writer(io.Discard)
	if logger != nil {
		sink = &onlineLogWriter{logger: logger}
	}
	cmd.Stdout = sink
	cmd.Stderr = sink
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("semantic service: start python: %w", err)
	}
	p := &SemanticProcess{cmd: cmd, done: make(chan struct{})}
	go func() {
		err := cmd.Wait()
		if logger != nil && err != nil && ctx.Err() == nil {
			logger.Warn("semantic service exited", "error", err)
		}
		close(p.done)
	}()
	client, err := NewSemanticClient(addr)
	if err != nil {
		return p, err
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return p, ctx.Err()
		case <-p.done:
			return p, fmt.Errorf("semantic service: python exited during startup")
		default:
		}
		probeCtx, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
		req, _ := http.NewRequestWithContext(probeCtx, http.MethodGet, "http://"+addr+"/healthz", nil)
		resp, err := client.client.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<10))
			_ = resp.Body.Close()
			cancel()
			return p, nil
		}
		cancel()
		time.Sleep(20 * time.Millisecond)
	}
	return p, fmt.Errorf("semantic service: health check timed out")
}

// Done is closed when the Python child exits.
func (p *SemanticProcess) Done() <-chan struct{} {
	if p == nil {
		return nil
	}
	return p.done
}
