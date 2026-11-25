package daemon

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/skyrimdlyalohov-droid/omnislash"
)

func TestRunAdHocIsFailClosed(t *testing.T) {
	cfg := testConfig(testJob())
	d, err := New(cfg, &fakeExec{}, nil, &strings.Builder{})
	if err != nil {
		t.Fatal(err)
	}
	req := omnislash.UIRunRequest{Target: "127.0.0.1:80", Probe: "adaptive", Path: "/"}

	if _, err := d.RunAdHoc(context.Background(), req); err == nil {
		t.Fatal("RunAdHoc without UI scope unexpectedly succeeded")
	}

	transport := omnislash.DefaultConfig()
	transport.Scope.Enabled = true
	transport.Scope.AllowHosts = []string{"192.0.2.10"}
	transport.Scope.AllowPorts = []int{80}
	transport.Scope.AllowPrivate = true
	scope, err := omnislash.NewScope(transport.Scope)
	if err != nil {
		t.Fatal(err)
	}
	d.SetUI(omnislash.UIOptions{Config: &transport, Scope: scope})
	if _, err := d.RunAdHoc(context.Background(), req); err == nil {
		t.Fatal("RunAdHoc with out-of-scope target unexpectedly succeeded")
	}

	transport.Scope.AllowHosts = []string{"127.0.0.1"}
	scope, err = omnislash.NewScope(transport.Scope)
	if err != nil {
		t.Fatal(err)
	}
	d.SetUI(omnislash.UIOptions{Config: &transport, Scope: scope})
	result, err := d.RunAdHoc(context.Background(), req)
	if err != nil {
		t.Fatalf("RunAdHoc in scope failed: %v", err)
	}
	if result.Target != req.Target || result.Probe != req.Probe {
		t.Errorf("result = %+v, request = %+v", result, req)
	}
}

func TestControlServerServesUIAndLegacyRoutes(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	disabled := false
	job := testJob()
	job.Enabled = &disabled
	cfg := testConfig(job)
	cfg.ControlAddr = addr
	cfg.PollInterval = omnislash.Duration(time.Hour)
	d, err := New(cfg, &fakeExec{}, nil, &strings.Builder{})
	if err != nil {
		t.Fatal(err)
	}
	d.SetUI(omnislash.UIOptions{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- d.Run(ctx) }()

	base := "http://" + addr
	var lastErr error
	for i := 0; i < 200; i++ {
		resp, err := http.Get(base + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			lastErr = nil
			break
		}
		lastErr = err
		time.Sleep(10 * time.Millisecond)
	}
	if lastErr != nil {
		t.Fatalf("control server never started: %v", lastErr)
	}

	resp, err := http.Get(base + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != `{"status":"ok"}` {
		t.Errorf("/healthz body = %q", body)
	}

	resp, err = http.Get(base + "/status")
	if err != nil {
		t.Fatal(err)
	}
	var status struct {
		Jobs []JobState `json:"jobs"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if len(status.Jobs) != 1 || status.Jobs[0].Name != job.Name {
		t.Errorf("/status jobs = %+v", status.Jobs)
	}

	resp, err = http.Get(base + "/experience")
	if err != nil {
		t.Fatal(err)
	}
	var experience struct {
		Enabled bool             `json:"enabled"`
		Cells   []ExperienceStat `json:"cells"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&experience); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if !experience.Enabled {
		t.Errorf("/experience enabled = false, want true")
	}

	resp, err = http.Get(base + "/")
	if err != nil {
		t.Fatal(err)
	}
	page, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(page), "OmniSlash Control") {
		t.Errorf("GET / = %d, body snippet = %.80q", resp.StatusCode, page)
	}

	resp, err = http.Get(base + "/api/dashboard")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /api/dashboard status = %d", resp.StatusCode)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("daemon did not shut down")
	}
}
