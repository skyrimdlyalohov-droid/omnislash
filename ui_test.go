package omnislash

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeUIScraper struct{ calls int }

func (s *fakeUIScraper) Refresh(context.Context) (ScraperStats, error) {
	s.calls++
	return ScraperStats{Accepted: 7, Candidates: 9, Sources: 3}, nil
}

type uiCaidoCapture struct {
	findings int
	url      string
	pat      string
}

func uiTestOptions(t *testing.T) (UIOptions, *fakeUIScraper, *uiCaidoCapture, *UIRunRequest) {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "state"), 0o755); err != nil {
		t.Fatal(err)
	}
	weights := `{
  "schema": "omnislash.learned-weights/v1",
  "examples": 17,
  "holdout": {"metrics": {"accuracy": 0.93, "examples": 4}}
}`
	vault := `{"version":1,"keys":[{"id":"k1","tech_stack_hash":"h2","tech_stack":["h2"],"provenance":"solution-derived"}]}`
	audit := strings.Join([]string{
		`{"time":"2026-11-25T01:00:00Z","job":"lab","target":"127.0.0.1:8080","probe":"smuggle-chain","tls":"h1","success":true,"findings":[{"kind":"smuggle_confirmed","confidence":"high","detail":"victim echo ncd=0.42"}],"result":{"responses":[{"raw":"HTTP/1.1 200 OK\r\n\r\nclean"},{"raw":"HTTP/1.1 200 OK\r\n\r\nGPOST"}]}}`,
		`{"time":"2026-11-25T01:01:00Z","job":"lab","target":"127.0.0.1:8080","success":true,"findings":[{"kind":"smuggle_confirmed","confidence":"low","detail":"unverified heuristic"}]}`,
		`{"time":"2026-11-25T01:02:00Z","job":"lab","target":"127.0.0.1:8080","success":false,"findings":[{"kind":"smuggle_confirmed","confidence":"high","detail":"failed attempt"}]}`,
	}, "\n") + "\n"
	for name, data := range map[string]string{
		"state/learned_weights.json": weights,
		"state/zero_day_vault.json":  vault,
		"audit.jsonl":                audit,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	cfg := DefaultConfig()
	cfg.Scope.Enabled = true
	cfg.Scope.AllowHosts = []string{"127.0.0.1"}
	cfg.Scope.AllowPorts = []int{80}
	cfg.Scope.AllowPrivate = true
	scope, err := NewScope(cfg.Scope)
	if err != nil {
		t.Fatal(err)
	}

	scraper := &fakeUIScraper{}
	caido := &uiCaidoCapture{}
	var lastRun UIRunRequest
	opts := UIOptions{
		Config:      &cfg,
		Scope:       scope,
		WorkDir:     dir,
		WeightsPath: "state/learned_weights.json",
		VaultPath:   "state/zero_day_vault.json",
		AuditPaths:  []string{"audit.jsonl"},
		Scraper:     scraper,
		Calibrate: func(context.Context) (string, error) {
			return `{"examples":42}`, nil
		},
		CaidoPush: func(_ context.Context, findings []json.RawMessage, url, pat string) (int, error) {
			caido.findings = len(findings)
			caido.url = url
			caido.pat = pat
			return len(findings), nil
		},
		Run: func(_ context.Context, req UIRunRequest) (UIRunResult, error) {
			lastRun = req
			return UIRunResult{Message: "probe completed", Probe: req.Probe, Target: req.Target, Success: true}, nil
		},
	}
	return opts, scraper, caido, &lastRun
}

func uiServer(t *testing.T, opts UIOptions) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	RegisterUI(mux, opts)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func uiPostJSON(t *testing.T, url string, body any) *http.Response {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func uiReadJSON(t *testing.T, resp *http.Response, dst any) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}

func TestUIIndexIsEmbedded(t *testing.T) {
	srv := uiServer(t, UIOptions{})
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / status = %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Fatalf("Content-Type = %q", got)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"<title>OmniSlash Control</title>", "/api/dashboard", "/api/run", "/api/caido/push"} {
		if !strings.Contains(string(body), marker) {
			t.Errorf("embedded page is missing %q", marker)
		}
	}
}

func TestUIAPIDashboardAndActions(t *testing.T) {
	opts, scraper, caido, lastRun := uiTestOptions(t)
	srv := uiServer(t, opts)

	resp, err := http.Get(srv.URL + "/api/dashboard")
	if err != nil {
		t.Fatal(err)
	}
	var dash UIDashboard
	uiReadJSON(t, resp, &dash)
	if dash.Brain.Examples == nil || *dash.Brain.Examples != 17 {
		t.Errorf("brain examples = %v, want 17", dash.Brain.Examples)
	}
	if dash.Brain.HoldoutAccuracy == nil || math.Abs(*dash.Brain.HoldoutAccuracy-0.93) > 1e-9 {
		t.Errorf("holdout accuracy = %v, want 0.93", dash.Brain.HoldoutAccuracy)
	}
	if dash.Vault.Keys != 1 || len(dash.Vault.TechStacks) != 1 || dash.Vault.TechStacks[0] != "h2" {
		t.Errorf("vault summary = %+v", dash.Vault)
	}
	if !dash.Scope.Enabled || len(dash.Scope.AllowHosts) != 1 || dash.Scope.AllowHosts[0] != "127.0.0.1" {
		t.Errorf("scope summary = %+v", dash.Scope)
	}
	if len(dash.Findings) != 1 {
		t.Fatalf("findings = %d, want 1 (confirmed only)", len(dash.Findings))
	}
	finding := dash.Findings[0]
	if finding.Kind != "smuggle_confirmed" || finding.Confidence != "high" {
		t.Errorf("finding = %+v", finding)
	}
	if finding.ConfidenceScore == nil || *finding.ConfidenceScore != 90 {
		t.Errorf("confidence score = %v, want 90", finding.ConfidenceScore)
	}
	if finding.NCD == nil || math.Abs(*finding.NCD-0.42) > 1e-9 {
		t.Errorf("ncd = %v, want 0.42", finding.NCD)
	}
	if !json.Valid(finding.Record) {
		t.Errorf("finding record is not valid JSON: %s", finding.Record)
	}
	wrapper, err := json.Marshal(map[string]any{"record": finding.Record})
	if err != nil {
		t.Fatal(err)
	}
	payload := uiFindingRecordPayload(wrapper)
	var compactRecord, compactPayload bytes.Buffer
	if err := json.Compact(&compactRecord, finding.Record); err != nil {
		t.Fatal(err)
	}
	if err := json.Compact(&compactPayload, payload); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(compactRecord.Bytes(), compactPayload.Bytes()) {
		t.Errorf("finding envelope was not unwrapped: %s", payload)
	}

	resp = uiPostJSON(t, srv.URL+"/api/scrape", map[string]any{})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/scrape status = %d", resp.StatusCode)
	}
	var scrape map[string]any
	uiReadJSON(t, resp, &scrape)
	if scraper.calls != 1 {
		t.Errorf("scraper calls = %d, want 1", scraper.calls)
	}

	resp = uiPostJSON(t, srv.URL+"/api/calibrate", map[string]any{})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/calibrate status = %d", resp.StatusCode)
	}
	var calibrate map[string]any
	uiReadJSON(t, resp, &calibrate)
	if calibrate["output"] != `{"examples":42}` {
		t.Errorf("calibrate output = %v", calibrate["output"])
	}

	resp = uiPostJSON(t, srv.URL+"/api/caido/push", map[string]any{
		"findings": []json.RawMessage{finding.Record},
		"url":      "http://127.0.0.1:8080/graphql",
		"pat":      "topsecret",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/caido/push status = %d", resp.StatusCode)
	}
	var pushed map[string]any
	uiReadJSON(t, resp, &pushed)
	if pushed["pushed"] != float64(1) || caido.findings != 1 || caido.pat != "topsecret" {
		t.Errorf("caido capture = %+v, response = %+v", caido, pushed)
	}

	resp = uiPostJSON(t, srv.URL+"/api/caido/push", map[string]any{
		"findings": []json.RawMessage{finding.Record},
		"url":      "http://example.com/graphql",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("non-local Caido URL status = %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()

	resp = uiPostJSON(t, srv.URL+"/api/run", map[string]any{
		"target": "127.0.0.1:80",
		"probe":  "adaptive",
		"path":   "/",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("in-scope POST /api/run status = %d", resp.StatusCode)
	}
	var run UIRunResult
	uiReadJSON(t, resp, &run)
	if !run.Success || lastRun.Target != "127.0.0.1:80" || lastRun.Probe != "adaptive" {
		t.Errorf("run result = %+v, request = %+v", run, *lastRun)
	}

	resp = uiPostJSON(t, srv.URL+"/api/run", map[string]any{
		"target": "127.0.0.2:80",
		"probe":  "adaptive",
		"path":   "/",
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("out-of-scope POST /api/run status = %d, want 403", resp.StatusCode)
	}
	var denied map[string]string
	uiReadJSON(t, resp, &denied)
	if !strings.Contains(denied["error"], "not in scope.allow_hosts") {
		t.Errorf("denial error = %q", denied["error"])
	}
	if lastRun.Target != "127.0.0.1:80" {
		t.Errorf("out-of-scope request reached the runner: %+v", *lastRun)
	}

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/scrape", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusMethodNotAllowed || resp.Header.Get("Allow") != http.MethodPost {
		t.Fatalf("GET /api/scrape status = %d, Allow = %q", resp.StatusCode, resp.Header.Get("Allow"))
	}
	resp.Body.Close()
}

func TestServeStatsKeepsLegacyRoutesWithUI(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Health.Enabled = false
	cfg.Audit.Enabled = false
	cfg.Gateway.Listen = ""
	proxy, err := NewProxy("http://127.0.0.1:18080", "http")
	if err != nil {
		t.Fatal(err)
	}
	pool, err := NewPool(&cfg, []*Proxy{proxy}, nil)
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	uiOpts := UIOptions{
		Status: func() any {
			return map[string]any{"jobs": []any{map[string]any{"name": "lab"}}}
		},
		Experience: func() any {
			return map[string]any{"enabled": true, "cells": []any{}}
		},
	}
	go func() { errCh <- ServeStats(ctx, addr, pool, nil, uiOpts) }()

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
		t.Fatalf("stats server never started: %v", lastErr)
	}

	for path, want := range map[string]string{
		"/healthz": "ok\n",
		"/readyz":  "ready\n",
	} {
		resp, err := http.Get(base + path)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK || string(body) != want {
			t.Errorf("GET %s = %d %q, want 200 %q", path, resp.StatusCode, body, want)
		}
	}
	resp, err := http.Get(base + "/stats")
	if err != nil {
		t.Fatal(err)
	}
	var stats Stats
	uiReadJSON(t, resp, &stats)
	if stats.Total != 1 {
		t.Errorf("stats total = %d, want 1", stats.Total)
	}
	resp, err = http.Get(base + "/status")
	if err != nil {
		t.Fatal(err)
	}
	var status struct {
		Jobs []struct {
			Name string `json:"name"`
		} `json:"jobs"`
	}
	uiReadJSON(t, resp, &status)
	if len(status.Jobs) != 1 || status.Jobs[0].Name != "lab" {
		t.Errorf("status jobs = %+v", status.Jobs)
	}
	resp, err = http.Get(base + "/experience")
	if err != nil {
		t.Fatal(err)
	}
	var experience struct {
		Enabled bool `json:"enabled"`
	}
	uiReadJSON(t, resp, &experience)
	if !experience.Enabled {
		t.Errorf("experience enabled = false, want true")
	}
	resp, err = http.Get(base + "/")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET / status = %d", resp.StatusCode)
	}
	resp.Body.Close()

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("ServeStats returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ServeStats did not shut down")
	}
}

func TestUIMissingRunCallbackIsNotSilentlySuccessful(t *testing.T) {
	srv := uiServer(t, UIOptions{})
	resp := uiPostJSON(t, srv.URL+"/api/run", map[string]any{
		"target": "127.0.0.1:80",
		"probe":  "adaptive",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("POST /api/run without callback status = %d, want 501", resp.StatusCode)
	}
	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body["error"], "not available") {
		t.Errorf("error = %q", body["error"])
	}
}

func TestUIWithEnvOverridesInheritedValues(t *testing.T) {
	got := uiWithEnv([]string{"A=old", "B=keep", "CAIDO_PAT=inherited"}, "A=new", "CAIDO_PAT=request")
	want := []string{"B=keep", "A=new", "CAIDO_PAT=request"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("env = %q, want %q", got, want)
	}
}

func TestUIDefaultCalibrateRunsNativeShellEntrypoint(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-calibrate.sh")
	body := "#!/bin/sh\nprintf 'WEIGHTS=%s\\n' \"$WEIGHTS\"\nprintf 'NATIVE_CORPUS=%s\\n' \"$NATIVE_CORPUS\"\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	o := UIOptions{
		WorkDir:         dir,
		WeightsPath:     "state/weights.json",
		CalibrateScript: "fake-calibrate.sh",
	}.withDefaults(nil)
	out, err := o.Calibrate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "WEIGHTS="+filepath.Join(dir, "state/weights.json")) {
		t.Errorf("calibration did not receive WEIGHTS: %q", out)
	}
	if !strings.Contains(out, "NATIVE_CORPUS="+filepath.Join(dir, "state/native_pair_corpus.jsonl")) {
		t.Errorf("calibration did not receive NATIVE_CORPUS: %q", out)
	}
}

func uiOnlineWait(t *testing.T, timeout time.Duration, condition func() bool, message string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", message)
}

func TestUIOnlineLearningToggleAndFeedback(t *testing.T) {
	opts, _, _, _ := uiTestOptions(t)
	// uiTestOptions uses an isolated WorkDir; point the feedback CLI at the
	// repository copy of the script so tests never need a repo checkout inside
	// a temp directory.
	feedbackScript, err := filepath.Abs(filepath.Join("research", "self_learning.py"))
	if err != nil {
		t.Fatal(err)
	}
	opts.OnlineOptions.FeedbackScriptPath = feedbackScript
	srv := uiServer(t, opts)
	control := filepath.Join(opts.WorkDir, "state", "online_loop_control.json")
	weightsFile := filepath.Join(opts.WorkDir, "state", "learned_weights.json")

	var dashboard struct {
		Online OnlineStatus `json:"online"`
	}
	resp, err := http.Get(srv.URL + "/api/dashboard")
	if err != nil {
		t.Fatal(err)
	}
	uiReadJSON(t, resp, &dashboard)
	if dashboard.Online.State != "PAUSED" || dashboard.Online.Available {
		t.Fatalf("missing status must be reported as unavailable/PAUSED: %+v", dashboard.Online)
	}

	resp = uiPostJSON(t, srv.URL+"/api/learning/toggle", map[string]any{"enabled": false})
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("toggle status = %d: %s", resp.StatusCode, body)
	}
	resp.Body.Close()
	controlData, err := os.ReadFile(control)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(controlData), `"enabled": false`) {
		t.Fatalf("control file did not pause the loop: %s", controlData)
	}
	if err := os.WriteFile(filepath.Join(opts.WorkDir, "state", "online_status.json"),
		[]byte(`{"state":"ACTIVE","active":true,"processed":9}`), 0o644); err != nil {
		t.Fatal(err)
	}
	resp, err = http.Get(srv.URL + "/api/learning/status")
	if err != nil {
		t.Fatal(err)
	}
	var status OnlineStatus
	uiReadJSON(t, resp, &status)
	if status.State != "PAUSED" || status.Active || status.Processed != 9 {
		t.Fatalf("control file must override stale status: %+v", status)
	}

	resp = uiPostJSON(t, srv.URL+"/api/learning/toggle", map[string]any{"enabled": true})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("resume status = %d", resp.StatusCode)
	}
	resp.Body.Close()

	for _, tc := range []struct {
		kind     string
		path     string
		wantSucc float64
	}{
		{kind: "confirm", path: "/ui-confirm", wantSucc: 2},
		{kind: "false-positive", path: "/ui-false-positive", wantSucc: 0},
	} {
		resp = uiPostJSON(t, srv.URL+"/api/learning/feedback", UIFeedbackRequest{
			Kind: tc.kind, Host: "ui-host", Tech: "h2", Path: tc.path, Weight: 2,
		})
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("feedback %s status = %d: %s", tc.kind, resp.StatusCode, body)
		}
		var result UIFeedbackResult
		uiReadJSON(t, resp, &result)
		if !result.Applied || result.ScoreDelta == 0 {
			t.Fatalf("feedback %s did not change ranking: %+v", tc.kind, result)
		}
		data, err := os.ReadFile(weightsFile)
		if err != nil {
			t.Fatal(err)
		}
		var weights struct {
			Global map[string]struct {
				Attempts  int     `json:"attempts"`
				Successes float64 `json:"successes"`
			} `json:"global"`
		}
		if err := json.Unmarshal(data, &weights); err != nil {
			t.Fatal(err)
		}
		cell := weights.Global["path:"+tc.path]
		if cell.Attempts != 2 || cell.Successes != tc.wantSucc {
			t.Fatalf("feedback %s cell = %+v", tc.kind, cell)
		}
	}
}

func TestUIOnlineAuditEventReranksWithoutProcessRestart(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 is required for the streaming loop test")
	}
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	if err := os.MkdirAll(state, 0o755); err != nil {
		t.Fatal(err)
	}
	audit := filepath.Join(dir, "audit.jsonl")
	weights := filepath.Join(state, "learned_weights.json")
	jobs := filepath.Join(state, "jobs_online.json")
	offset := filepath.Join(state, "online_loop_offset.json")
	status := filepath.Join(state, "online_status.json")
	control := filepath.Join(state, "online_loop_control.json")
	initial := `{"schema":"omnislash.learned-weights/v1","examples":1,"global":{"cl:9":{"attempts":1,"successes":1,"ema":1,"sources":["online-audit"]}},"hosts":{},"tech":{},"holdout":{"hosts":[]}}`
	if err := os.WriteFile(weights, []byte(initial), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(audit, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	args := []string{
		"research/online_loop.py",
		"--audit", audit,
		"--weights", weights,
		"--jobs", jobs,
		"--offset", offset,
		"--status", status,
		"--control", control,
		"--interval", "0.05",
	}
	cmd := exec.CommandContext(ctx, "python3", args...)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		// Cancel before Wait, otherwise a test failure can leave Wait blocked.
		cancel()
		_ = cmd.Wait()
	}()

	opts := UIOptions{
		WorkDir:     dir,
		WeightsPath: "state/learned_weights.json",
		OnlineOptions: OnlineLoopOptions{
			WorkDir: dir, AuditPath: audit, WeightsPath: weights, JobsPath: jobs,
			OffsetPath: offset, StatusPath: status, ControlPath: control,
		},
	}
	srv := uiServer(t, opts)
	var dashboard struct {
		Online OnlineStatus `json:"online"`
	}
	uiOnlineWait(t, 5*time.Second, func() bool {
		resp, err := http.Get(srv.URL + "/api/dashboard")
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		if err := json.NewDecoder(resp.Body).Decode(&dashboard); err != nil {
			return false
		}
		return dashboard.Online.State == "ACTIVE"
	}, "ACTIVE stream status")

	line := `{"time":"2026-11-25T13:00:00Z","job":"live","attempt":1,"target":"127.0.0.1:8443","probe":"h2-cl","tls":"h2","learning":{"host":"live-host","tech_stack":"h2"},"declared_length":9,"result":{"exchanges":[{"raw":"GET /ui-live-negative HTTP/1.1\r\nContent-Length: 9\r\n\r\n"}],"responses":[{"status":400,"body":"Invalid request"}]}}` + "\n"
	if err := os.WriteFile(audit, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	// Rewriting the audit changed its inode; the worker replay resets to zero.
	uiOnlineWait(t, 10*time.Second, func() bool {
		data, err := os.ReadFile(weights)
		if err != nil {
			return false
		}
		var w struct {
			Global map[string]struct {
				Attempts  int     `json:"attempts"`
				Successes float64 `json:"successes"`
				EMA       float64 `json:"ema"`
			} `json:"global"`
		}
		if err := json.Unmarshal(data, &w); err != nil {
			return false
		}
		cell := w.Global["path:/ui-live-negative"]
		return cell.Attempts == 1 && cell.Successes == 0 && 0.5*cell.EMA < 0.5
	}, "weights update from appended audit event")

	var after struct {
		Online OnlineStatus `json:"online"`
	}
	uiOnlineWait(t, 5*time.Second, func() bool {
		resp, err := http.Get(srv.URL + "/api/dashboard")
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		if err := json.NewDecoder(resp.Body).Decode(&after); err != nil {
			return false
		}
		return after.Online.Processed >= 1
	}, "dashboard streamed episode counter")

	resp := uiPostJSON(t, srv.URL+"/api/learning/toggle", map[string]any{"enabled": false})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("toggle status = %d", resp.StatusCode)
	}
	resp.Body.Close()
	uiOnlineWait(t, 5*time.Second, func() bool {
		payload, err := os.ReadFile(status)
		if err != nil {
			return false
		}
		return strings.Contains(string(payload), `"state": "PAUSED"`)
	}, "paused stream status")
}

func TestUIPoolSummaryCountsTiersWithoutChangingStatsSchema(t *testing.T) {
	cfg := DefaultConfig()
	proxy, err := NewProxy("http://127.0.0.1:18081", "http")
	if err != nil {
		t.Fatal(err)
	}
	pool, err := NewPool(&cfg, []*Proxy{proxy}, nil)
	if err != nil {
		t.Fatal(err)
	}
	summary := uiPoolSummary(pool)
	if summary.Sniper+summary.Infantry != 1 {
		t.Fatalf("tier counts = %+v", summary)
	}
	stats := pool.Stats()
	if _, err := json.Marshal(stats); err != nil {
		t.Fatal(fmt.Errorf("stats must stay JSON-serializable: %w", err))
	}
}
