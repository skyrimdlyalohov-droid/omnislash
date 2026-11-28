package omnislash

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/skyrimdlyalohov-droid/omnislash/web"
)

// UIOptions configures the embedded dashboard. All callbacks are optional:
// missing actions are reported honestly instead of pretending to have run.
type UIOptions struct {
	// Pool, Config and Scope are normally derived from the running transport.
	Pool   *Pool
	Config *Config
	Scope  *Scope

	// ConfigPath is the transport config file, used for dashboard provenance.
	ConfigPath string
	// WorkDir is the base directory for the relative state/script paths below.
	WorkDir string

	WeightsPath     string
	VaultPath       string
	CalibrateScript string
	CaidoBridgePath string
	TrainAuditGlob  string
	AuditPaths      []string
	Scraper         UIScraper
	Calibrate       func(context.Context) (string, error)
	CaidoPush       func(context.Context, []json.RawMessage, string, string) (int, error)
	Run             func(context.Context, UIRunRequest) (UIRunResult, error)
	Status          func() any
	Experience      func() any

	// OnlineOptions names the files shared with research/online_loop.py.
	// Zero values fall back to WorkDir-relative defaults.
	OnlineOptions OnlineLoopOptions
	// OnlineStatus, OnlineToggle and OnlineFeedback may be supplied by the
	// daemon so the dashboard reports the loop it actually started.
	OnlineStatus   func() any
	OnlineToggle   func(context.Context, bool) (any, error)
	OnlineFeedback func(context.Context, UIFeedbackRequest) (any, error)
}

// UIScraper is the part of *Scraper needed by the Refresh pool action.
type UIScraper interface {
	Refresh(context.Context) (ScraperStats, error)
}

// UIRunRequest is a scope-checked Quick Run request. Target is the literal
// address the executor must dial; it has already passed Scope.CheckTarget.
type UIRunRequest struct {
	Target   string `json:"target"`
	Original string `json:"original,omitempty"`
	Probe    string `json:"probe"`
	Path     string `json:"path"`
}

// UIRunResult is the compact outcome shown in the Quick Run panel.
type UIRunResult struct {
	Message  string   `json:"message"`
	Job      string   `json:"job,omitempty"`
	Probe    string   `json:"probe"`
	Target   string   `json:"target"`
	Success  bool     `json:"success"`
	Findings []string `json:"findings,omitempty"`
	Statuses []int    `json:"statuses,omitempty"`
	Error    string   `json:"error,omitempty"`
}

type UIPool struct {
	Sniper   int     `json:"sniper"`
	Infantry int     `json:"infantry"`
	Cooldown int     `json:"cooldown"`
	AvgIQRMS float64 `json:"avg_iqr"`
}

type UIBrain struct {
	HoldoutAccuracy *float64 `json:"holdout_accuracy"`
	Examples        *int     `json:"examples"`
}

type UIVault struct {
	TechStacks []string `json:"tech_stacks"`
	Keys       int      `json:"keys"`
}

type UIScope struct {
	Enabled    bool     `json:"enabled"`
	AllowHosts []string `json:"allow_hosts"`
	AllowPorts []int    `json:"allow_ports"`
}

type UIFinding struct {
	Time            string          `json:"time,omitempty"`
	Host            string          `json:"host,omitempty"`
	Job             string          `json:"job,omitempty"`
	Kind            string          `json:"kind"`
	Confidence      string          `json:"confidence,omitempty"`
	ConfidenceScore *int            `json:"confidence_score,omitempty"`
	NCD             *float64        `json:"ncd,omitempty"`
	Detail          string          `json:"detail,omitempty"`
	Record          json.RawMessage `json:"record,omitempty"`
}

type UIDashboard struct {
	Pool       UIPool      `json:"pool"`
	Brain      UIBrain     `json:"brain"`
	Vault      UIVault     `json:"vault"`
	Scope      UIScope     `json:"scope"`
	Findings   []UIFinding `json:"findings"`
	Status     any         `json:"status,omitempty"`
	Experience any         `json:"experience,omitempty"`
	Online     any         `json:"online,omitempty"`
}

// RegisterUI installs the embedded dashboard and its action API on mux. The
// legacy JSON routes must be registered by the caller before this function.
func RegisterUI(mux *http.ServeMux, opts UIOptions) {
	if mux == nil {
		return
	}
	o := opts.withDefaults(nil)

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if !uiRequireMethod(w, r, http.MethodGet) {
			return
		}
		page, err := web.FS.ReadFile("index.html")
		if err != nil {
			uiError(w, http.StatusInternalServerError, fmt.Errorf("embedded dashboard: %w", err))
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write(page)
	})

	mux.HandleFunc("/api/dashboard", func(w http.ResponseWriter, r *http.Request) {
		if !uiRequireMethod(w, r, http.MethodGet) {
			return
		}
		uiJSON(w, http.StatusOK, o.dashboard(r.Context()))
	})

	mux.HandleFunc("/api/scrape", func(w http.ResponseWriter, r *http.Request) {
		if !uiRequireMethod(w, r, http.MethodPost) {
			return
		}
		if o.Scraper == nil {
			uiError(w, http.StatusNotImplemented, errors.New("proxy scraper is disabled on this control server"))
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
		defer cancel()
		stats, err := o.Scraper.Refresh(ctx)
		if err != nil {
			uiError(w, http.StatusBadGateway, err)
			return
		}
		uiJSON(w, http.StatusOK, map[string]any{
			"message": "proxy pool refreshed",
			"scraper": stats,
		})
	})

	mux.HandleFunc("/api/calibrate", func(w http.ResponseWriter, r *http.Request) {
		if !uiRequireMethod(w, r, http.MethodPost) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
		defer cancel()
		out, err := o.Calibrate(ctx)
		if err != nil {
			uiError(w, http.StatusBadGateway, err)
			return
		}
		uiJSON(w, http.StatusOK, map[string]any{"message": "calibration finished", "output": out})
	})

	type caidoRequest struct {
		Findings []json.RawMessage `json:"findings"`
		URL      string            `json:"url"`
		PAT      string            `json:"pat"`
	}
	mux.HandleFunc("/api/caido/push", func(w http.ResponseWriter, r *http.Request) {
		if !uiRequireMethod(w, r, http.MethodPost) {
			return
		}
		var req caidoRequest
		if !uiDecode(w, r, &req) {
			return
		}
		if len(req.Findings) == 0 {
			uiError(w, http.StatusBadRequest, errors.New("select at least one confirmed finding"))
			return
		}
		if len(req.PAT) > 8192 || strings.ContainsRune(req.PAT, 0) {
			uiError(w, http.StatusBadRequest, errors.New("PAT is too long or contains a NUL byte"))
			return
		}
		target, err := uiValidateCaidoURL(req.URL)
		if err != nil {
			uiError(w, http.StatusBadRequest, err)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
		defer cancel()
		pushed, err := o.CaidoPush(ctx, req.Findings, target, req.PAT)
		if err != nil {
			uiError(w, http.StatusBadGateway, err)
			return
		}
		uiJSON(w, http.StatusOK, map[string]any{
			"message": "Caido Replay updated",
			"pushed":  pushed,
		})
	})

	type runRequest struct {
		Target string `json:"target"`
		Probe  string `json:"probe"`
		Path   string `json:"path"`
	}
	mux.HandleFunc("/api/run", func(w http.ResponseWriter, r *http.Request) {
		if !uiRequireMethod(w, r, http.MethodPost) {
			return
		}
		if o.Run == nil {
			uiError(w, http.StatusNotImplemented, errors.New("quick run is not available on this control server"))
			return
		}
		var req runRequest
		if !uiDecode(w, r, &req) {
			return
		}
		run, err := uiCheckedRunRequest(r.Context(), o, req.Target, req.Probe, req.Path)
		if err != nil {
			uiError(w, http.StatusForbidden, err)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
		defer cancel()
		result, err := o.Run(ctx, run)
		if err != nil {
			uiError(w, http.StatusBadGateway, err)
			return
		}
		uiJSON(w, http.StatusOK, result)
	})

	mux.HandleFunc("/api/learning/status", func(w http.ResponseWriter, r *http.Request) {
		if !uiRequireMethod(w, r, http.MethodGet) {
			return
		}
		if o.OnlineStatus == nil {
			uiError(w, http.StatusNotImplemented, errors.New("online learning status is unavailable on this control server"))
			return
		}
		uiJSON(w, http.StatusOK, o.OnlineStatus())
	})

	mux.HandleFunc("/api/learning/toggle", func(w http.ResponseWriter, r *http.Request) {
		if !uiRequireMethod(w, r, http.MethodPost) {
			return
		}
		if o.OnlineToggle == nil {
			uiError(w, http.StatusNotImplemented, errors.New("online learning toggle is unavailable on this control server"))
			return
		}
		var req struct {
			Enabled *bool `json:"enabled"`
		}
		if !uiDecode(w, r, &req) {
			return
		}
		var enabled bool
		if req.Enabled != nil {
			enabled = *req.Enabled
		} else {
			// Bare POST toggles the current state; the worker owns the durable
			// control file, so this stays correct across process restarts.
			enabled = !uiOnlineEnabled(o)
		}
		result, err := o.OnlineToggle(r.Context(), enabled)
		if err != nil {
			uiError(w, http.StatusBadGateway, err)
			return
		}
		uiJSON(w, http.StatusOK, result)
	})

	mux.HandleFunc("/api/learning/feedback", func(w http.ResponseWriter, r *http.Request) {
		if !uiRequireMethod(w, r, http.MethodPost) {
			return
		}
		if o.OnlineFeedback == nil {
			uiError(w, http.StatusNotImplemented, errors.New("online feedback is unavailable on this control server"))
			return
		}
		var req UIFeedbackRequest
		if !uiDecode(w, r, &req) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		result, err := o.OnlineFeedback(ctx, req)
		if err != nil {
			uiError(w, http.StatusBadGateway, err)
			return
		}
		uiJSON(w, http.StatusOK, result)
	})
}

func uiOnlineEnabled(o UIOptions) bool {
	if o.OnlineStatus == nil {
		return false
	}
	snapshot, ok := o.OnlineStatus().(OnlineStatus)
	return ok && snapshot.State == "ACTIVE" && snapshot.Active
}

func (o UIOptions) withDefaults(pool *Pool) UIOptions {
	if o.Pool == nil {
		o.Pool = pool
	}
	if o.Config == nil && o.Pool != nil {
		cfg := o.Pool.Config()
		o.Config = &cfg
	}
	if o.Scope == nil && o.Pool != nil {
		o.Scope = o.Pool.Scope()
	}
	if o.WorkDir == "" {
		o.WorkDir = "."
	}
	if o.WeightsPath == "" {
		o.WeightsPath = "state/learned_weights.json"
	}
	if o.VaultPath == "" {
		o.VaultPath = "state/zero_day_vault.json"
	}
	if o.CalibrateScript == "" {
		o.CalibrateScript = "lab/calibrate-brain.sh"
	}
	if o.CaidoBridgePath == "" {
		o.CaidoBridgePath = "osint/caido_bridge.py"
	}
	if o.TrainAuditGlob == "" {
		o.TrainAuditGlob = "runs/*/daemon-*.jsonl"
	}
	if len(o.AuditPaths) == 0 && o.Config != nil && o.Config.Audit.Path != "" && o.Config.Audit.Path != "-" {
		o.AuditPaths = []string{o.Config.Audit.Path}
	}
	if o.Calibrate == nil {
		o.Calibrate = uiDefaultCalibrate(o)
	}
	if o.CaidoPush == nil {
		o.CaidoPush = uiDefaultCaidoPush(o)
	}
	o.OnlineOptions = uiOnlineOptions(o)
	if o.OnlineStatus == nil {
		opts := o.OnlineOptions
		o.OnlineStatus = func() any { return OnlineSnapshot(opts, nil) }
	}
	if o.OnlineToggle == nil {
		opts := o.OnlineOptions
		o.OnlineToggle = func(_ context.Context, enabled bool) (any, error) {
			if err := ToggleOnline(opts, enabled); err != nil {
				return nil, err
			}
			return map[string]any{
				"enabled": enabled,
				"message": map[bool]string{true: "online feedback loop resumed", false: "online feedback loop paused"}[enabled],
			}, nil
		}
	}
	if o.OnlineFeedback == nil {
		opts := o.OnlineOptions
		o.OnlineFeedback = func(ctx context.Context, req UIFeedbackRequest) (any, error) {
			return ApplyOnlineFeedback(ctx, opts, req)
		}
	}
	return o
}

// uiOnlineOptions fills only the fields the caller left empty, so the daemon
// can point the UI at its own state directory without restating every default.
func uiOnlineOptions(o UIOptions) OnlineLoopOptions {
	base := DefaultOnlineLoopOptions(o.WorkDir)
	custom := o.OnlineOptions
	if custom.WorkDir == "" {
		custom.WorkDir = base.WorkDir
	}
	if custom.WeightsPath == "" {
		custom.WeightsPath = o.WeightsPath
	}
	if custom.JobsPath == "" {
		custom.JobsPath = base.JobsPath
	}
	if custom.OffsetPath == "" {
		custom.OffsetPath = base.OffsetPath
	}
	if custom.StatusPath == "" {
		custom.StatusPath = base.StatusPath
	}
	if custom.ControlPath == "" {
		custom.ControlPath = base.ControlPath
	}
	if custom.ScriptPath == "" {
		custom.ScriptPath = base.ScriptPath
	}
	if custom.FeedbackScriptPath == "" {
		custom.FeedbackScriptPath = base.FeedbackScriptPath
	}
	if custom.Python == "" {
		custom.Python = base.Python
	}
	if custom.Interval <= 0 {
		custom.Interval = base.Interval
	}
	return custom
}

func (o UIOptions) dashboard(ctx context.Context) UIDashboard {
	_ = ctx
	d := UIDashboard{
		Pool:     uiPoolSummary(o.Pool),
		Brain:    uiBrainSummary(o),
		Vault:    uiVaultSummary(o),
		Scope:    uiScopeSummary(o),
		Findings: uiAuditFindings(o),
	}
	if o.Status != nil {
		d.Status = o.Status()
	}
	if o.Experience != nil {
		d.Experience = o.Experience()
	}
	if o.OnlineStatus != nil {
		d.Online = o.OnlineStatus()
	}
	return d
}

func uiPoolSummary(pool *Pool) UIPool {
	var out UIPool
	if pool == nil {
		return out
	}
	stats := pool.Stats()
	out.Sniper = pool.SniperCount()
	out.Infantry = pool.InfantryCount()
	out.Cooldown = stats.InCooldown
	var sum float64
	var n int
	for _, pr := range pool.Proxies() {
		if pr == nil {
			continue
		}
		if iqr := pr.IQR(); iqr > 0 {
			sum += float64(iqr.Microseconds()) / 1000
			n++
		}
	}
	if n > 0 {
		out.AvgIQRMS = math.Round(sum/float64(n)*1000) / 1000
	}
	return out
}

func uiBrainSummary(o UIOptions) UIBrain {
	var out UIBrain
	data, err := os.ReadFile(uiResolve(o.WorkDir, o.WeightsPath))
	if err != nil {
		return out
	}
	var weights struct {
		Examples *int `json:"examples"`
		Holdout  struct {
			Metrics struct {
				Accuracy *float64 `json:"accuracy"`
			} `json:"metrics"`
		} `json:"holdout"`
	}
	if err := json.Unmarshal(data, &weights); err != nil {
		return out
	}
	out.HoldoutAccuracy = weights.Holdout.Metrics.Accuracy
	out.Examples = weights.Examples
	return out
}

func uiVaultSummary(o UIOptions) UIVault {
	out := UIVault{TechStacks: []string{}}
	data, err := os.ReadFile(uiResolve(o.WorkDir, o.VaultPath))
	if err != nil {
		return out
	}
	var vault struct {
		Keys []struct {
			TechStackHash string   `json:"tech_stack_hash"`
			TechStack     []string `json:"tech_stack"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(data, &vault); err != nil {
		return out
	}
	out.Keys = len(vault.Keys)
	seen := make(map[string]struct{})
	for _, key := range vault.Keys {
		name := key.TechStackHash
		if name == "" {
			name = strings.Join(key.TechStack, ",")
		}
		if name != "" {
			seen[name] = struct{}{}
		}
	}
	for name := range seen {
		out.TechStacks = append(out.TechStacks, name)
	}
	sort.Strings(out.TechStacks)
	return out
}

func uiScopeSummary(o UIOptions) UIScope {
	out := UIScope{AllowHosts: []string{}, AllowPorts: []int{}}
	if o.Config == nil {
		return out
	}
	out.Enabled = o.Config.Scope.Enabled
	out.AllowHosts = append(out.AllowHosts, o.Config.Scope.AllowHosts...)
	out.AllowPorts = append(out.AllowPorts, o.Config.Scope.AllowPorts...)
	return out
}

type uiFindingRecord struct {
	Kind       string `json:"kind"`
	Confidence string `json:"confidence"`
	Detail     string `json:"detail"`
	Response   int    `json:"response_seq"`
}

type uiAuditRecord struct {
	Time     string            `json:"time"`
	Job      string            `json:"job"`
	Target   string            `json:"target"`
	Probe    string            `json:"probe"`
	TLS      string            `json:"tls"`
	Success  bool              `json:"success"`
	Findings []uiFindingRecord `json:"findings"`
	Result   *struct {
		Responses []struct {
			Seq int    `json:"seq"`
			Raw string `json:"raw"`
		} `json:"responses"`
	} `json:"result"`
}

var ncdPattern = regexp.MustCompile(`(?i)ncd[=:]\s*([0-9]*\.?[0-9]+)`)

func uiAuditFindings(o UIOptions) []UIFinding {
	out := make([]UIFinding, 0, 64)
	for _, path := range o.AuditPaths {
		if path == "" || path == "-" {
			continue
		}
		f, err := os.Open(uiResolve(o.WorkDir, path))
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 64*1024), 4<<20)
		for scanner.Scan() {
			line := bytes.TrimSpace(scanner.Bytes())
			if len(line) == 0 {
				continue
			}
			var rec uiAuditRecord
			if err := json.Unmarshal(line, &rec); err != nil || !rec.Success {
				continue
			}
			for _, finding := range rec.Findings {
				if !uiConfirmedKind(finding.Kind) || uiUnverified(finding.Detail) {
					continue
				}
				lineCopy := append(json.RawMessage(nil), line...)
				entry := UIFinding{
					Time:            rec.Time,
					Host:            uiTargetHost(rec.Target),
					Job:             rec.Job,
					Kind:            finding.Kind,
					Confidence:      finding.Confidence,
					ConfidenceScore: uiConfidenceScore(finding.Confidence),
					NCD:             uiNCD(rec, finding),
					Detail:          finding.Detail,
					Record:          lineCopy,
				}
				out = append(out, entry)
			}
		}
		_ = f.Close()
	}
	if len(out) > 500 {
		out = append([]UIFinding(nil), out[len(out)-500:]...)
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

var uiConfirmedKinds = map[string]bool{
	"smuggle_confirmed": true,
	"cache_poisoned":    true,
	// Gadget discovery: a crypto canary echoed in Location/body or retained on
	// a clean control GET is a confirmed unkeyed/cache gadget.
	"gadget_reflected":         true,
	"unkeyed_header":           true,
	"h2_tunnel_confirmed":      true,
	"race_confirmed":           true,
	"desync_confirmed":         true,
	"universal_key_confirmed":  true,
	"upgrade_desync_confirmed": true,
	"neighbor_shift":           true,
}

func uiConfirmedKind(kind string) bool {
	return uiConfirmedKinds[strings.ToLower(strings.TrimSpace(kind))]
}

func uiUnverified(detail string) bool {
	d := strings.ToLower(detail)
	return strings.Contains(d, "unverified") || strings.Contains(d, "verified=false") || strings.Contains(d, "verified: false")
}

func uiConfidenceScore(level string) *int {
	var score int
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "high":
		score = 90
	case "medium":
		score = 70
	case "low":
		score = 40
	default:
		return nil
	}
	return &score
}

func uiNCD(rec uiAuditRecord, finding uiFindingRecord) *float64 {
	if match := ncdPattern.FindStringSubmatch(finding.Detail); len(match) == 2 {
		if value, err := strconv.ParseFloat(match[1], 64); err == nil {
			rounded := math.Round(value*1000) / 1000
			return &rounded
		}
	}
	if rec.Result == nil || len(rec.Result.Responses) < 2 {
		return nil
	}
	baseline := rec.Result.Responses[0].Raw
	sample := rec.Result.Responses[1].Raw
	if finding.Response > 0 {
		for _, response := range rec.Result.Responses {
			if response.Seq == finding.Response {
				sample = response.Raw
				break
			}
		}
	}
	if baseline == "" || sample == "" {
		return nil
	}
	value := math.Round(NormalizedCompressionDistance([]byte(baseline), []byte(sample))*1000) / 1000
	return &value
}

func uiTargetHost(target string) string {
	if host, _, err := net.SplitHostPort(target); err == nil {
		return uiNormalizeHost(host)
	}
	return uiNormalizeHost(target)
}

func uiNormalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.Trim(host, "[]")
	return strings.TrimSuffix(host, ".")
}

func uiNormalizeTarget(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("target is required")
	}
	if _, _, err := net.SplitHostPort(raw); err == nil {
		return raw, nil
	}
	if u, err := url.Parse(raw); err == nil && u.Host != "" && (u.Scheme == "http" || u.Scheme == "https") {
		raw = u.Host
		if _, _, err := net.SplitHostPort(raw); err == nil {
			return raw, nil
		}
	}
	host := strings.Trim(raw, "[]")
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return "[" + host + "]:80", nil
	}
	return raw + ":80", nil
}

func uiHostInAllowList(host string, rules []string) bool {
	host = uiNormalizeHost(host)
	if host == "" {
		return false
	}
	for _, rule := range rules {
		rule = uiNormalizeHost(rule)
		if rule == "" {
			continue
		}
		if rule == host {
			return true
		}
		if strings.HasPrefix(rule, "*.") && strings.HasSuffix(host, rule[1:]) {
			return true
		}
	}
	return false
}

func uiCheckedRunRequest(ctx context.Context, o UIOptions, target, probe, path string) (UIRunRequest, error) {
	if o.Scope == nil || !o.Scope.Enabled() {
		return UIRunRequest{}, errors.New("scope is disabled: quick run is denied (fail-closed)")
	}
	if o.Config == nil || len(o.Config.Scope.AllowHosts) == 0 {
		return UIRunRequest{}, errors.New("scope.allow_hosts is empty: quick run is denied (fail-closed)")
	}
	checkedTarget, err := uiNormalizeTarget(target)
	if err != nil {
		return UIRunRequest{}, err
	}
	host := uiTargetHost(checkedTarget)
	if !uiHostInAllowList(host, o.Config.Scope.AllowHosts) {
		return UIRunRequest{}, fmt.Errorf("target host %q is not in scope.allow_hosts", host)
	}
	resolved, err := o.Scope.CheckTarget(ctx, checkedTarget)
	if err != nil {
		return UIRunRequest{}, err
	}
	probe = strings.ToLower(strings.TrimSpace(probe))
	if probe == "" {
		probe = "adaptive"
	}
	switch probe {
	case "adaptive", "h2-cl", "smuggle-chain", "raw-replay":
	default:
		return UIRunRequest{}, fmt.Errorf("unsupported quick-run probe %q", probe)
	}
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") || len(path) > 512 || strings.ContainsAny(path, "\r\n\t") {
		return UIRunRequest{}, errors.New("path must start with / and contain no control characters")
	}
	return UIRunRequest{
		Target:   resolved,
		Original: strings.TrimSpace(target),
		Probe:    probe,
		Path:     path,
	}, nil
}

func uiValidateCaidoURL(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		raw = "http://127.0.0.1:8080/graphql"
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid Caido URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errors.New("caido URL must use http or https")
	}
	if u.User != nil {
		return "", errors.New("caido URL must not contain credentials")
	}
	host := strings.ToLower(u.Hostname())
	allowed := map[string]bool{"localhost": true, "127.0.0.1": true, "::1": true}
	for _, extra := range strings.Split(os.Getenv("OMNISLASH_CAIDO_HOSTS"), ",") {
		if h := uiNormalizeHost(extra); h != "" {
			allowed[h] = true
		}
	}
	if !allowed[host] {
		return "", fmt.Errorf("caido host %q is not allowed (set OMNISLASH_CAIDO_HOSTS to override)", host)
	}
	return u.String(), nil
}

// CaidoPushURL validates the Caido endpoint used by both the dashboard's
// /api/caido/push handler and the daemon's automatic finding export. Empty
// input selects the local bridge at 127.0.0.1:8080.
func CaidoPushURL(raw string) (string, error) { return uiValidateCaidoURL(raw) }

func uiDefaultCaidoPush(o UIOptions) func(context.Context, []json.RawMessage, string, string) (int, error) {
	return func(ctx context.Context, findings []json.RawMessage, target, pat string) (int, error) {
		script := uiResolve(o.WorkDir, o.CaidoBridgePath)
		if _, err := os.Stat(script); err != nil {
			return 0, fmt.Errorf("caido bridge unavailable: %w", err)
		}
		dir, err := os.MkdirTemp("", "omnislash-caido-")
		if err != nil {
			return 0, err
		}
		defer os.RemoveAll(dir)
		auditPath := filepath.Join(dir, "audit.jsonl")
		outPath := filepath.Join(dir, "report.json")
		records := 0
		f, err := os.OpenFile(auditPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return 0, err
		}
		for _, finding := range findings {
			line := uiTrimAuditRecord(uiFindingRecordPayload(finding))
			if len(line) == 0 || !uiIsConfirmedRecord(line) {
				continue
			}
			if _, err := f.Write(append(line, '\n')); err != nil {
				_ = f.Close()
				return 0, err
			}
			records++
		}
		if err := f.Close(); err != nil {
			return 0, err
		}
		if records == 0 {
			return 0, errors.New("no confirmed findings were selected")
		}
		args := []string{script, "--audit", auditPath, "--url", target, "--out", outPath}
		cmd := exec.CommandContext(ctx, "python3", args...)
		cmd.Dir = o.WorkDir
		cmd.Env = uiWithEnv(os.Environ(), "CAIDO_PAT="+pat)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return 0, fmt.Errorf("caido bridge failed: %w: %s", err, uiClip(string(out), 2000))
		}
		for _, line := range strings.Split(string(out), "\n") {
			var summary struct {
				OK        int `json:"ok"`
				Processed int `json:"processed"`
			}
			if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &summary); err == nil && (summary.OK > 0 || summary.Processed > 0) {
				return summary.OK, nil
			}
		}
		report, err := os.ReadFile(outPath)
		if err != nil {
			return 0, fmt.Errorf("caido bridge produced no report: %w", err)
		}
		var results []struct {
			OK bool `json:"ok"`
		}
		if err := json.Unmarshal(report, &results); err != nil {
			return 0, fmt.Errorf("caido bridge report is invalid: %w", err)
		}
		pushed := 0
		for _, result := range results {
			if result.OK {
				pushed++
			}
		}
		return pushed, nil
	}
}

// uiFindingRecordPayload accepts both a raw audit line and the dashboard's
// finding envelope, which embeds the original record for replay export.
func uiFindingRecordPayload(raw json.RawMessage) json.RawMessage {
	var wrapper struct {
		Record json.RawMessage `json:"record"`
	}
	if err := json.Unmarshal(raw, &wrapper); err == nil && len(wrapper.Record) > 0 && json.Valid(wrapper.Record) {
		return wrapper.Record
	}
	return raw
}

func uiIsConfirmedRecord(line []byte) bool {
	var rec struct {
		Success  bool              `json:"success"`
		Findings []uiFindingRecord `json:"findings"`
	}
	if err := json.Unmarshal(line, &rec); err != nil || !rec.Success {
		return false
	}
	for _, finding := range rec.Findings {
		if uiConfirmedKind(finding.Kind) && !uiUnverified(finding.Detail) {
			return true
		}
	}
	return false
}

func uiTrimAuditRecord(line []byte) []byte {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(line, &root); err != nil {
		return nil
	}
	rawResult, ok := root["result"]
	if !ok {
		return line
	}
	var result map[string]json.RawMessage
	if err := json.Unmarshal(rawResult, &result); err != nil {
		return line
	}
	rawResponses, ok := result["responses"]
	if !ok {
		return line
	}
	var responses []map[string]json.RawMessage
	if err := json.Unmarshal(rawResponses, &responses); err != nil {
		return line
	}
	for _, response := range responses {
		raw, ok := response["raw"]
		if !ok {
			continue
		}
		var body string
		if err := json.Unmarshal(raw, &body); err != nil {
			continue
		}
		if len(body) > 4000 {
			trimmed, err := json.Marshal(body[:4000])
			if err == nil {
				response["raw"] = trimmed
			}
		}
	}
	if encoded, err := json.Marshal(responses); err == nil {
		result["responses"] = encoded
	}
	if encoded, err := json.Marshal(result); err == nil {
		root["result"] = encoded
	}
	encoded, err := json.Marshal(root)
	if err != nil {
		return nil
	}
	return encoded
}

func uiDefaultCalibrate(o UIOptions) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		script := uiResolve(o.WorkDir, o.CalibrateScript)
		if _, err := os.Stat(script); err != nil {
			return "", fmt.Errorf("calibration script unavailable: %w", err)
		}
		weights := uiResolve(o.WorkDir, o.WeightsPath)

		// The shell entrypoint is the full native cycle (local Go/Python pairs,
		// WAF negatives and all runs/* audits). A .py override remains supported
		// for callers that deliberately want the bare learner.
		if strings.HasSuffix(strings.ToLower(script), ".sh") {
			cmd := exec.CommandContext(ctx, "bash", script)
			cmd.Dir = o.WorkDir
			cmd.Env = uiWithEnv(os.Environ(),
				"WEIGHTS="+weights,
				"NATIVE_CORPUS="+uiResolve(o.WorkDir, "state/native_pair_corpus.jsonl"),
			)
			out, err := cmd.CombinedOutput()
			if err != nil {
				return uiClip(string(out), 2000), fmt.Errorf("native calibration failed: %w", err)
			}
			return uiClip(string(out), 4000), nil
		}

		args := []string{
			script, "--weights", weights, "train",
			"--audit-glob", o.TrainAuditGlob,
			"--simulate",
			"--out", weights,
		}
		for _, path := range o.AuditPaths {
			if path != "" && path != "-" {
				args = append(args, "--audit", path)
			}
		}
		cmd := exec.CommandContext(ctx, "python3", args...)
		cmd.Dir = o.WorkDir
		out, err := cmd.CombinedOutput()
		if err != nil {
			return uiClip(string(out), 2000), fmt.Errorf("calibration failed: %w", err)
		}
		return uiClip(string(out), 4000), nil
	}
}

// uiWithEnv replaces existing values for the supplied KEY=value pairs so an
// inherited PAT or output path cannot shadow the one chosen by this request.
func uiWithEnv(base []string, overrides ...string) []string {
	keys := make(map[string]bool, len(overrides))
	for _, pair := range overrides {
		if i := strings.IndexByte(pair, '='); i > 0 {
			keys[pair[:i]] = true
		}
	}
	out := make([]string, 0, len(base)+len(overrides))
	for _, pair := range base {
		key := pair
		if i := strings.IndexByte(pair, '='); i > 0 {
			key = pair[:i]
		}
		if keys[key] {
			continue
		}
		out = append(out, pair)
	}
	return append(out, overrides...)
}

func uiResolve(workDir, path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(workDir, path)
}

func uiClip(s string, limit int) string {
	s = strings.TrimSpace(s)
	if len(s) > limit {
		return s[:limit] + "…"
	}
	return s
}

func uiRequireMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method == method {
		return true
	}
	w.Header().Set("Allow", method)
	uiError(w, http.StatusMethodNotAllowed, fmt.Errorf("method %s not allowed", r.Method))
	return false
}

func uiDecode(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(dst); err != nil {
		uiError(w, http.StatusBadRequest, fmt.Errorf("invalid JSON: %w", err))
		return false
	}
	return true
}

func uiJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(value)
}

func uiError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}
