package omnislash

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// OnlineStatus is the dashboard-facing view of the streaming feedback loop.
// Accuracy here is the EMA of freshly labeled attempts; holdout accuracy stays
// in the weights file's holdout.metrics block.
type OnlineStatus struct {
	Schema          string                `json:"schema,omitempty"`
	State           string                `json:"state"`
	Active          bool                  `json:"active"`
	Available       bool                  `json:"available"`
	Processed       int                   `json:"processed"`
	HoldoutSkipped  int                   `json:"holdout_skipped"`
	Accuracy        float64               `json:"accuracy"`
	AccuracyDelta   float64               `json:"accuracy_delta"`
	AccuracyHistory []OnlineAccuracyPoint `json:"accuracy_history,omitempty"`
	Examples        int                   `json:"examples"`
	Jobs            OnlineJobCounts       `json:"jobs"`
	Outcomes        map[string]int        `json:"outcomes,omitempty"`
	LastError       string                `json:"last_error,omitempty"`
	UpdatedAt       string                `json:"updated_at,omitempty"`
}

type OnlineAccuracyPoint struct {
	Time     string  `json:"time,omitempty"`
	Accuracy float64 `json:"accuracy"`
	Label    float64 `json:"label,omitempty"`
}

type OnlineJobCounts struct {
	Strike     int `json:"strike"`
	Candidates int `json:"candidates"`
}

// UIFeedbackRequest is one manual +/-2.0 label from the dashboard.
type UIFeedbackRequest struct {
	Kind     string            `json:"kind"` // confirm | false-positive
	Host     string            `json:"host,omitempty"`
	Tech     string            `json:"tech,omitempty"`
	CL       int               `json:"cl,omitempty"`
	Path     string            `json:"path,omitempty"`
	Finding  string            `json:"finding,omitempty"`
	Weight   float64           `json:"weight,omitempty"`
	Features map[string]string `json:"features,omitempty"`
}

// UIFeedbackResult is the compact reply from self_learning.py feedback.
type UIFeedbackResult struct {
	Weights     string  `json:"weights,omitempty"`
	Action      string  `json:"action,omitempty"`
	Applied     bool    `json:"applied"`
	Reason      string  `json:"reason,omitempty"`
	ScoreBefore float64 `json:"score_before,omitempty"`
	ScoreAfter  float64 `json:"score_after,omitempty"`
	ScoreDelta  float64 `json:"score_delta,omitempty"`
	Output      string  `json:"output,omitempty"`
}

// OnlineLoopOptions names every file owned by the streaming loop. Relative
// paths are resolved against WorkDir. ScriptPath is the streaming worker;
// FeedbackScriptPath is the CLI that applies manual labels to weights.
type OnlineLoopOptions struct {
	WorkDir            string
	AuditPath          string
	WeightsPath        string
	JobsPath           string
	OffsetPath         string
	StatusPath         string
	ControlPath        string
	ScriptPath         string
	FeedbackScriptPath string
	Python             string
	Interval           time.Duration
}

// DefaultOnlineLoopOptions returns the repository-relative state paths used by
// both omnislashd and omnislash serve.
func DefaultOnlineLoopOptions(workDir string) OnlineLoopOptions {
	return OnlineLoopOptions{
		WorkDir:            workDir,
		WeightsPath:        "state/learned_weights.json",
		JobsPath:           "state/jobs_online.json",
		OffsetPath:         "state/online_loop_offset.json",
		StatusPath:         "state/online_status.json",
		ControlPath:        "state/online_loop_control.json",
		ScriptPath:         "research/online_loop.py",
		FeedbackScriptPath: "research/self_learning.py",
		Python:             "python3",
		Interval:           250 * time.Millisecond,
	}
}

func (o OnlineLoopOptions) abs(path string) string {
	return uiResolve(o.WorkDir, path)
}

// OnlineProcess owns the child python loop. CommandContext kills it when the
// parent context is cancelled, so shutdown never depends on a polling timer.
type OnlineProcess struct {
	cmd  *exec.Cmd
	done chan struct{}
	opts OnlineLoopOptions
}

// StartOnlineLoop launches research/online_loop.py against the audit log. The
// loop itself starts at the persisted offset, so restarting the daemon does not
// replay old evidence.
func StartOnlineLoop(ctx context.Context, opts OnlineLoopOptions, logger *slog.Logger) (*OnlineProcess, error) {
	workDir := opts.WorkDir
	if workDir == "" {
		workDir = "."
	}
	opts.WorkDir = workDir
	if opts.WeightsPath == "" {
		opts.WeightsPath = "state/learned_weights.json"
	}
	if opts.JobsPath == "" {
		opts.JobsPath = "state/jobs_online.json"
	}
	if opts.OffsetPath == "" {
		opts.OffsetPath = "state/online_loop_offset.json"
	}
	if opts.StatusPath == "" {
		opts.StatusPath = "state/online_status.json"
	}
	if opts.ControlPath == "" {
		opts.ControlPath = "state/online_loop_control.json"
	}
	if opts.ScriptPath == "" {
		opts.ScriptPath = "research/online_loop.py"
	}
	if opts.Python == "" {
		opts.Python = "python3"
	}
	if opts.Interval <= 0 {
		opts.Interval = 250 * time.Millisecond
	}
	if opts.AuditPath == "" {
		return nil, fmt.Errorf("online loop: audit path is required")
	}

	args := []string{
		opts.abs(opts.ScriptPath),
		"--audit", opts.abs(opts.AuditPath),
		"--weights", opts.abs(opts.WeightsPath),
		"--jobs", opts.abs(opts.JobsPath),
		"--offset", opts.abs(opts.OffsetPath),
		"--status", opts.abs(opts.StatusPath),
		"--control", opts.abs(opts.ControlPath),
		"--interval", strconv.FormatFloat(opts.Interval.Seconds(), 'f', 3, 64),
	}
	cmd := exec.CommandContext(ctx, opts.Python, args...)
	cmd.Dir = workDir
	cmd.Env = uiWithEnv(os.Environ(), "PYTHONUNBUFFERED=1")
	sink := io.Writer(io.Discard)
	if logger != nil {
		sink = &onlineLogWriter{logger: logger}
	}
	cmd.Stdout = sink
	cmd.Stderr = sink
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("online loop: start python: %w", err)
	}
	p := &OnlineProcess{cmd: cmd, done: make(chan struct{}), opts: opts}
	go func() {
		err := cmd.Wait()
		if logger != nil && err != nil && ctx.Err() == nil {
			logger.Warn("online loop exited", "error", err)
		}
		close(p.done)
	}()
	if err := initialiseOnlineControl(p.opts.abs(p.opts.ControlPath)); err != nil && logger != nil {
		logger.Warn("online control initialise failed", "error", err)
	}
	return p, nil
}

// Done is closed when the python child exits.
func (p *OnlineProcess) Done() <-chan struct{} {
	if p == nil {
		return nil
	}
	return p.done
}

func (p *OnlineProcess) options() OnlineLoopOptions {
	if p == nil {
		return DefaultOnlineLoopOptions(".")
	}
	return p.opts
}

type onlineLogWriter struct{ logger *slog.Logger }

func (w *onlineLogWriter) Write(b []byte) (int, error) {
	if text := strings.TrimSpace(string(b)); text != "" {
		w.logger.Debug("online loop", "output", uiClip(text, 2000))
	}
	return len(b), nil
}

func initialiseOnlineControl(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	return atomicWriteJSON(path, map[string]any{
		"enabled":      true,
		"seq":          1,
		"requested_at": time.Now().UTC().Format(time.RFC3339),
	})
}

// ToggleOnline writes a monotonic control file; the python worker applies it on
// its next poll, so no signal handling or process restart is required.
func ToggleOnline(opts OnlineLoopOptions, enabled bool) error {
	path := opts.abs(opts.ControlPath)
	if path == "" {
		return fmt.Errorf("online control path is empty")
	}
	current, _ := readJSONFile(path)
	seq := 1
	if current != nil {
		if value, ok := current["seq"].(float64); ok {
			seq = int(value) + 1
		}
		if enabledValue, ok := current["enabled"].(bool); ok && enabledValue == enabled {
			// Still write a fresh seq so an observer can see the request.
			seq++
		}
	}
	return atomicWriteJSON(path, map[string]any{
		"enabled":      enabled,
		"seq":          seq,
		"requested_at": time.Now().UTC().Format(time.RFC3339),
	})
}

// OnlineSnapshot reads the status file published by the python worker. A stale
// status is marked inactive; a missing one is reported honestly as unavailable.
func OnlineSnapshot(opts OnlineLoopOptions, process *OnlineProcess) OnlineStatus {
	status := OnlineStatus{State: "PAUSED", Available: false}
	raw, err := readJSONFile(opts.abs(opts.StatusPath))
	if err == nil && raw != nil {
		status.Available = true
		if value, ok := raw["schema"].(string); ok {
			status.Schema = value
		}
		if value, ok := raw["state"].(string); ok {
			status.State = value
		}
		if value, ok := raw["active"].(bool); ok {
			status.Active = value
		}
		status.Processed = intField(raw, "processed")
		status.HoldoutSkipped = intField(raw, "holdout_skipped")
		status.Examples = intField(raw, "examples")
		status.Accuracy = floatField(raw, "accuracy")
		status.AccuracyDelta = floatField(raw, "accuracy_delta")
		if counts, ok := raw["outcomes"].(map[string]any); ok {
			status.Outcomes = make(map[string]int, len(counts))
			for name, value := range counts {
				status.Outcomes[name] = intField(map[string]any{name: value}, name)
			}
		}
		if value, ok := raw["last_error"].(string); ok {
			status.LastError = value
		}
		if value, ok := raw["updated_at"].(string); ok {
			status.UpdatedAt = value
		}
		if history, ok := raw["accuracy_history"].([]any); ok {
			for _, item := range history {
				point, ok := item.(map[string]any)
				if !ok {
					continue
				}
				entry := OnlineAccuracyPoint{
					Accuracy: floatField(point, "accuracy"),
					Label:    floatField(point, "label"),
				}
				if value, ok := point["time"].(string); ok {
					entry.Time = value
				}
				status.AccuracyHistory = append(status.AccuracyHistory, entry)
			}
		}
		if jobs, ok := raw["jobs"].(map[string]any); ok {
			status.Jobs = OnlineJobCounts{
				Strike:     intField(jobs, "strike"),
				Candidates: intField(jobs, "candidates"),
			}
		}
	}
	if control, err := readJSONFile(opts.abs(opts.ControlPath)); err == nil && control != nil {
		if enabled, ok := control["enabled"].(bool); ok && !enabled {
			status.State = "PAUSED"
			status.Active = false
		}
	}
	if process != nil {
		select {
		case <-process.Done():
			status.Active = false
			if status.State != "PAUSED" {
				status.State = "PAUSED"
			}
		default:
		}
	}
	if status.State == "" {
		status.State = "PAUSED"
	}
	return status
}

// ApplyOnlineFeedback calls self_learning.py feedback with a single label. It
// is used by the dashboard's Confirm / False Positive buttons.
func ApplyOnlineFeedback(ctx context.Context, opts OnlineLoopOptions, req UIFeedbackRequest) (UIFeedbackResult, error) {
	features := map[string]string{}
	for key, value := range req.Features {
		features[key] = value
	}
	if req.CL > 0 {
		features[fmt.Sprintf("cl:%d", req.CL)] = "1"
	}
	if req.Path != "" {
		features["path:"+req.Path] = "1"
	}
	if req.Finding != "" {
		features["finding:"+req.Finding] = "1"
	}
	if len(features) == 0 {
		return UIFeedbackResult{}, fmt.Errorf("feedback requires cl, path, finding or features")
	}
	kind := strings.ToLower(strings.TrimSpace(req.Kind))
	if kind != "confirm" && kind != "false-positive" && kind != "false_positive" && kind != "falsepositive" {
		return UIFeedbackResult{}, fmt.Errorf("feedback kind must be confirm or false-positive")
	}
	positive := kind == "confirm"
	weight := req.Weight
	if weight == 0 {
		weight = 2.0
	}
	encoded, err := json.Marshal(features)
	if err != nil {
		return UIFeedbackResult{}, err
	}
	python := opts.Python
	if python == "" {
		python = "python3"
	}
	script := opts.FeedbackScriptPath
	if script == "" {
		script = "research/self_learning.py"
	}
	args := []string{
		opts.abs(script), "feedback",
		"--features", string(encoded),
		"--host", valueOr(req.Host, "*"),
		"--tech", req.Tech,
		"--cl", strconv.Itoa(req.CL),
		"--path", req.Path,
		"--finding", req.Finding,
		"--weight", strconv.FormatFloat(weight, 'f', 2, 64),
		"--out", opts.abs(opts.WeightsPath),
	}
	if positive {
		args = append(args, "--confirm")
	} else {
		args = append(args, "--false-positive")
	}
	cmd := exec.CommandContext(ctx, python, args...)
	cmd.Dir = opts.abs(".")
	if cmd.Dir == "" {
		cmd.Dir = "."
	}
	cmd.Env = uiWithEnv(os.Environ(), "PYTHONUNBUFFERED=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return UIFeedbackResult{Output: uiClip(string(out), 2000)}, fmt.Errorf("feedback failed: %w", err)
	}
	result := UIFeedbackResult{Output: uiClip(string(out), 2000)}
	dec := json.NewDecoder(strings.NewReader(string(out)))
	if err := dec.Decode(&result); err != nil {
		return result, fmt.Errorf("feedback output is not JSON: %w", err)
	}
	return result, nil
}

func valueOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func intField(obj map[string]any, key string) int {
	if value, ok := obj[key].(float64); ok {
		return int(value)
	}
	return 0
}

func floatField(obj map[string]any, key string) float64 {
	if value, ok := obj[key].(float64); ok {
		return value
	}
	return 0
}

func readJSONFile(path string) (map[string]any, error) {
	if path == "" {
		return nil, fmt.Errorf("empty path")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, err
	}
	return obj, nil
}

// atomicWriteJSON mirrors the python side so both processes use temp+replace.
func atomicWriteJSON(path string, value any) error {
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	f, err := os.CreateTemp(parent, ".tmp-omnislash-ctrl-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
