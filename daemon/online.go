package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/skyrimdlyalohov-droid/omnislash"
)

// onlineCell mirrors one cell in state/learned_weights.json. It is a prior for
// ordering declared jobs, never a verdict or a replacement for the probe.
type onlineCell struct {
	Attempts  int      `json:"attempts"`
	Successes float64  `json:"successes"`
	EMA       float64  `json:"ema"`
	Sources   []string `json:"sources"`
}

type onlinePrior struct {
	ExactWeight float64
	MinExact    int
	Global      map[string]onlineCell
	Hosts       map[string]map[string]onlineCell
	Tech        map[string]map[string]onlineCell
	NegativeCL  map[int]bool
}

type onlineWeightsFile struct {
	ExactWeight      float64                          `json:"exact_weight"`
	MinExactAttempts int                              `json:"min_exact_attempts"`
	Global           map[string]onlineCell            `json:"global"`
	Hosts            map[string]map[string]onlineCell `json:"hosts"`
	Tech             map[string]map[string]onlineCell `json:"tech"`
	Negative         struct {
		CL []int `json:"cl"`
	} `json:"negative"`
}

func loadOnlinePrior(path string) (*onlinePrior, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw onlineWeightsFile
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	p := &onlinePrior{
		ExactWeight: raw.ExactWeight,
		MinExact:    raw.MinExactAttempts,
		Global:      raw.Global,
		Hosts:       raw.Hosts,
		Tech:        raw.Tech,
		NegativeCL:  make(map[int]bool),
	}
	if p.ExactWeight <= 0 || p.ExactWeight > 1 {
		p.ExactWeight = 0.8
	}
	if p.MinExact <= 0 {
		p.MinExact = 2
	}
	for _, cl := range raw.Negative.CL {
		p.NegativeCL[cl] = true
	}
	return p, nil
}

func (p *onlinePrior) score(feature, host, tech string) (float64, bool) {
	if p == nil {
		return 0.5, false
	}
	base, ok := p.Global[feature]
	score := cellScore(base)
	if !ok {
		score = 0.5
	}
	for _, cell := range []onlineCell{
		p.Tech[tech][feature],
		p.Hosts[host][feature],
	} {
		if cell.Attempts >= p.MinExact && !solutionDerived(cell) {
			score = p.ExactWeight*cellScore(cell) + (1-p.ExactWeight)*score
		}
	}
	return score, ok
}

func cellScore(cell onlineCell) float64 {
	if cell.Attempts <= 0 {
		return 0.5
	}
	rate := cell.Successes / float64(cell.Attempts)
	return 0.5*cell.EMA + 0.5*rate
}

func solutionDerived(cell onlineCell) bool {
	for _, source := range cell.Sources {
		lower := strings.ToLower(source)
		if strings.Contains(lower, "solution-derived") || strings.Contains(lower, "playbook:") {
			return true
		}
	}
	return false
}

// onlineRuntime owns the python worker and the hot-reload state. Its mutex
// keeps weight/job swaps invisible to an in-flight attempt: execute() copies a
// JobConfig once per attempt and never observes a half-applied patch.
type onlineRuntime struct {
	mu         sync.Mutex
	d          *Daemon
	log        *slog.Logger
	opts       omnislash.OnlineLoopOptions
	process    *omnislash.OnlineProcess
	prior      *onlinePrior
	weightsKey string
	jobsKey    string
}

func newOnlineRuntime(d *Daemon, cfg *Config) *onlineRuntime {
	opts := omnislash.DefaultOnlineLoopOptions(cfg.OnlinePaths.WorkDir)
	opts.WeightsPath = cfg.OnlinePaths.WeightsPath
	opts.JobsPath = cfg.OnlinePaths.JobsPath
	opts.OffsetPath = cfg.OnlinePaths.OffsetPath
	opts.StatusPath = cfg.OnlinePaths.StatusPath
	opts.ControlPath = cfg.OnlinePaths.ControlPath
	if cfg.LogFile != "" {
		opts.AuditPath = cfg.LogFile
	}
	return &onlineRuntime{d: d, log: d.log, opts: opts}
}

func (r *onlineRuntime) start(ctx context.Context) {
	if r == nil || r.opts.AuditPath == "" {
		if r != nil && r.log != nil {
			r.log.Warn("online learning has no audit log; worker not started")
		}
		return
	}
	process, err := omnislash.StartOnlineLoop(ctx, r.opts, r.log)
	if err != nil {
		r.log.Warn("online loop start failed", "error", err)
		return
	}
	r.mu.Lock()
	r.process = process
	r.mu.Unlock()
	r.log.Info("online feedback loop started", "audit", r.opts.AuditPath, "weights", r.opts.WeightsPath)
}

func (r *onlineRuntime) reload(force bool) error {
	if r == nil {
		return nil
	}
	weightsPath := r.opts.WeightsPath
	jobsPath := r.opts.JobsPath
	weightsKey, err := stateKey(weightsPath)
	if err != nil {
		return err
	}
	jobsKey, _ := stateKey(jobsPath)

	r.mu.Lock()
	changedWeights := force || weightsKey != r.weightsKey
	changedJobs := force || jobsKey != r.jobsKey
	r.weightsKey = weightsKey
	r.jobsKey = jobsKey
	r.mu.Unlock()

	if changedWeights {
		prior, err := loadOnlinePrior(weightsPath)
		if err != nil {
			if !os.IsNotExist(err) {
				return fmt.Errorf("online weights reload: %w", err)
			}
		} else {
			r.mu.Lock()
			r.prior = prior
			r.mu.Unlock()
			if r.log != nil {
				r.log.Info("learned priors hot-reloaded", "path", weightsPath, "cells", len(prior.Global))
			}
		}
	}
	if changedJobs {
		if err := r.applyJobs(jobsPath); err != nil {
			return fmt.Errorf("online jobs reload: %w", err)
		}
	}
	return nil
}

func stateKey(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d-%d-%s", info.ModTime().UnixNano(), info.Size(), path), nil
}

// rank orders candidates by the freshly loaded weights. A feature with no
// learned cell keeps the caller's order so an untried option is never starved.
func (r *onlineRuntime) rank(prefix string, candidates []string, host, tech string) []string {
	if r == nil || len(candidates) < 2 {
		return append([]string(nil), candidates...)
	}
	r.mu.Lock()
	prior := r.prior
	r.mu.Unlock()
	if prior == nil {
		return append([]string(nil), candidates...)
	}
	scores := make(map[string]float64, len(candidates))
	evidence := false
	for _, candidate := range candidates {
		feature := prefix + ":" + candidate
		score, ok := prior.score(feature, host, tech)
		scores[candidate] = score
		if ok && score != 0.5 {
			evidence = true
		}
	}
	if !evidence {
		return append([]string(nil), candidates...)
	}
	out := append([]string(nil), candidates...)
	sort.SliceStable(out, func(i, j int) bool { return scores[out[i]] > scores[out[j]] })
	return out
}

func (r *onlineRuntime) rankCL(candidates []int, host, tech string) []int {
	if r == nil || len(candidates) < 2 {
		return append([]int(nil), candidates...)
	}
	r.mu.Lock()
	prior := r.prior
	r.mu.Unlock()
	if prior == nil {
		return append([]int(nil), candidates...)
	}
	scores := make(map[int]float64, len(candidates))
	evidence := false
	for _, value := range candidates {
		score, ok := prior.score(fmt.Sprintf("cl:%d", value), host, tech)
		if prior.NegativeCL[value] {
			score -= 1.0
		}
		scores[value] = score
		if ok && score != 0.5 {
			evidence = true
		}
	}
	if !evidence {
		return append([]int(nil), candidates...)
	}
	out := append([]int(nil), candidates...)
	sort.SliceStable(out, func(i, j int) bool { return scores[out[i]] > scores[out[j]] })
	return out
}

// onlineJobFile carries only verified strikes in "jobs". The python worker
// writes unverified hypotheses to "candidates" and the daemon ignores them.
type onlineJobFile struct {
	Schema     string           `json:"schema"`
	Jobs       []onlineJobEntry `json:"jobs"`
	Candidates []onlineJobEntry `json:"candidates"`
}

type onlineJobEntry struct {
	Name       string            `json:"name"`
	Verified   bool              `json:"verified"`
	Strike     bool              `json:"strike"`
	CrossProxy *onlineCrossProxy `json:"cross_proxy"`
	Patch      json.RawMessage   `json:"patch"`
}

type onlineCrossProxy struct {
	Verified   bool     `json:"verified"`
	Identities []string `json:"identities"`
}

func (r *onlineRuntime) applyJobs(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var file onlineJobFile
	if err := json.Unmarshal(data, &file); err != nil {
		return err
	}
	for _, entry := range file.Jobs {
		if !entry.Strike || !entry.Verified || entry.CrossProxy == nil ||
			!entry.CrossProxy.Verified || len(entry.CrossProxy.Identities) < 2 {
			// Quarantine invariant: no unverified trigger becomes a strike.
			continue
		}
		var job JobConfig
		if err := json.Unmarshal(entry.Patch, &job); err != nil {
			continue
		}
		if job.Name == "" {
			job.Name = entry.Name
		}
		if job.Name == "" || job.Target.Addr == "" || job.Probe == "" {
			continue
		}
		if job.TLS == "" {
			job.TLS = "h2"
		}
		if job.SuccessFinding == "" {
			// Without an independent finding a strike would be a mere write.
			continue
		}
		if err := validateOnlineJob(&job); err != nil {
			if r.log != nil {
				r.log.Warn("online job rejected", "name", job.Name, "error", err)
			}
			continue
		}
		r.d.mu.Lock()
		replaced := false
		for i := range r.d.cfg.Jobs {
			if r.d.cfg.Jobs[i].Name != job.Name {
				continue
			}
			// Running attempts keep their copied job; only future scheduling
			// sees the patch, so active sessions are never interrupted.
			r.d.cfg.Jobs[i] = job
			replaced = true
			break
		}
		if !replaced {
			r.d.cfg.Jobs = append(r.d.cfg.Jobs, job)
			r.d.states[job.Name] = &JobState{Name: job.Name}
		}
		if r.d.states[job.Name] == nil {
			r.d.states[job.Name] = &JobState{Name: job.Name}
		}
		r.d.mu.Unlock()
		if r.log != nil {
			r.log.Info("verified online strike job installed", "name", job.Name,
				"path", job.Target.Path, "cl", job.DeclaredLength)
		}
	}
	return nil
}

func validateOnlineJob(job *JobConfig) error {
	if job.Attempts < 0 {
		return fmt.Errorf("negative attempts")
	}
	switch job.TLS {
	case "", "h1", "h2", "none":
	default:
		return fmt.Errorf("unsupported tls %q", job.TLS)
	}
	switch job.Probe {
	case "smuggle-chain", "smuggle", "race", "h2race", "h2-cl", "h2-tunnel",
		"differential-fuzz", "raw-replay", "upgrade-desync":
	default:
		return fmt.Errorf("unsupported probe %q", job.Probe)
	}
	return nil
}

func (r *onlineRuntime) snapshot() any {
	if r == nil {
		return omnislash.OnlineStatus{State: "PAUSED"}
	}
	r.mu.Lock()
	process := r.process
	r.mu.Unlock()
	return omnislash.OnlineSnapshot(r.opts, process)
}

func (r *onlineRuntime) toggle(_ context.Context, enabled bool) (any, error) {
	if r == nil {
		return nil, fmt.Errorf("online learning is not configured on this process")
	}
	if err := omnislash.ToggleOnline(r.opts, enabled); err != nil {
		return nil, err
	}
	state := "PAUSED"
	message := "online feedback loop paused"
	if enabled {
		state, message = "ACTIVE", "online feedback loop resumed"
	}
	return map[string]any{"enabled": enabled, "state": state, "message": message}, nil
}

func (r *onlineRuntime) feedback(ctx context.Context, req omnislash.UIFeedbackRequest) (any, error) {
	if r == nil {
		return nil, fmt.Errorf("online learning is not configured on this process")
	}
	result, err := omnislash.ApplyOnlineFeedback(ctx, r.opts, req)
	if err == nil {
		reloadErr := r.reload(true)
		if reloadErr != nil && r.log != nil {
			r.log.Warn("priors reload after manual feedback failed", "error", reloadErr)
		}
	}
	return result, err
}
