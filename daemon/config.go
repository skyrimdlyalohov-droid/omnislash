// Package daemon turns probes into a long-running service: jobs are declared in
// a JSON file, scheduled on an interval, retried, and recorded as JSONL. Every
// attempt still goes through probe.Runner, so one attempt uses one pinned
// session and one set of sockets; the daemon never dials a target itself.
package daemon

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"time"

	"github.com/skyrimdlyalohov-droid/omnislash"
	"github.com/skyrimdlyalohov-droid/omnislash/probe"
)

// Target is the probe target descriptor.
type Target = probe.Target

// Config is the daemon configuration file.
type Config struct {
	// OmnislashConfig is the transport config: trust tier, scope, pool.
	OmnislashConfig string `json:"omnislash_config"`
	// Proxies is an optional proxy list. Empty means direct egress, which
	// requires trust_tier=trusted and allow_direct=true in the transport config.
	Proxies string `json:"proxies"`
	// LogFile receives one JSON object per attempt. Empty logs to stderr only.
	LogFile string `json:"log_file"`
	// PollInterval is how often the scheduler looks for due jobs.
	PollInterval omnislash.Duration `json:"poll_interval"`
	// Concurrency bounds simultaneously running jobs.
	Concurrency int `json:"concurrency"`
	// ExitOnSuccess stops the daemon after the first successful job. This is the
	// CI/lab mode: one command, one verdict, process exit.
	ExitOnSuccess bool `json:"exit_on_success"`
	// ControlAddr enables a localhost control endpoint (/healthz, /status).
	ControlAddr string `json:"control_addr"`

	// LearningEnabled turns on the audit-log feedback loop. Nil means enabled:
	// the daemon reads its own JSONL audit log at startup and uses observed
	// success rates to rank variants and mutations on subsequent attempts.
	LearningEnabled *bool `json:"learning_enabled,omitempty"`
	// LearningPolicy controls epsilon-greedy exploration. One roll is taken per
	// attempt and shared by every ranking stage, so exploration never stacks to
	// ~22.5%. Epsilon decays exponentially until it reaches EpsilonMin.
	LearningPolicy LearningPolicy `json:"learning_policy,omitempty"`
	// LearningSources are additional audit JSONL files to replay at startup.
	// Paths are resolved against the daemon config directory. The daemon's own
	// log_file is always included in addition to these.
	LearningSources []string `json:"learning_sources,omitempty"`

	// OnlineLearning starts research/online_loop.py alongside the long-running
	// daemon. Nil means enabled. One-shot (-once / -job) modes never start it.
	OnlineLearning *bool `json:"online_learning,omitempty"`
	// OnlinePaths overrides the state files shared with the python worker.
	// Relative paths are resolved against this config's directory.
	OnlinePaths OnlineLearningPaths `json:"online_paths,omitempty"`

	Jobs []JobConfig `json:"jobs"`
}

// LearningPolicy is the exploration schedule for learned rankings.
// Epsilon starts at 0.12 (inside the 10-15% band), decays per observed attempt
// and never drops below EpsilonMin. Explicit zeros mean "use the defaults".
type LearningPolicy struct {
	Epsilon      float64 `json:"epsilon,omitempty"`
	EpsilonMin   float64 `json:"epsilon_min,omitempty"`
	EpsilonDecay float64 `json:"epsilon_decay,omitempty"`
}

func (p LearningPolicy) withDefaults() LearningPolicy {
	if p.Epsilon <= 0 {
		p.Epsilon = 0.12
	}
	if p.EpsilonMin <= 0 {
		p.EpsilonMin = 0.02
	}
	if p.EpsilonDecay <= 0 {
		p.EpsilonDecay = 0.995
	}
	return p
}

// epsilonAt returns the exploration probability after n observed attempts.
func (p LearningPolicy) epsilonAt(n int64) float64 {
	p = p.withDefaults()
	if n < 0 {
		n = 0
	}
	value := p.EpsilonMin + (p.Epsilon-p.EpsilonMin)*math.Pow(p.EpsilonDecay, float64(n))
	if value < p.EpsilonMin {
		return p.EpsilonMin
	}
	if value > p.Epsilon {
		return p.Epsilon
	}
	return value
}

// OnlineLearningPaths names the files owned by the streaming feedback loop.
type OnlineLearningPaths struct {
	// WorkDir is the directory the python worker runs from (defaults to the
	// process CWD). It holds research/online_loop.py and self_learning.py.
	WorkDir     string `json:"work_dir,omitempty"`
	WeightsPath string `json:"weights_path,omitempty"`
	JobsPath    string `json:"jobs_path,omitempty"`
	OffsetPath  string `json:"offset_path,omitempty"`
	StatusPath  string `json:"status_path,omitempty"`
	ControlPath string `json:"control_path,omitempty"`
}

// TargetConfig is the dial target and the request authority.
type TargetConfig struct {
	Addr string `json:"addr"`
	Host string `json:"host"`
	Path string `json:"path"`
}

// JobConfig declares one automated probe.
type JobConfig struct {
	Name    string       `json:"name"`
	Enabled *bool        `json:"enabled,omitempty"`
	Target  TargetConfig `json:"target"`

	// TLS is "h1" (default), "h2" or "none".
	TLS string `json:"tls"`
	// Probe is "smuggle-chain", "smuggle", "race" or "h2race".
	Probe string `json:"probe"`

	Variant      string `json:"variant"`
	VictimMethod string `json:"victim_method"`
	VictimPath   string `json:"victim_path"`

	// Smuggled request fields for the TE.CL variant of smuggle-chain and the
	// H2.CL probe. Smuggled* describe the HTTP/1.1 request carried in the
	// surplus DATA; Body, when set, is written verbatim instead.
	SmuggledMethod string `json:"smuggled_method"`
	SmuggledPath   string `json:"smuggled_path"`
	SmuggledHost   string `json:"smuggled_host"`
	SmuggledBody   string `json:"smuggled_body"`
	SmuggledPrefix string `json:"smuggled_prefix"`
	Body           string `json:"body"`

	// H2.CL fields. DeclaredLength is the HTTP/2 content-length header; the
	// surplus DATA is the smuggled request. Authority overrides :authority.
	DeclaredLength  int    `json:"declared_length"`
	DeclaredLengths []int  `json:"declared_lengths"`
	Authority       string `json:"authority"`
	Scheme          string `json:"scheme"`
	// SameConnectionVictim reuses the poisoned h2 connection; SkipVictim leaves
	// the smuggled response for the lab's real browser.
	SameConnectionVictim bool               `json:"same_connection_victim"`
	SkipVictim           bool               `json:"skip_victim"`
	HoldAfterPoison      omnislash.Duration `json:"hold_after_poison"`
	ReadExtraStream      bool               `json:"read_extra_stream"`

	SuccessContains string `json:"success_contains"`
	// SuccessFinding requires a finding of this kind. It is how a job states
	// "cache_poisoned", not merely "the probe completed".
	SuccessFinding string   `json:"success_finding"`
	PoisonPath     string   `json:"poison_path"`
	GadgetPath     string   `json:"gadget_path"`
	Host           string   `json:"host"`
	TunnelHost     string   `json:"tunnel_host"`
	PaddingPaths   []string `json:"padding_paths"`
	Count          int      `json:"count"`
	Method         string   `json:"method"`
	Path           string   `json:"path"`
	SingleUse      bool     `json:"single_use"`

	// Differential-fuzz fields.
	Mutations        []string           `json:"mutations"`
	TechStack        []string           `json:"tech_stack"`
	Pairs            int                `json:"pairs"`
	JitterMaxIQR     omnislash.Duration `json:"jitter_max_iqr"`
	Hold             omnislash.Duration `json:"hold"`
	NeighborShiftNCD float64            `json:"neighbor_shift_ncd"`

	// Raw replay / universal key fields.
	RawPayloadB64 string `json:"raw_payload_b64"`
	RawPayloadHex string `json:"raw_payload_hex"`

	// Upgrade-desync fields.
	UpgradeType string `json:"upgrade_type"` // websocket, grpc, h2c

	// Attempts is the number of probe runs inside one scheduled execution.
	Attempts int `json:"attempts"`
	// UntilSuccess stops retrying this job once it succeeds, and with
	// exit_on_success stops the daemon.
	UntilSuccess bool `json:"until_success"`

	Interval    omnislash.Duration `json:"interval"`
	Timeout     omnislash.Duration `json:"timeout"`
	Idle        omnislash.Duration `json:"idle"`
	RetryDelay  omnislash.Duration `json:"retry_delay"`
	VictimDelay omnislash.Duration `json:"victim_delay"`
}

// LoadConfig reads path and resolves relative file paths against its directory.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("daemon: read config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("daemon: parse %s: %w", path, err)
	}
	base := filepath.Dir(path)
	cfg.OmnislashConfig = resolvePath(base, cfg.OmnislashConfig)
	cfg.Proxies = resolvePath(base, cfg.Proxies)
	cfg.LogFile = resolvePath(base, cfg.LogFile)
	for i, src := range cfg.LearningSources {
		cfg.LearningSources[i] = resolvePath(base, src)
	}
	cfg.OnlinePaths.WorkDir = resolvePath(base, cfg.OnlinePaths.WorkDir)
	cfg.OnlinePaths.WeightsPath = resolvePath(base, cfg.OnlinePaths.WeightsPath)
	cfg.OnlinePaths.JobsPath = resolvePath(base, cfg.OnlinePaths.JobsPath)
	cfg.OnlinePaths.OffsetPath = resolvePath(base, cfg.OnlinePaths.OffsetPath)
	cfg.OnlinePaths.StatusPath = resolvePath(base, cfg.OnlinePaths.StatusPath)
	cfg.OnlinePaths.ControlPath = resolvePath(base, cfg.OnlinePaths.ControlPath)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func resolvePath(base, p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(base, p)
}

// Validate checks the parts of the daemon config that do not need the network.
func (c *Config) Validate() error {
	if c.OmnislashConfig == "" {
		return fmt.Errorf("daemon: omnislash_config is required")
	}
	policy := c.LearningPolicy.withDefaults()
	if policy.Epsilon < 0 || policy.Epsilon > 1 {
		return fmt.Errorf("daemon: learning_policy.epsilon must be in [0,1]")
	}
	if policy.EpsilonMin < 0 || policy.EpsilonMin > policy.Epsilon {
		return fmt.Errorf("daemon: learning_policy.epsilon_min must be in [0,epsilon]")
	}
	if policy.EpsilonDecay <= 0 || policy.EpsilonDecay > 1 {
		return fmt.Errorf("daemon: learning_policy.epsilon_decay must be in (0,1]")
	}
	if c.PollInterval.Std() < 0 {
		return fmt.Errorf("daemon: poll_interval must not be negative")
	}
	if len(c.Jobs) == 0 {
		return fmt.Errorf("daemon: at least one job is required")
	}
	seen := make(map[string]bool, len(c.Jobs))
	for i := range c.Jobs {
		j := &c.Jobs[i]
		if j.Name == "" {
			return fmt.Errorf("daemon: jobs[%d].name is required", i)
		}
		if seen[j.Name] {
			return fmt.Errorf("daemon: duplicate job %q", j.Name)
		}
		seen[j.Name] = true
		if j.Target.Addr == "" {
			return fmt.Errorf("daemon: job %q: target.addr is required", j.Name)
		}
		switch j.TLS {
		case "", "h1", "h2", "none":
		default:
			return fmt.Errorf("daemon: job %q: tls must be h1, h2 or none", j.Name)
		}
		switch j.Probe {
		case "smuggle-chain", "smuggle", "race", "h2race", "h2-cl", "h2-tunnel", "differential-fuzz", "raw-replay", "upgrade-desync":
		default:
			return fmt.Errorf("daemon: job %q: unsupported probe %q", j.Name, j.Probe)
		}
		if j.Attempts < 0 {
			return fmt.Errorf("daemon: job %q: attempts must not be negative", j.Name)
		}
		if j.Probe == "h2race" && j.tlsMode() != "h2" {
			return fmt.Errorf("daemon: job %q: h2race requires tls=h2", j.Name)
		}
		if j.Probe == "h2-tunnel" && j.tlsMode() != "h2" {
			return fmt.Errorf("daemon: job %q: h2-tunnel requires tls=h2", j.Name)
		}
		if j.Probe == "h2-cl" && j.tlsMode() != "h2" {
			return fmt.Errorf("daemon: job %q: h2-cl requires tls=h2", j.Name)
		}
		if j.Probe == "smuggle" && j.Variant == string(probe.VariantH2Downgrade) && j.tlsMode() != "h2" {
			return fmt.Errorf("daemon: job %q: h2.downgrade requires tls=h2", j.Name)
		}
		if j.Interval.Std() < 0 || j.Timeout.Std() < 0 || j.Idle.Std() < 0 || j.RetryDelay.Std() < 0 || j.VictimDelay.Std() < 0 || j.HoldAfterPoison.Std() < 0 {
			return fmt.Errorf("daemon: job %q: durations must not be negative", j.Name)
		}
	}
	return nil
}

// IsEnabled reports whether the job should run. Jobs are enabled by default.
func (j *JobConfig) IsEnabled() bool {
	return j.Enabled == nil || *j.Enabled
}

// IsLearningEnabled reports whether the audit feedback loop is active. Nil
// means enabled, so existing configs gain learning without a schema change.
func (c *Config) IsLearningEnabled() bool {
	return c.LearningEnabled == nil || *c.LearningEnabled
}

// IsOnlineLearningEnabled reports whether the streaming python loop is active.
// Nil means enabled; -once/-job modes still skip it because no worker survives
// a one-shot process.
func (c *Config) IsOnlineLearningEnabled() bool {
	return c.OnlineLearning == nil || *c.OnlineLearning
}

func (j *JobConfig) interval() time.Duration {
	if d := j.Interval.Std(); d > 0 {
		return d
	}
	return 30 * time.Second
}

func (j *JobConfig) attempts() int {
	if j.Attempts > 0 {
		return j.Attempts
	}
	if j.Probe == "smuggle-chain" {
		return 3
	}
	return 1
}

func (j *JobConfig) retryDelay() time.Duration {
	if d := j.RetryDelay.Std(); d > 0 {
		return d
	}
	return time.Second
}

func (j *JobConfig) tlsMode() string {
	if j.TLS == "" {
		return "h1"
	}
	return j.TLS
}

func (j *JobConfig) target() (target Target, err error) {
	if j.Target.Addr == "" {
		return target, fmt.Errorf("daemon: job %q: target.addr is required", j.Name)
	}
	path := j.Path
	if path == "" {
		path = j.Target.Path
	}
	return Target{Addr: j.Target.Addr, Host: j.Target.Host, Path: path}, nil
}
