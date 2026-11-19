// Package daemon turns probes into a long-running service: jobs are declared in
// a JSON file, scheduled on an interval, retried, and recorded as JSONL. Every
// attempt still goes through probe.Runner, so one attempt uses one pinned
// session and one set of sockets; the daemon never dials a target itself.
package daemon

import (
	"encoding/json"
	"fmt"
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

	Jobs []JobConfig `json:"jobs"`
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

	Variant         string `json:"variant"`
	VictimMethod    string `json:"victim_method"`
	VictimPath      string `json:"victim_path"`
	SuccessContains string `json:"success_contains"`
	Count           int    `json:"count"`
	Method          string `json:"method"`
	Path            string `json:"path"`
	SingleUse       bool   `json:"single_use"`

	// Attempts is the number of probe runs inside one scheduled execution.
	Attempts int `json:"attempts"`
	// UntilSuccess stops retrying this job once it succeeds, and with
	// exit_on_success stops the daemon.
	UntilSuccess bool `json:"until_success"`

	Interval   omnislash.Duration `json:"interval"`
	Timeout    omnislash.Duration `json:"timeout"`
	Idle       omnislash.Duration `json:"idle"`
	RetryDelay omnislash.Duration `json:"retry_delay"`
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
		case "smuggle-chain", "smuggle", "race", "h2race":
		default:
			return fmt.Errorf("daemon: job %q: unsupported probe %q", j.Name, j.Probe)
		}
		if j.Attempts < 0 {
			return fmt.Errorf("daemon: job %q: attempts must not be negative", j.Name)
		}
		if j.Probe == "h2race" && j.tlsMode() != "h2" {
			return fmt.Errorf("daemon: job %q: h2race requires tls=h2", j.Name)
		}
		if j.Probe == "smuggle" && j.Variant == string(probe.VariantH2Downgrade) && j.tlsMode() != "h2" {
			return fmt.Errorf("daemon: job %q: h2.downgrade requires tls=h2", j.Name)
		}
		if j.Interval.Std() < 0 || j.Timeout.Std() < 0 || j.Idle.Std() < 0 || j.RetryDelay.Std() < 0 {
			return fmt.Errorf("daemon: job %q: durations must not be negative", j.Name)
		}
	}
	return nil
}

// IsEnabled reports whether the job should run. Jobs are enabled by default.
func (j *JobConfig) IsEnabled() bool {
	return j.Enabled == nil || *j.Enabled
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
