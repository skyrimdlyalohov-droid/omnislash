// Package playbook loads curated OmniSlash cases. A playbook is a replayable
// prior with explicit provenance: it can order experiments, but it is never
// presented as an autonomous discovery or as an observed audit record.
package playbook

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/skyrimdlyalohov-droid/omnislash/daemon"
)

// Provenance records where the decisive idea came from.
type Provenance struct {
	Kind                string `json:"kind"`
	AutonomousDiscovery bool   `json:"autonomous_discovery"`
	SourceURL           string `json:"source_url,omitempty"`
	Disclosure          string `json:"disclosure,omitempty"`
}

// AppliesTo describes the protocol edge and technique a case belongs to.
type AppliesTo struct {
	ProtocolEdge  string   `json:"protocol_edge"`
	Probe         string   `json:"probe"`
	TLS           string   `json:"tls"`
	TechStack     []string `json:"tech_stack,omitempty"`
	Gadget        string   `json:"gadget,omitempty"`
	Authorization string   `json:"authorization,omitempty"`
}

// Learning is the optional ordering prior carried by a case.
type Learning struct {
	SeedGlobalPrior bool `json:"seed_global_prior"`
	Key             struct {
		Host      string `json:"host,omitempty"`
		TLS       string `json:"tls,omitempty"`
		Probe     string `json:"probe,omitempty"`
		Variant   string `json:"variant,omitempty"`
		Mutation  string `json:"mutation,omitempty"`
		TechStack string `json:"tech_stack,omitempty"`
	} `json:"key"`
	Signal     string `json:"signal,omitempty"`
	Attempts   int    `json:"attempts"`
	Successes  int    `json:"successes"`
	Provenance string `json:"provenance,omitempty"`
	Note       string `json:"note,omitempty"`
}

// Case is one structured lab solution.
type Case struct {
	Schema       string                     `json:"schema"`
	ID           string                     `json:"id"`
	Title        string                     `json:"title"`
	Provenance   Provenance                 `json:"provenance"`
	AppliesTo    AppliesTo                  `json:"applies_to"`
	JobTemplates map[string]json.RawMessage `json:"job_templates"`
	Learning     Learning                   `json:"learning"`
}

// Load reads and validates one playbook case.
func Load(path string) (*Case, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("playbook: read %s: %w", path, err)
	}
	var c Case
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("playbook: parse %s: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("playbook: %s: %w", path, err)
	}
	return &c, nil
}

// Validate checks the fields needed to turn a case into an ordering prior.
func (c *Case) Validate() error {
	if c == nil {
		return fmt.Errorf("nil case")
	}
	if c.Schema != "omnislash.playbook/v1" {
		return fmt.Errorf("unsupported schema %q", c.Schema)
	}
	if c.ID == "" {
		return fmt.Errorf("id is required")
	}
	if c.Provenance.Kind == "" {
		return fmt.Errorf("provenance.kind is required")
	}
	if len(c.JobTemplates) == 0 {
		return fmt.Errorf("at least one job template is required")
	}
	return nil
}

// Seeds converts the case's learning label into a daemon experience seed.
// Empty means the case is replay-only and does not affect ranking.
func (c *Case) Seeds() []daemon.ExperienceSeed {
	if c == nil || !c.Learning.SeedGlobalPrior || c.Learning.Attempts <= 0 {
		return nil
	}
	host := c.Learning.Key.Host
	if host == "" {
		host = "*"
	}
	provenance := c.Learning.Provenance
	if provenance == "" {
		provenance = c.Provenance.Kind
	}
	return []daemon.ExperienceSeed{{
		Host:       host,
		TLS:        c.Learning.Key.TLS,
		Probe:      c.Learning.Key.Probe,
		Variant:    c.Learning.Key.Variant,
		Mutation:   c.Learning.Key.Mutation,
		TechStack:  c.Learning.Key.TechStack,
		Attempts:   c.Learning.Attempts,
		Successes:  c.Learning.Successes,
		Provenance: provenance,
		Source:     "playbook:" + c.ID,
	}}
}
