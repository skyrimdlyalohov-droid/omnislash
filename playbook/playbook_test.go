package playbook

import (
	"path/filepath"
	"testing"
)

func TestLoadSolvedLabCase(t *testing.T) {
	path := filepath.Join("..", "playbooks", "h2-cl-resources-redirect.json")
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.ID != "h2-cl-resources-redirect" {
		t.Fatalf("id = %q", c.ID)
	}
	if c.Provenance.Kind != "solution-derived" || c.Provenance.AutonomousDiscovery {
		t.Fatalf("provenance = %+v, want disclosed solution-derived case", c.Provenance)
	}
	if len(c.JobTemplates) < 2 {
		t.Fatalf("job templates = %d, want verify and solve", len(c.JobTemplates))
	}
	seeds := c.Seeds()
	if len(seeds) != 1 {
		t.Fatalf("seeds = %d, want 1", len(seeds))
	}
	s := seeds[0]
	if s.Host != "*" || s.TLS != "h2" || s.Probe != "h2-cl" || s.TechStack != "h2" {
		t.Fatalf("unexpected seed key: %+v", s)
	}
	if s.Source != "playbook:h2-cl-resources-redirect" || s.Provenance != "solution-derived" {
		t.Fatalf("unexpected seed provenance: %+v", s)
	}
}
