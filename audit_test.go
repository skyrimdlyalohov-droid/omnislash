package omnislash

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestAuditLoggerWritesJSONL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := newAuditLogger(AuditConfig{Enabled: true, Path: path})
	if err != nil {
		t.Fatalf("newAuditLogger: %v", err)
	}
	a.Log(AuditEvent{Kind: "http", Method: "GET", Target: "https://lab.local/", Status: 200, Proxy: "http://127.0.0.1:8080"})
	a.Log(AuditEvent{Kind: "connect", Target: "lab.local:443", Reason: "circuit_open"})
	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	lines := 0
	for _, line := range splitLines(data) {
		if len(line) == 0 {
			continue
		}
		var ev AuditEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Fatalf("invalid JSON line %q: %v", line, err)
		}
		if ev.Time.IsZero() {
			t.Fatalf("event has zero timestamp: %+v", ev)
		}
		lines++
	}
	if lines != 2 {
		t.Fatalf("expected 2 audit lines, got %d", lines)
	}
}

func TestAuditTargetStripsQueryAndUserinfo(t *testing.T) {
	u, err := url.Parse("https://user:secret@lab.local/path?token=secret")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := auditTarget(u), "https://lab.local/path"; got != want {
		t.Fatalf("auditTarget = %q, want %q", got, want)
	}
}

func TestAuditLoggerDisabledIsNoop(t *testing.T) {
	a, err := newAuditLogger(AuditConfig{})
	if err != nil {
		t.Fatalf("newAuditLogger: %v", err)
	}
	if a != nil {
		t.Fatalf("disabled audit logger must be nil")
	}
	a.Log(AuditEvent{Kind: "http", Target: "https://lab.local/"})
	if err := a.Close(); err != nil {
		t.Fatalf("nil Close: %v", err)
	}
}

func splitLines(data []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			out = append(out, data[start:i])
			start = i + 1
		}
	}
	if start < len(data) {
		out = append(out, data[start:])
	}
	return out
}
