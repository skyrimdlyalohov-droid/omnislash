package omnislash

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"sync"
	"time"
)

// AuditEvent is one JSON line in the audit log. It intentionally has no field
// for request or response bodies: evidence collection is the caller's job, not
// the transport's.
type AuditEvent struct {
	Time      time.Time `json:"time"`
	Kind      string    `json:"kind"`
	Method    string    `json:"method,omitempty"`
	Target    string    `json:"target,omitempty"`
	Status    int       `json:"status,omitempty"`
	Proxy     string    `json:"proxy,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	RequestID string    `json:"request_id,omitempty"`
	Duration  string    `json:"duration,omitempty"`
}

// AuditLogger serializes audit events to one writer. A nil logger is a no-op,
// so callers do not need nil checks.
type AuditLogger struct {
	mu  sync.Mutex
	enc *json.Encoder
	w   io.WriteCloser
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

// auditTarget strips the query string and userinfo so tokens never reach the
// audit log.
func auditTarget(u *url.URL) string {
	if u == nil {
		return ""
	}
	return u.Scheme + "://" + u.Host + u.Path
}

func newAuditLogger(cfg AuditConfig) (*AuditLogger, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	var w io.WriteCloser
	switch cfg.Path {
	case "", "-":
		w = nopWriteCloser{Writer: os.Stdout}
	default:
		f, err := os.OpenFile(cfg.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, fmt.Errorf("open audit log %s: %w", cfg.Path, err)
		}
		w = f
	}
	return &AuditLogger{w: w, enc: json.NewEncoder(w)}, nil
}

// Log writes one event. Errors are ignored: auditing must never take down a
// scan, and the underlying writer is a local file or stdout.
func (a *AuditLogger) Log(ev AuditEvent) {
	if a == nil {
		return
	}
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	_ = a.enc.Encode(ev)
}

// Close flushes and closes the underlying file. It is safe to call on nil.
func (a *AuditLogger) Close() error {
	if a == nil || a.w == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.w == nil {
		return nil
	}
	err := a.w.Close()
	a.w = nil
	return err
}
