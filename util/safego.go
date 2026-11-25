// Package util contains process-safety primitives shared by the transport,
// the probe engine and the local Python supervisor.
package util

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime/debug"
	"time"
)

// ErrPrecisionLost means the probe failed because of a local code fault, not
// because the target answered, the WAF blocked us or the proxy died. Callers
// must never learn from such a record; it is a correctness alarm.
var ErrPrecisionLost = errors.New("omnislash: precision lost: recovered panic")

// maxAuditPayload bounds the hex dump. A panic caused by a hostile frame must
// not turn into an unbounded audit file or an OOM while handling the panic.
const maxAuditPayload = 64 << 10

// panicAuditPath is overridable for tests and for deployments that keep state
// outside the working directory. The default is a local, process-owned file.
func panicAuditPath() string {
	if path := os.Getenv("OMNISLASH_PANIC_AUDIT"); path != "" {
		return path
	}
	return "panic_audit.log"
}

type panicAuditRecord struct {
	Time         time.Time `json:"time"`
	Error        string    `json:"error"`
	Panic        string    `json:"panic"`
	Stack        string    `json:"stack"`
	PayloadHex   string    `json:"payload_hex,omitempty"`
	PayloadBytes int       `json:"payload_bytes,omitempty"`
	Truncated    bool      `json:"payload_truncated,omitempty"`
}

// SafeGo runs fn in a new goroutine and contains a panic. The returned channel
// receives exactly one error when fn panics and is then closed. A successful
// run closes the channel without a value.
//
// The panic is never swallowed: it is appended to panic_audit.log with the
// stack and a hex dump, and the caller receives ErrPrecisionLost. Use
// SafeGoPayload when the bytes being processed are known, so the audit entry
// contains the exact frame or payload that triggered the fault.
func SafeGo(fn func()) <-chan error {
	return SafeGoPayload(nil, fn)
}

// SafeGoPayload is SafeGo with the raw bytes that were being processed. The
// payload is copied before the goroutine starts, so the caller may reuse its
// buffer immediately.
func SafeGoPayload(payload []byte, fn func()) <-chan error {
	raw := append([]byte(nil), payload...)
	errs := make(chan error, 1)
	go func() {
		defer close(errs)
		defer func() {
			if recovered := recover(); recovered != nil {
				errs <- recordPanic(raw, recovered)
			}
		}()
		if fn != nil {
			fn()
		}
	}()
	return errs
}

// SafeCall runs fn in the current goroutine and converts a panic into
// ErrPrecisionLost. It is used on hot paths where the caller needs a
// synchronous result (for example one probe execution) but still must not take
// the daemon down. The panic audit is written before the error is returned.
func SafeCall(payload []byte, fn func() error) (err error) {
	return SafeCallDynamic(func() []byte { return payload }, fn)
}

// SafeCallDynamic is SafeCall with a payload provider. The provider runs inside
// the deferred recover, so it can return the bytes that were actually in flight
// when the panic happened rather than a stale pre-call snapshot.
func SafeCallDynamic(payload func() []byte, fn func() error) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			var raw []byte
			if payload != nil {
				raw = payload()
			}
			err = recordPanic(raw, recovered)
		}
	}()
	if fn == nil {
		return nil
	}
	return fn()
}

// recordPanic writes the audit entry and returns the caller-visible error. A
// failed audit write is appended to the error: losing the evidence is itself a
// precision problem and must be visible.
func recordPanic(payload []byte, recovered any) error {
	raw := payload
	truncated := false
	if len(raw) > maxAuditPayload {
		raw = raw[:maxAuditPayload]
		truncated = true
	}
	panicErr := fmt.Errorf("%w: %v", ErrPrecisionLost, recovered)
	record := panicAuditRecord{
		Time:         time.Now().UTC(),
		Error:        panicErr.Error(),
		Panic:        fmt.Sprint(recovered),
		Stack:        string(debug.Stack()),
		PayloadHex:   hex.EncodeToString(raw),
		PayloadBytes: len(payload),
		Truncated:    truncated,
	}
	line, marshalErr := json.Marshal(record)
	if marshalErr != nil {
		return fmt.Errorf("%w (audit encode failed: %v)", panicErr, marshalErr)
	}
	line = append(line, '\n')
	path := panicAuditPath()
	f, openErr := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if openErr != nil {
		return fmt.Errorf("%w (panic audit %s: %v)", panicErr, path, openErr)
	}
	_, writeErr := f.Write(line)
	closeErr := f.Close()
	if writeErr != nil {
		return fmt.Errorf("%w (panic audit write: %v)", panicErr, writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("%w (panic audit close: %v)", panicErr, closeErr)
	}
	return panicErr
}
