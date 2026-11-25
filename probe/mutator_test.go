package probe

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/skyrimdlyalohov-droid/omnislash/util"
)

type allowScope struct{}

func (allowScope) CheckTarget(context.Context, string) (string, error) { return "allowed", nil }

type denyScope struct{}

func (denyScope) CheckTarget(context.Context, string) (string, error) {
	return "", errors.New("target is not in allow_hosts")
}

func testMutator(mode MutationMode, pool BufferPool) *PayloadMutator {
	return &PayloadMutator{
		Scope:  allowScope{},
		Target: "example.com:80",
		Mode:   mode,
		Pool:   pool,
	}
}

const mutatorBaseRequest = "POST /x HTTP/1.1\r\n" +
	"Host: example.com\r\n" +
	"Content-Length: 4\r\n" +
	"Transfer-Encoding: chunked\r\n" +
	"Connection: close\r\n" +
	"\r\n" +
	"4\r\nabcd\r\n0\r\n\r\n"

func TestPayloadMutatorPreservesCRLFStructure(t *testing.T) {
	base := []byte(mutatorBaseRequest)
	for _, mode := range []MutationMode{
		MutationHeaderFolding,
		MutationCaseMixing,
		MutationChunkExtensions,
	} {
		t.Run(string(mode), func(t *testing.T) {
			out, err := testMutator(mode, nil).Mutate(base, 7)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(out, base) {
				t.Fatal("mutation did not change the request")
			}
			if !validCRLF(out) {
				t.Fatalf("mutation introduced a bare CR or LF: %q", out)
			}
			if bytes.Count(out, []byte("\r\n")) != bytes.Count(base, []byte("\r\n")) {
				t.Fatalf("CRLF count changed: base=%d out=%d", bytes.Count(base, []byte("\r\n")), bytes.Count(out, []byte("\r\n")))
			}
			if bytes.Count(out, requestSeparator) != bytes.Count(base, requestSeparator) {
				t.Fatalf("CRLFCRLF count changed: base=%d out=%d", bytes.Count(base, requestSeparator), bytes.Count(out, requestSeparator))
			}
			at := bytes.Index(out, requestSeparator) + len(requestSeparator)
			baseAt := bytes.Index(base, requestSeparator) + len(requestSeparator)
			if mode != MutationChunkExtensions && !bytes.Equal(out[at:], base[baseAt:]) {
				t.Fatalf("body changed in %s: %q", mode, out[at:])
			}
		})
	}

	t.Run("header folding replaces spaces with tabs", func(t *testing.T) {
		out, err := testMutator(MutationHeaderFolding, nil).Mutate(base, 1)
		if err != nil {
			t.Fatal(err)
		}
		lower := strings.ToLower(string(out))
		if !strings.Contains(lower, "content-length:\t") && !strings.Contains(lower, "content-length:  ") {
			t.Fatalf("Content-Length was not folded: %q", out)
		}
	})

	t.Run("case mixing changes framing header case", func(t *testing.T) {
		out, err := testMutator(MutationCaseMixing, nil).Mutate(base, 3)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(out, []byte("Content-Length")) || bytes.Contains(out, []byte("Transfer-Encoding")) {
			t.Fatalf("framing headers kept canonical case: %q", out)
		}
	})

	t.Run("chunk extension is hex and stays on one line", func(t *testing.T) {
		out, err := testMutator(MutationChunkExtensions, nil).Mutate(base, 5)
		if err != nil {
			t.Fatal(err)
		}
		at := bytes.Index(out, requestSeparator) + len(requestSeparator)
		firstLine := string(out[at : at+bytes.Index(out[at:], []byte("\r\n"))])
		if !strings.HasPrefix(firstLine, "4;") || len(firstLine) != 6 {
			t.Fatalf("chunk extension = %q", firstLine)
		}
		for _, c := range firstLine[2:] {
			if !strings.ContainsRune("0123456789abcdef", c) {
				t.Fatalf("non-hex chunk extension: %q", firstLine)
			}
		}
	})
}

// observingPool records what the mutator returns. It is sync.Pool-shaped so it
// can replace BufferPool without changing production behavior.
type observingPool struct {
	mu   sync.Mutex
	puts [][]byte
}

func (p *observingPool) Get() any {
	buf := make([]byte, 512)
	return &buf
}

func (p *observingPool) Put(v any) {
	ptr := v.(*[]byte)
	full := (*ptr)[:cap(*ptr)]
	snapshot := append([]byte(nil), full...)
	p.mu.Lock()
	p.puts = append(p.puts, snapshot)
	p.mu.Unlock()
}

func TestPayloadMutatorReturnsZeroedBufferToPool(t *testing.T) {
	pool := &observingPool{}
	out, err := testMutator(MutationHeaderFolding, pool).Mutate([]byte(mutatorBaseRequest), 11)
	if err != nil {
		t.Fatal(err)
	}
	pool.mu.Lock()
	defer pool.mu.Unlock()
	if len(pool.puts) != 1 {
		t.Fatalf("pool Put calls = %d, want 1", len(pool.puts))
	}
	for i, b := range pool.puts[0] {
		if b != 0 {
			t.Fatalf("buffer byte %d = %q, want zero (payload bleeding)", i, b)
		}
	}
	if !bytes.Contains(out, []byte("HTTP/1.1")) || bytes.Contains(out, []byte{0}) {
		t.Fatalf("returned payload was damaged by buffer reuse: %q", out)
	}
}

type panicPool struct{}

func (panicPool) Get() any { panic("injected pool fault") }
func (panicPool) Put(any)  {}

func TestMutatorAndFSMPanicsBecomeEngineFault(t *testing.T) {
	t.Setenv("OMNISLASH_PANIC_AUDIT", t.TempDir()+"/panic_audit.log")

	if _, err := safeMutate(testMutator(MutationAuto, panicPool{}), []byte(mutatorBaseRequest), 1); !errors.Is(err, util.ErrPrecisionLost) {
		t.Fatalf("mutator panic error = %v, want ErrPrecisionLost", err)
	}

	machine := &ParserStateMachine{PanicOnAnalyze: true}
	state, err := safeAnalyze(machine, []byte("HTTP/1.1 200 OK\r\n\r\n"), nil)
	if state != EngineFault || !errors.Is(err, util.ErrPrecisionLost) {
		t.Fatalf("fsm panic = (%s, %v), want Engine Fault + ErrPrecisionLost", state, err)
	}
}

func TestPayloadMutatorIsDeniedWithoutScope(t *testing.T) {
	m := &PayloadMutator{Target: "example.com:80", Mode: MutationAuto}
	if _, err := m.Mutate([]byte(mutatorBaseRequest), 1); !errors.Is(err, ErrMutationScopeDenied) {
		t.Fatalf("error = %v, want ErrMutationScopeDenied", err)
	}
	m.Scope = denyScope{}
	if _, err := m.Mutate([]byte(mutatorBaseRequest), 1); !errors.Is(err, ErrMutationScopeDenied) {
		t.Fatalf("error = %v, want ErrMutationScopeDenied", err)
	}
}

func TestPayloadMutatorIsDeterministic(t *testing.T) {
	base := []byte(mutatorBaseRequest)
	first, err := testMutator(MutationAuto, nil).Mutate(base, 42)
	if err != nil {
		t.Fatal(err)
	}
	second, err := testMutator(MutationAuto, nil).Mutate(base, 42)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("same seed produced different bytes: %q vs %q", first, second)
	}
}
