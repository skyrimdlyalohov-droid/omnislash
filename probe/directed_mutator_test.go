package probe

import (
	"bytes"
	"testing"
)

func TestBoundaryShiftKeepsCRLFAndScope(t *testing.T) {
	base := []byte("POST /a HTTP/1.1\r\nHost: lab.test\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
	mut := &PayloadMutator{
		Scope:   denyScope{},
		Target:  "lab.test:443",
		Mode:    MutationBoundaryShift,
		Fitness: 0.1,
	}
	if _, err := mut.Mutate(base, 7); err == nil {
		t.Fatal("directed mutation must be refused by a fail-closed scope guard")
	}
	mut.Scope = allowScope{}
	pool := &observingPool{}
	mut.Pool = pool
	out, err := safeMutate(mut, base, 7)
	if err != nil {
		t.Fatal(err)
	}
	if !validCRLF(out) || !bytes.Contains(out, []byte("Content-Length: 5")) {
		t.Fatalf("boundary shift = %q, want CL+1 with intact CRLF", out)
	}
	if !bytes.Contains(out, []byte("omni=")) {
		t.Fatalf("TE boundary was not shifted: %q", out)
	}
	pool.mu.Lock()
	defer pool.mu.Unlock()
	if len(pool.puts) != 1 {
		t.Fatalf("pool Put calls = %d, want 1", len(pool.puts))
	}
	for _, b := range pool.puts[0] {
		if b != 0 {
			t.Fatal("directed mutation leaked its scratch buffer into the pool")
		}
	}

	mut.Fitness = -0.5
	mut.Pool = nil
	down, err := safeMutate(mut, base, 7)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(down, []byte("Content-Length: 3")) {
		t.Fatalf("negative fitness must shift CL down: %q", down)
	}
}

func TestEliteCrossoverUsesOnlyConfirmedFraming(t *testing.T) {
	base := []byte("POST /a HTTP/1.1\r\nHost: lab.test\r\nContent-Length: 4\r\n\r\nbody")
	eliteA := []byte("POST /a HTTP/1.1\r\nHost: lab.test\r\nContent-Length: 9\r\nTransfer-Encoding: chunked\r\n\r\nbody")
	eliteB := []byte("POST /a HTTP/1.1\r\nHost: lab.test\r\nContent-Length: 7\r\nTransfer-Encoding: identity\r\n\r\nbody")
	mut := &PayloadMutator{
		Scope: allowScope{}, Target: "lab.test:443",
		Mode: MutationEliteCrossover, Elite: [][]byte{eliteA, eliteB},
	}
	out, err := mut.Mutate(base, 11)
	if err != nil {
		t.Fatal(err)
	}
	if !validCRLF(out) {
		t.Fatalf("crossover broke CRLF framing: %q", out)
	}
	if !bytes.Contains(out, []byte("Content-Length: 9")) && !bytes.Contains(out, []byte("Content-Length: 7")) {
		t.Fatalf("crossover lost elite framing values: %q", out)
	}

	var pool ElitePool
	if !pool.Add(eliteA, 2) || !pool.Add(eliteB, 3) || pool.Add(base, 1) {
		t.Fatal("the elite pool must keep only the two highest-fitness patterns")
	}
	patterns := pool.Patterns()
	if len(patterns) != 2 || !bytes.Equal(patterns[0], eliteB) {
		t.Fatalf("elite order = %q, want highest fitness first", patterns)
	}
}
