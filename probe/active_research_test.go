package probe

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// deterministicCanary keeps group testing reproducible without weakening the
// production default of crypto/rand. One 12-byte canary is enough for a
// single-header candidate.
func deterministicCanary() *bytes.Reader {
	return bytes.NewReader(bytes.Repeat([]byte{0xab}, 64))
}

type cacheReflectionMock struct {
	trigger string

	mu        sync.Mutex
	path      string
	location  string
	injected  bool
	requests  int
	allPaths  []string
	lastPaths []string
}

func (m *cacheReflectionMock) serve(conn net.Conn) {
	defer conn.Close()
	req, err := readGadgetRequest(conn)
	if err != nil {
		return
	}
	canary, hasHeader := req.headers[strings.ToLower(m.trigger)]
	m.mu.Lock()
	m.requests++
	m.allPaths = append(m.allPaths, req.path)
	if hasHeader && canary != "" {
		m.injected = true
		m.path = req.path
		m.location = "https://cache.test/redirect/" + canary
		location := m.location
		m.mu.Unlock()
		writeGadgetResponse(conn, 301, map[string]string{"Location": location}, `{"cached":true}`)
		return
	}
	injected, path, location := m.injected, m.path, m.location
	m.mu.Unlock()
	if injected && req.path == path {
		writeGadgetResponse(conn, 301, map[string]string{"Location": location}, `{"cached":true}`)
		return
	}
	writeGadgetResponse(conn, 200, nil, `{"ok":true,"nonce":"AAAA"}`)
}

func (m *cacheReflectionMock) snapshot() (int, bool, []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.requests, m.injected, append([]string(nil), m.allPaths...)
}

func TestGadgetStandaloneRequiresReflectionAndCleanPersistence(t *testing.T) {
	for _, mode := range []GadgetMode{GadgetStandalone, GadgetUnkeyedCache} {
		t.Run(string(mode), func(t *testing.T) {
			mock := &cacheReflectionMock{trigger: "x-original-url"}
			p := &GadgetProbe{
				Mode:         mode,
				Headers:      []string{"X-Original-URL"},
				BatchSize:    1,
				MaxRequests:  8,
				canaryReader: deterministicCanary(),
			}
			res, err := p.ExecuteMulti(context.Background(),
				Target{Addr: "lab.test:80", Host: "lab.test", Path: "/target"},
				&pipeGadgetSource{mock: mock})
			if err != nil {
				t.Fatal(err)
			}
			kinds := make(map[string]int)
			for _, f := range res.Findings {
				kinds[f.Kind]++
				if f.Confidence != ConfidenceHigh && (f.Kind == "gadget_reflected" || f.Kind == "cache_poisoned") {
					t.Fatalf("confirmation is not high confidence: %+v", f)
				}
			}
			if kinds["gadget_reflected"] != 1 || kinds["cache_poisoned"] != 1 {
				t.Fatalf("findings = %+v, want one reflection and one persisted cache finding", res.Findings)
			}
			if kinds["unkeyed_header"] != 0 {
				t.Fatalf("standalone promoted an unkeyed header without verification: %+v", res.Findings)
			}
			requests, injected, paths := mock.snapshot()
			if requests != 3 || !injected {
				t.Fatalf("requests = %d injected = %v, want 3 requests including the injected one", requests, injected)
			}
			if len(paths) != 3 || paths[0] != paths[1] || paths[1] != paths[2] || !strings.Contains(paths[0], "_omni_cb=") {
				t.Fatalf("cache keys differ across baseline, injection and control: %v", paths)
			}
			if len(res.Exchanges) != 3 {
				t.Fatalf("exchanges = %d, want baseline, injection and clean control GET", len(res.Exchanges))
			}
			canary := strings.Repeat("ab", 12)
			if !strings.Contains(res.Exchanges[1].Raw, "X-Original-URL: "+canary) {
				t.Fatalf("injected request lacks its canary: %q", res.Exchanges[1].Raw)
			}
			if strings.Contains(res.Exchanges[2].Raw, "X-Original-URL:") {
				t.Fatalf("control GET reused the gadget header: %q", res.Exchanges[2].Raw)
			}
			if !strings.Contains(res.Exchanges[2].Raw, paths[2]) {
				t.Fatalf("control GET addressed a different cache key: %q", res.Exchanges[2].Raw)
			}
		})
	}
}

type noReflectionMock struct{ requests atomic.Int32 }

func (m *noReflectionMock) serve(conn net.Conn) {
	defer conn.Close()
	req, err := readGadgetRequest(conn)
	if err != nil {
		return
	}
	if n := m.requests.Add(1); n == 1 {
		writeGadgetResponse(conn, 200, nil, `{"ok":true}`)
		return
	}
	canary := req.headers["x-original-url"]
	writeGadgetResponse(conn, 301, map[string]string{
		"Location": "https://redirect.test/landing",
		"X-Echo":   canary,
	}, `{"ok":false}`)
}

func TestGadgetStandaloneRejectsChangeWithoutReflection(t *testing.T) {
	mock := &noReflectionMock{}
	p := &GadgetProbe{
		Mode:         GadgetStandalone,
		Headers:      []string{"X-Original-URL"},
		BatchSize:    1,
		MaxRequests:  8,
		canaryReader: deterministicCanary(),
	}
	res, err := p.ExecuteMulti(context.Background(),
		Target{Addr: "lab.test:80", Host: "lab.test"}, &pipeGadgetSource{mock: mock})
	if err != nil {
		t.Fatal(err)
	}
	var diagnostic bool
	for _, f := range res.Findings {
		if f.Kind == "gadget_reflection_missing" && f.Confidence == ConfidenceLow {
			diagnostic = true
		}
		if f.Confidence == ConfidenceHigh {
			t.Fatalf("non-reflected response was confirmed: %+v", f)
		}
	}
	if !diagnostic {
		t.Fatalf("no reflection diagnostic: %+v", res.Findings)
	}
	if got := int(mock.requests.Load()); got != 2 {
		t.Fatalf("requests = %d, want 2 (no control GET without reflection)", got)
	}
}

type rejectingGadgetMock struct{ requests atomic.Int32 }

func (m *rejectingGadgetMock) serve(conn net.Conn) {
	defer conn.Close()
	if _, err := readGadgetRequest(conn); err != nil {
		return
	}
	if m.requests.Add(1) == 1 {
		writeGadgetResponse(conn, 200, nil, `{"ok":true}`)
		return
	}
	writeGadgetResponse(conn, 400, nil, "rejected")
}

func TestGadgetProbeStopsOnTargetRejected(t *testing.T) {
	cases := []struct {
		baseline int
		sample   int
		want     bool
	}{
		{200, 400, true},
		{200, 501, true},
		{301, 400, true},
		{301, 501, true},
		{200, 403, false},
		{404, 400, false},
		{200, 200, false},
	}
	for _, tc := range cases {
		if got := parserRejected(tc.baseline, tc.sample); got != tc.want {
			t.Fatalf("parserRejected(%d, %d) = %v, want %v", tc.baseline, tc.sample, got, tc.want)
		}
	}

	mock := &rejectingGadgetMock{}
	p := &GadgetProbe{Headers: []string{"X-Host"}, BatchSize: 1, MaxRequests: 32}
	res, err := p.ExecuteMulti(context.Background(),
		Target{Addr: "lab.test:80", Host: "lab.test"}, &pipeGadgetSource{mock: mock})
	if err != nil {
		t.Fatal(err)
	}
	if got := int(mock.requests.Load()); got != 2 {
		t.Fatalf("requests = %d, want baseline + one rejected signature only", got)
	}
	var rejected bool
	for _, f := range res.Findings {
		if f.Kind == FindingTargetRejected {
			rejected = true
			if !strings.Contains(f.Detail, "200 -> 400") {
				t.Fatalf("rejection detail = %q", f.Detail)
			}
		}
		if f.Kind == "unkeyed_header" {
			t.Fatal("a parser rejection was promoted to a gadget")
		}
	}
	if !rejected {
		t.Fatalf("no target_rejected finding: %+v", res.Findings)
	}
}

type rejectingFuzzMock struct{ requests atomic.Int32 }

func (m *rejectingFuzzMock) serve(conn net.Conn) {
	defer conn.Close()
	req, err := readGadgetRequest(conn)
	if err != nil {
		return
	}
	m.requests.Add(1)
	if _, mutated := req.headers["transfer-encoding"]; mutated {
		writeGadgetResponse(conn, 400, nil, "rejected")
		return
	}
	writeGadgetResponse(conn, 200, nil, `{"ok":true}`)
}

func TestDifferentialFuzzStopsOnTargetRejected(t *testing.T) {
	mock := &rejectingFuzzMock{}
	p := &DifferentialFuzzProbe{
		Mutations:    []string{"chunk_extensions"},
		Pairs:        1,
		Hold:         time.Millisecond,
		JitterMaxIQR: time.Second, // loopback timing must not gate this verdict
		Timeout:      time.Second,
	}
	res, err := p.ExecuteMulti(context.Background(),
		Target{Addr: "lab.test:80", Host: "lab.test"}, &pipeGadgetSource{mock: mock})
	if err != nil {
		t.Fatal(err)
	}
	var rejected bool
	for _, f := range res.Findings {
		if f.Kind == FindingTargetRejected {
			rejected = true
			if !strings.Contains(f.Detail, "200 -> 400") {
				t.Fatalf("rejection detail = %q", f.Detail)
			}
		}
		if f.Kind == "differential_status" || f.Kind == "neighbor_shift" {
			t.Fatalf("parser rejection was treated as desync evidence: %+v", f)
		}
	}
	if !rejected {
		t.Fatalf("no target_rejected finding: %+v", res.Findings)
	}
}

func TestGadgetModeValidation(t *testing.T) {
	for _, mode := range []GadgetMode{"", GadgetChained, GadgetStandalone, GadgetUnkeyedCache} {
		if !mode.Valid() {
			t.Fatalf("mode %q should be valid", mode)
		}
	}
	if GadgetMode("unknown").Valid() {
		t.Fatal("unknown gadget mode was accepted")
	}
	p := &GadgetProbe{Mode: GadgetMode("unknown"), Headers: []string{"X-Host"}}
	if _, err := p.ExecuteMulti(context.Background(), Target{}, &pipeGadgetSource{mock: &gadgetMock{}}); err == nil {
		t.Fatal("unknown mode reached the wire")
	}
}

func TestRareMutationModesRotateWithoutLosingFraming(t *testing.T) {
	scope := acceptAllScope{}
	base := []byte("GET / HTTP/1.1\r\nHost: lab.test\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
	modes := []MutationMode{
		MutationOWSBeforeColon, MutationOWSInValue,
		MutationConflictingFraming, MutationChunkBoundaryExt,
	}
	m := &PayloadMutator{Scope: scope, Target: "lab.test:80", Modes: modes}
	seen := make(map[string]bool, len(modes))
	for seed := int64(0); seed < int64(len(modes)); seed++ {
		out, err := m.Mutate(base, seed)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		if bytes.Count(out, []byte("\r\n")) != bytes.Count(base, []byte("\r\n")) {
			t.Fatalf("seed %d changed the CRLF framing: %q", seed, out)
		}
		if !strings.Contains(strings.ToLower(string(out)), "transfer-encoding") {
			t.Fatalf("seed %d dropped the framing header: %q", seed, out)
		}
		seen[string(out)] = true
	}
	if len(seen) < 2 {
		t.Fatalf("explicit modes produced one identical payload: %d unique results", len(seen))
	}

	denied := &PayloadMutator{Scope: rejectAllScope{}, Target: "lab.test:80", Modes: modes}
	if _, err := denied.Mutate(base, 0); !errors.Is(err, ErrMutationScopeDenied) {
		t.Fatalf("scope denial = %v, want ErrMutationScopeDenied", err)
	}
}

type acceptAllScope struct{}

func (acceptAllScope) CheckTarget(context.Context, string) (string, error) { return "", nil }

type rejectAllScope struct{}

func (rejectAllScope) CheckTarget(context.Context, string) (string, error) {
	return "", errors.New("not in scope")
}
