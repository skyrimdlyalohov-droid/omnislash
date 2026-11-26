package probe

import (
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// A real Nginx error page for a broken chunked body. The front-end closes the
// client socket while the back-end is still waiting for the smuggled request.
const nginxInvalidChunkResponse = "HTTP/1.1 200 OK\r\n" +
	"Server: nginx/1.24.0\r\n" +
	"Date: Tue, 26 Nov 2026 10:00:00 GMT\r\n" +
	"Content-Type: text/html; charset=UTF-8\r\n" +
	"Content-Length: 196\r\n" +
	"Connection: close\r\n" +
	"\r\n" +
	"<html>\r\n<head><title>400 Bad Request</title></head>\r\n" +
	"<body><center><h1>400 Bad Request</h1></center>\r\n" +
	"<center><h2>invalid chunk size</h2></center>\r\n" +
	"<hr><center>nginx/1.24.0</center></body>\r\n</html>\r\n"

func TestAnalyzeDivergenceNginxInvalidChunk(t *testing.T) {
	machine := &ParserStateMachine{RequestHadTE: true}
	state := machine.AnalyzeDivergence([]byte(nginxInvalidChunkResponse), io.EOF)
	if state != FEClosedBEWaiting {
		t.Fatalf("state = %s, want %s", state, FEClosedBEWaiting)
	}
}

func TestAnalyzeDivergenceStates(t *testing.T) {
	tests := []struct {
		name  string
		raw   string
		err   error
		hadTE bool
		want  ParserState
	}{
		{"sync ok", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", nil, false, SyncOK},
		{"waf blocked", "HTTP/1.1 403 Forbidden\r\nServer: cloudflare\r\n\r\ncaptcha", nil, false, WAFBlocked},
		{"rate limited", "HTTP/1.1 429 Too Many Requests\r\n\r\n", nil, false, WAFBlocked},
		{"timeout", "", &probeTimeoutError{err: errors.New("deadline exceeded")}, true, EngineFault},
		{"network error", "", io.ErrUnexpectedEOF, false, EngineFault},
		{"empty with te", "", io.EOF, true, FEClosedBEWaiting},
		{"empty without te", "", io.EOF, false, EngineFault},
		{"nginx bad request", "HTTP/1.1 400 Bad Request\r\nServer: nginx\r\n\r\n<body>Bad Request</body>", io.EOF, true, FEClosedBEWaiting},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			machine := &ParserStateMachine{RequestHadTE: tt.hadTE}
			got := machine.AnalyzeDivergence([]byte(tt.raw), tt.err)
			if got != tt.want {
				t.Fatalf("state = %s, want %s", got, tt.want)
			}
		})
	}

	// A nil FSM is a local fault, never a silent SyncOK.
	var nilMachine *ParserStateMachine
	if got := nilMachine.AnalyzeDivergence([]byte(nginxInvalidChunkResponse), nil); got != EngineFault {
		t.Fatalf("nil FSM state = %s, want %s", got, EngineFault)
	}
}

type mutationTestConn struct {
	replyConn
	written []byte
}

func (c *mutationTestConn) Write(p []byte) (int, error) {
	c.written = append(c.written, p...)
	return len(p), nil
}

func TestMutationConnEscalatesDesyncToFinding(t *testing.T) {
	t.Setenv("OMNISLASH_PANIC_AUDIT", t.TempDir()+"/panic_audit.log")

	conn := &mutationTestConn{replyConn: replyConn{data: []byte(nginxInvalidChunkResponse)}}
	mc := newMutationConn(conn, testMutator(MutationCaseMixing, nil), 2, &ParserStateMachine{})
	req := []byte("POST /x HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n0\r\n\r\n")
	if _, err := mc.Write(req); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(string(conn.written)), "transfer-encoding") {
		t.Fatalf("raw write did not carry TE header: %q", conn.written)
	}

	buf := make([]byte, 4096)
	if _, err := mc.Read(buf); err != nil && !errors.Is(err, io.EOF) && !strings.Contains(err.Error(), "reply exhausted") {
		t.Fatalf("read: %v", err)
	}

	res := &Result{}
	if fault := mc.finish(res, nil); fault != nil {
		t.Fatalf("finish fault = %v", fault)
	}
	if res.ParserDivergence != string(FEClosedBEWaiting) {
		t.Fatalf("parser_divergence = %q, want %q", res.ParserDivergence, FEClosedBEWaiting)
	}
	found := false
	for _, f := range res.Findings {
		if f.Kind == "desync_confirmed" && f.Confidence == ConfidenceHigh {
			found = true
		}
	}
	if !found {
		t.Fatalf("findings = %+v, want high-confidence desync_confirmed", res.Findings)
	}
}

func TestRefusedMutationIsNotAParserDesync(t *testing.T) {
	t.Setenv("OMNISLASH_PANIC_AUDIT", t.TempDir()+"/panic_audit.log")

	conn := &mutationTestConn{replyConn: replyConn{}}
	fsm := &ParserStateMachine{RequestHadTE: true}
	mc := newMutationConn(conn, testMutator(MutationCaseMixing, nil), 2, fsm)
	// A refused mutation leaves no bytes on the wire. The recorded fault must
	// outrank an empty answer that would otherwise look like FE_Closed.
	mc.fault = errors.New("probe: payload contains bare CR or LF")

	res := &Result{}
	if fault := mc.finish(res, nil); fault == nil {
		t.Fatal("finish must report the refused mutation")
	}
	if res.ParserDivergence != string(EngineFault) {
		t.Fatalf("parser_divergence = %q, want %q", res.ParserDivergence, EngineFault)
	}
}

func TestMutationConnPassesThroughSplitTimingWrite(t *testing.T) {
	t.Setenv("OMNISLASH_PANIC_AUDIT", t.TempDir()+"/panic_audit.log")

	conn := &mutationTestConn{replyConn: replyConn{data: []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")}}
	mc := newMutationConn(conn, testMutator(MutationCaseMixing, nil), 2, &ParserStateMachine{})
	full := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n")
	split := len(full) - 1
	if _, err := mc.Write(full[:split]); err != nil {
		t.Fatal(err)
	}
	if _, err := mc.Write(full[split:]); err != nil {
		t.Fatal(err)
	}
	if string(conn.written) != string(full) {
		t.Fatalf("split write was rewritten: %q", conn.written)
	}

	buf := make([]byte, 4096)
	if _, err := mc.Read(buf); err != nil {
		t.Fatal(err)
	}
	res := &Result{}
	if fault := mc.finish(res, nil); fault != nil {
		t.Fatalf("finish fault = %v", fault)
	}
	if res.ParserDivergence != string(SyncOK) {
		t.Fatalf("parser_divergence = %q, want %q", res.ParserDivergence, SyncOK)
	}
}

func TestMutationConnPreservesTimingDesync(t *testing.T) {
	t.Setenv("OMNISLASH_PANIC_AUDIT", t.TempDir()+"/panic_audit.log")

	conn := &mutationTestConn{replyConn: replyConn{data: []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")}}
	mc := newMutationConn(conn, testMutator(MutationCaseMixing, nil), 2, &ParserStateMachine{})
	if _, err := mc.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	if _, err := mc.Read(buf); err != nil {
		t.Fatal(err)
	}

	res := &Result{ParserDivergence: string(TimingDesync), TimingDivergence: string(TimingDesync)}
	if fault := mc.finish(res, nil); fault != nil {
		t.Fatalf("finish fault = %v", fault)
	}
	if res.ParserDivergence != string(TimingDesync) {
		t.Fatalf("parser_divergence = %q, want %q", res.ParserDivergence, TimingDesync)
	}
}

func TestStrongParserVerdictSurvivesFailedConnection(t *testing.T) {
	t.Setenv("OMNISLASH_PANIC_AUDIT", t.TempDir()+"/panic_audit.log")

	req := []byte("POST /x HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
	good := &mutationTestConn{replyConn: replyConn{data: []byte(nginxInvalidChunkResponse)}}
	gmc := newMutationConn(good, testMutator(MutationCaseMixing, nil), 2, &ParserStateMachine{})
	if _, err := gmc.Write(req); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, maxMutationFSMBytes)
	if _, err := gmc.Read(buf); err != nil && !strings.Contains(err.Error(), "reply exhausted") {
		t.Fatal(err)
	}
	res := &Result{}
	if fault := gmc.finish(res, nil); fault != nil {
		t.Fatalf("first finish fault = %v", fault)
	}
	if res.ParserDivergence != string(FEClosedBEWaiting) {
		t.Fatalf("first verdict = %q", res.ParserDivergence)
	}

	bad := &mutationTestConn{replyConn: replyConn{}}
	bmc := newMutationConn(bad, testMutator(MutationCaseMixing, nil), 2, &ParserStateMachine{})
	if fault := bmc.finish(res, nil); fault != nil {
		t.Fatalf("second finish fault = %v", fault)
	}
	if res.ParserDivergence != string(FEClosedBEWaiting) {
		t.Fatalf("aggregated verdict = %q, want %q", res.ParserDivergence, FEClosedBEWaiting)
	}
}

func TestMutationConnNeverRewritesBinaryFrames(t *testing.T) {
	conn := &mutationTestConn{replyConn: replyConn{data: []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")}}
	mc := newMutationConn(conn, testMutator(MutationChunkExtensions, nil), 2, &ParserStateMachine{})
	frame := []byte{0x00, 0x00, 0x08, 0x01, 'H', 'T', 'T', 'P', '/', '1', '.', '1'}
	if _, err := mc.Write(frame); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(conn.written), "\x00\x00\x08\x01") {
		t.Fatalf("binary frame was rewritten: %v", conn.written)
	}
}

func TestParserStateStringValues(t *testing.T) {
	want := map[ParserState]string{
		SyncOK:            "SyncOK",
		FEClosedBEWaiting: "FE_Closed_BE_Waiting",
		WAFBlocked:        "WAF_Blocked",
		EngineFault:       "Engine_Fault",
		TimingDesync:      "Timing_Desync",
	}
	for state, label := range want {
		if string(state) != label {
			t.Fatalf("state = %q, want %q", state, label)
		}
	}
}

func TestParserDoesNotScanUnboundedResponse(t *testing.T) {
	machine := &ParserStateMachine{}
	// A response larger than the scan cap must still be classified promptly.
	raw := strings.Repeat("x", maxParserScanBytes+1000)
	start := time.Now()
	if got := machine.AnalyzeDivergence([]byte(raw), nil); got != SyncOK {
		t.Fatalf("state = %s, want SyncOK", got)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("FSM scan took too long")
	}
}
