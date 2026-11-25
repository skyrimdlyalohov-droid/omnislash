package omnislash

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestSemanticSupervisorRestartsChild proves the Wait -> 2 s -> restart loop.
// The fake analyzer answers one health check and then exits, like a Python
// sidecar killed by the OOM killer.
func TestSemanticSupervisorRestartsChild(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 is not available")
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "research"), 0o755); err != nil {
		t.Fatal(err)
	}
	script := `import argparse, http.server, os, threading

parser = argparse.ArgumentParser()
parser.add_argument("--addr", required=True)
args = parser.parse_args()
host, port = args.addr.rsplit(":", 1)

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            self.wfile.flush()
            # Give the Go health check time to read the response, then crash.
            threading.Timer(0.2, lambda: os._exit(0)).start()
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, *args):
        pass

http.server.ThreadingHTTPServer((host, int(port)), Handler).serve_forever()
`
	if err := os.WriteFile(filepath.Join(dir, "research", "semantic_service.py"), []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}

	addr := freeAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, err := StartSemanticService(ctx, addr, dir, testLogger())
	if err != nil {
		t.Fatalf("StartSemanticService: %v", err)
	}
	defer p.Close()

	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if p.Restarts() >= 1 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("semantic child was not restarted; restarts=%d", p.Restarts())
}

// TestSemanticCloseReleasesPort guards the one-shot exit path: Close must be
// synchronous, otherwise os.Exit can orphan the child and the next run loops
// forever on "address already in use".
func TestSemanticCloseReleasesPort(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 is not available")
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "research"), 0o755); err != nil {
		t.Fatal(err)
	}
	script := `import argparse, http.server
parser = argparse.ArgumentParser()
parser.add_argument("--addr", required=True)
args = parser.parse_args()
host, port = args.addr.rsplit(":", 1)
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass
http.server.ThreadingHTTPServer((host, int(port)), Handler).serve_forever()
`
	if err := os.WriteFile(filepath.Join(dir, "research", "semantic_service.py"), []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}
	addr := freeAddr(t)
	p, err := StartSemanticService(context.Background(), addr, dir, testLogger())
	if err != nil {
		t.Fatalf("StartSemanticService: %v", err)
	}
	p.Close()
	select {
	case <-p.Done():
	default:
		t.Fatal("Close returned before the supervisor stopped")
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("port %s still held after Close: %v", addr, err)
	}
	_ = ln.Close()
}
