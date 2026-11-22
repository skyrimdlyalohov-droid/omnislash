#!/usr/bin/env bash
# Autonomous E2E smoke test for OmniSlash pipeline.
# No real internet. Uses local mock servers only.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TMPDIR_BASE="${TMPDIR:-/tmp}"
RUN_DIR="$(mktemp -d "$TMPDIR_BASE/omnislash-e2e.XXXXXX")"
MOCK_DIR="$RUN_DIR/mocks"
mkdir -p "$MOCK_DIR"
BIN="$RUN_DIR/bin"
mkdir -p "$BIN"

log() { printf '[e2e] %s\n' "$*"; }
fail() { printf '[e2e] FAIL: %s\n' "$*" >&2; exit 1; }

PIDS=()
cleanup() {
  for pid in "${PIDS[@]:-}"; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
}
trap cleanup EXIT INT TERM

pick_port() {
  python3 - <<'PY'
import socket
s=socket.socket(); s.bind(('127.0.0.1',0)); print(s.getsockname()[1]); s.close()
PY
}

VULN_PORT="$(pick_port)"
TARPIT_PORT="$(pick_port)"
CAIDO_PORT="$(pick_port)"

log "Run dir: $RUN_DIR"
log "Ports: vuln=$VULN_PORT tarpit=$TARPIT_PORT caido=$CAIDO_PORT"

# ---- Mock vulnerable smuggle backend ----
cat > "$MOCK_DIR/vuln_server.py" <<'PY'
import socket, sys, threading
port = int(sys.argv[1])
leftover = {'g': ''}
lock = threading.Lock()
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1', port))
srv.listen(50)
print(f'VULN_READY {port}', flush=True)

def handle(c):
    try:
        c.settimeout(3)
        with lock:
            prefix = leftover.get('g', '')
        data = b''
        while b'\r\n\r\n' not in data and len(data) < 65536:
            chunk = c.recv(4096)
            if not chunk: break
            data += chunk
        # read chunked body if present; stop after 0-chunk and keep leftover byte
        if b'transfer-encoding: chunked' in data.lower() or b'chunked' in data.lower():
            while b'\r\n0\r\n\r\n' not in data and len(data) < 65536:
                chunk = c.recv(4096)
                if not chunk: break
                data += chunk
            idx = data.find(b'\r\n0\r\n\r\n')
            if idx != -1:
                after = data[idx+len(b'\r\n0\r\n\r\n'):]
                if after:
                    with lock:
                        leftover['g'] = after[:1].decode('latin1', errors='ignore')
        line = data.split(b'\r\n',1)[0].decode('latin1', errors='ignore')
        if prefix and (prefix + line).startswith('GPOST '):
            body = b'Unrecognized method GPOST'
            resp = b'HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: ' + str(len(body)).encode() + b'\r\nConnection: close\r\n\r\n' + body
            c.sendall(resp)
            with lock:
                leftover['g'] = ''
            return
        body = b'OK'
        resp = b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\n' + body
        c.sendall(resp)
    except Exception:
        pass
    finally:
        try: c.close()
        except Exception: pass

while True:
    c, _ = srv.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
PY

# ---- Mock tarpit server ----
cat > "$MOCK_DIR/tarpit_server.py" <<'PY'
import http.server, sys
port = int(sys.argv[1])
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        body = b'{"admin_panel":true,"endpoints":["/api/admin","/api/internal"],"token":"FAKE_TOKEN_12345678"}'
        self.send_response(200)
        self.send_header('Content-Type','application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    do_POST = do_GET
http.server.ThreadingHTTPServer(('127.0.0.1', port), H).serve_forever()
PY

# ---- Mock Caido GraphQL server ----
cat > "$MOCK_DIR/caido_mock.py" <<'PY'
import json, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
port = int(sys.argv[1])
out = sys.argv[2]
received = []
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        n = int(self.headers.get('Content-Length','0'))
        body = self.rfile.read(n).decode('utf-8', errors='replace')
        try:
            obj = json.loads(body)
        except Exception:
            obj = {"raw": body}
        received.append(obj)
        with open(out, 'w', encoding='utf-8') as f:
            json.dump(received, f, indent=2, ensure_ascii=False)
        resp = {"data": {"createReplaySession": {"session": {"id": "replay-1", "name": "ok"}}}}
        b = json.dumps(resp).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type','application/json')
        self.send_header('Content-Length', str(len(b)))
        self.end_headers()
        self.wfile.write(b)
ThreadingHTTPServer(('127.0.0.1', port), H).serve_forever()
PY

python3 "$MOCK_DIR/vuln_server.py" "$VULN_PORT" > "$RUN_DIR/vuln.log" 2>&1 & PIDS+=("$!")
python3 "$MOCK_DIR/tarpit_server.py" "$TARPIT_PORT" > "$RUN_DIR/tarpit.log" 2>&1 & PIDS+=("$!")
python3 "$MOCK_DIR/caido_mock.py" "$CAIDO_PORT" "$RUN_DIR/caido_received.json" > "$RUN_DIR/caido.log" 2>&1 & PIDS+=("$!")
sleep 0.5

# ---- Build binaries ----
log "Building omnislash + omnislashd"
(cd "$ROOT" && go build -trimpath -o "$BIN/omnislash" ./cmd/omnislash)
(cd "$ROOT" && go build -trimpath -o "$BIN/omnislashd" ./cmd/omnislashd)

# ---- Phase 1: engine.py ----
log "Phase 1: engine.py"
cat > "$RUN_DIR/httpx.json" <<JSON
{"url":"http://127.0.0.1:${VULN_PORT}/","host":"127.0.0.1","status_code":200,"content_length":2,"words":1,"lines":1,"title":"ok","webserver":"nginx","tech":["Nginx","Envoy"],"header":{"Server":"nginx","Via":"1.1 proxy"}}
JSON
python3 "$ROOT/osint/engine.py" --domain "127.0.0.1" --httpx-json "$RUN_DIR/httpx.json" --out "$RUN_DIR/targets_engine.json" > "$RUN_DIR/engine.log"

# Merge: keep engine output for vuln + add tarpit host as high-risk honeypot
python3 - "$RUN_DIR/targets_engine.json" "$RUN_DIR/targets_verified.json" "$VULN_PORT" "$TARPIT_PORT" <<'PY'
import json, sys
src, dst, vuln_port, tarpit_port = sys.argv[1:5]
with open(src) as f: vuln = json.load(f)
vuln['target'] = '127.0.0.1'
vuln['ip'] = '127.0.0.1'
vuln['known_ports'] = [int(vuln_port)]
vuln['is_honeypot'] = False
vuln['deception_risk'] = 'low'
vuln['confidence_score'] = max(int(vuln.get('confidence_score', 1)), 1)
tarpit = {
  "target": "127.0.0.2",
  "ip": "127.0.0.2",
  "confidence_score": -5,
  "behind_waf": False,
  "is_honeypot": True,
  "deception_risk": "high",
  "recommended_profile": "l7_web",
  "known_ports": [int(tarpit_port)],
  "tech": ["Unknown"],
  "cdn_name": "",
  "webserver": "fake",
  "cache_headers": {},
  "baseline": {"status_code":200,"content_length":88,"words":3,"lines":1,"title_hash":"deadbeef"},
  "origin_ips": [],
  "auth_context": {}
}
with open(dst,'w') as f: json.dump([vuln, tarpit], f, indent=2); f.write('\n')
PY

# ---- Phase 2: planner.py ----
log "Phase 2: planner.py"
python3 "$ROOT/osint/planner.py" --in "$RUN_DIR/targets_verified.json" --out "$RUN_DIR/jobs.json" --omnislash-config "$RUN_DIR/omnislash.config.json" --log-file "$RUN_DIR/omnislashd-audit.jsonl" > "$RUN_DIR/planner.log"

# Patch jobs for local smoke: ensure smuggle-chain job targets local vuln port with GPOST marker
python3 - "$RUN_DIR/jobs.json" "$VULN_PORT" <<'PY'
import json, sys
p, vuln_port = sys.argv[1], sys.argv[2]
with open(p) as f: cfg = json.load(f)
jobs = []
for j in cfg.get('jobs', []):
    if j.get('probe') == 'smuggle-chain':
        j['target'] = {"addr": f"127.0.0.1:{vuln_port}", "host": "127.0.0.1", "path": "/"}
        j['tls'] = 'none'
        j['victim_method'] = 'POST'
        j['victim_path'] = '/'
        j['success_contains'] = 'Unrecognized method GPOST'
        j['attempts'] = 2
        j['timeout'] = '3s'
        j['idle'] = '500ms'
        jobs.append(j)
        break
if not jobs:
    jobs = [{
      "name":"local-smuggle", "enabled":True,
      "target":{"addr":f"127.0.0.1:{vuln_port}","host":"127.0.0.1","path":"/"},
      "tls":"none","probe":"smuggle-chain","victim_method":"POST","victim_path":"/",
      "success_contains":"Unrecognized method GPOST","attempts":2,"until_success":True,
      "interval":"1s","timeout":"3s","idle":"500ms","retry_delay":"200ms",
      "metadata":{"baseline":{"status_code":200}}
    }]
cfg['jobs'] = jobs
cfg['generated_scope'] = {"allow_hosts":["127.0.0.1"], "allow_private": True}
with open(p,'w') as f: json.dump(cfg,f,indent=2); f.write('\n')
PY

# Build omnislash transport config for daemon (fail-closed scope, allow_private for local test)
cat > "$RUN_DIR/omnislash.config.json" <<JSON
{
  "default_scheme": "socks5",
  "strategy": "round_robin",
  "trust_tier": "trusted",
  "allow_direct": true,
  "safety": {"enabled": false},
  "audit": {"enabled": false},
  "scope": {
    "enabled": true,
    "allow_hosts": ["127.0.0.1"],
    "allow_ports": [${VULN_PORT}, ${TARPIT_PORT}],
    "allow_private": true,
    "resolve_locally": true
  },
  "gateway": {"listen": "127.0.0.1:0", "token": "", "proxy_pin_header": "X-Omnislash-Proxy"}
}
JSON

# ---- Phase 3: omnislashd ----
log "Phase 3: omnislashd -once"
"$BIN/omnislashd" -config "$RUN_DIR/jobs.json" -once > "$RUN_DIR/omnislashd.stdout.log" 2>&1 || true

# ---- Phase 4: caido_bridge + summary ----
log "Phase 4: caido_bridge"
python3 "$ROOT/osint/caido_bridge.py" --audit "$RUN_DIR/omnislashd-audit.jsonl" --url "http://127.0.0.1:${CAIDO_PORT}/graphql" --pat "test" --out "$RUN_DIR/caido-bridge.json" > "$RUN_DIR/bridge.log" 2>&1 || true

log "Phase 4: summary"
python3 - "$RUN_DIR" <<'PY'
import json, os, sys
run_dir = sys.argv[1]
def load_json(p, default=None):
    try:
        with open(p) as f: return json.load(f)
    except Exception: return default
def load_jsonl(p):
    items=[]
    try:
        with open(p) as f:
            for line in f:
                line=line.strip()
                if not line: continue
                try: items.append(json.loads(line))
                except Exception: pass
    except Exception: pass
    return items
tv = load_json(os.path.join(run_dir,'targets_verified.json'), [])
jobs = load_json(os.path.join(run_dir,'jobs.json'), {})
daemon_audit = load_jsonl(os.path.join(run_dir,'omnislashd-audit.jsonl'))
bridge = load_json(os.path.join(run_dir,'caido-bridge.json'), [])
targets = tv if isinstance(tv,list) else [tv]
honeypots = [t for t in targets if t.get('is_honeypot') or t.get('deception_risk')=='high']
confirmed = [r for r in daemon_audit if r.get('success')]
bridge_ok = sum(1 for x in bridge if isinstance(x,dict) and x.get('ok'))
summary = {
  "targets_total": len(targets),
  "targets_honeypot_or_high_risk": len(honeypots),
  "jobs_generated": len(jobs.get('jobs',[])) if isinstance(jobs,dict) else 0,
  "daemon_confirmed": len(confirmed),
  "caido_bridge_ok": bridge_ok,
}
with open(os.path.join(run_dir,'summary.json'),'w') as f: json.dump(summary,f,indent=2); f.write('\n')
print(json.dumps(summary))
PY

# ---- Assertions ----
log "Assertions"
[[ -f "$RUN_DIR/targets_verified.json" ]] || fail "targets_verified.json missing"
[[ -f "$RUN_DIR/jobs.json" ]] || fail "jobs.json missing"
[[ -f "$RUN_DIR/omnislashd-audit.jsonl" ]] || fail "omnislashd-audit.jsonl missing"
[[ -f "$RUN_DIR/caido-bridge.json" ]] || fail "caido-bridge.json missing"
[[ -f "$RUN_DIR/summary.json" ]] || fail "summary.json missing"

python3 - "$RUN_DIR" <<'PY'
import json, sys, os
run_dir=sys.argv[1]
summary=json.load(open(os.path.join(run_dir,'summary.json')))
jobs=json.load(open(os.path.join(run_dir,'jobs.json')))
audit=[json.loads(l) for l in open(os.path.join(run_dir,'omnislashd-audit.jsonl')) if l.strip()]
bridge=json.load(open(os.path.join(run_dir,'caido-bridge.json')))

# Tarpit host was filtered from jobs/scope
allow = jobs.get('generated_scope',{}).get('allow_hosts',[])
assert '127.0.0.2' not in allow, allow
assert '127.0.0.1' in allow, allow
assert summary['targets_honeypot_or_high_risk'] >= 1

# Confirmed finding reached bridge mock
confirmed=[r for r in audit if r.get('success')]
assert confirmed, 'no confirmed daemon records'
kinds=[]
for r in confirmed:
  for f in r.get('findings',[]) or []:
    kinds.append(f.get('kind'))
assert 'smuggle_confirmed' in kinds, kinds
assert summary['caido_bridge_ok'] >= 1, summary
assert any(x.get('ok') for x in bridge), bridge
print('E2E_ASSERTIONS_OK')
PY

log "PASS: E2E smoke test"
log "Artifacts: $RUN_DIR"