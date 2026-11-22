#!/usr/bin/env bash
# OmniSlash end-to-end pipeline: OSINT -> Planner -> Gateway/Recon -> omnislashd -> Caido bridge -> summary
# Safe by default: fail-closed scope, local gateway, no evasion logic.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TARGET=""
SCOPE_FILE=""
HTTPX_JSON=""
CAIDO_AUTH=""
CAIDO_URL="${CAIDO_URL:-http://127.0.0.1:8080/graphql}"
CAIDO_PAT="${CAIDO_PAT:-}"
NUCLEI_TARGETS=""
SKIP_NUCLEI=1
SKIP_CAIDO=0
SKIP_DAEMON=0
GATEWAY_LISTEN="${GATEWAY_LISTEN:-127.0.0.1:3128}"
GATEWAY_STATS="${GATEWAY_STATS:-127.0.0.1:9090}"
BASE_CONFIG="${BASE_CONFIG:-$ROOT/config.example.json}"
PROXIES="${PROXIES:-$ROOT/lab/no-proxies.txt}"
RUNS_DIR="${RUNS_DIR:-$ROOT/runs}"

usage() {
  cat <<'USAGE'
Usage: lab/run-pipeline.sh --target <domain> [options]

Options:
  --target <domain>        Target domain (required unless --scope-file given)
  --scope-file <file>      File with targets (one per line); first target used for run name
  --httpx-json <file>      Optional httpx JSON/JSONL enrichment
  --caido-auth <file>      Optional Caido export JSON for auth context
  --caido-url <url>        Caido GraphQL URL (default: http://127.0.0.1:8080/graphql)
  --caido-pat <token>      Caido PAT (or env CAIDO_PAT)
  --nuclei-targets <file>  Targets file for Nuclei (enables Nuclei stage)
  --skip-nuclei            Skip Nuclei (default)
  --run-nuclei             Enable Nuclei stage (requires --nuclei-targets)
  --skip-caido             Skip Caido bridge
  --skip-daemon            Skip omnislashd execution
  --base-config <file>     Base omnislash config (default: config.example.json)
  --proxies <file>         Proxy list file (default: lab/no-proxies.txt)
  --runs-dir <dir>         Runs directory (default: ./runs)
  -h, --help               Show help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) TARGET="$2"; shift 2;;
    --scope-file) SCOPE_FILE="$2"; shift 2;;
    --httpx-json) HTTPX_JSON="$2"; shift 2;;
    --caido-auth) CAIDO_AUTH="$2"; shift 2;;
    --caido-url) CAIDO_URL="$2"; shift 2;;
    --caido-pat) CAIDO_PAT="$2"; shift 2;;
    --nuclei-targets) NUCLEI_TARGETS="$2"; shift 2;;
    --skip-nuclei) SKIP_NUCLEI=1; shift;;
    --run-nuclei) SKIP_NUCLEI=0; shift;;
    --skip-caido) SKIP_CAIDO=1; shift;;
    --skip-daemon) SKIP_DAEMON=1; shift;;
    --base-config) BASE_CONFIG="$2"; shift 2;;
    --proxies) PROXIES="$2"; shift 2;;
    --runs-dir) RUNS_DIR="$2"; shift 2;;
    -h|--help) usage; exit 0;;
    *) echo "unknown arg: $1" >&2; usage; exit 2;;
  esac
done

if [[ -z "$TARGET" && -n "$SCOPE_FILE" ]]; then
  TARGET="$(grep -vE '^\s*(#|$)' "$SCOPE_FILE" | head -n1 | tr -d '\r')"
fi
if [[ -z "$TARGET" ]]; then
  echo "--target or --scope-file required" >&2
  usage
  exit 2
fi

TS="$(date -u +%Y%m%dT%H%M%SZ)"
SAFE_TARGET="$(echo "$TARGET" | tr '/:*?\"<>| ' '_' | tr -cd 'A-Za-z0-9._-')"
RUN_DIR="$RUNS_DIR/${TS}_${SAFE_TARGET}"
mkdir -p "$RUN_DIR"

log() { printf '[pipeline] %s\n' "$*"; }
die() { printf '[pipeline] ERROR: %s\n' "$*" >&2; exit 1; }

GATEWAY_PID=""
cleanup() {
  if [[ -n "$GATEWAY_PID" ]]; then
    kill "$GATEWAY_PID" 2>/dev/null || true
    wait "$GATEWAY_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

log "Run dir: $RUN_DIR"
printf '%s\n' "$TARGET" > "$RUN_DIR/target.txt"

# ---- Phase 1: OSINT & Enrichment ----
log "Phase 1: OSINT enrichment"
ENGINE_ARGS=(--domain "$TARGET" --out "$RUN_DIR/targets_verified.json")
[[ -n "$HTTPX_JSON" ]] && ENGINE_ARGS+=(--httpx-json "$HTTPX_JSON")
[[ -n "$CAIDO_AUTH" ]] && ENGINE_ARGS+=(--caido-auth "$CAIDO_AUTH")
python3 "$ROOT/osint/engine.py" "${ENGINE_ARGS[@]}" > "$RUN_DIR/engine.stdout.log"

# ---- Phase 2: Planning & Scope Sync ----
log "Phase 2: Planner + scope sync"
python3 "$ROOT/osint/planner.py" --in "$RUN_DIR/targets_verified.json" --out "$RUN_DIR/jobs.json" --omnislash-config "$RUN_DIR/omnislash.config.json" --log-file "$RUN_DIR/omnislashd-audit.jsonl" > "$RUN_DIR/planner.stdout.log"

python3 - "$BASE_CONFIG" "$RUN_DIR/jobs.json" "$RUN_DIR/omnislash.config.json" "$GATEWAY_LISTEN" "$GATEWAY_STATS" "$RUN_DIR/omnislash-audit.jsonl" <<'PY'
import json, sys
base, jobs_path, out, gw_listen, gw_stats, audit_path = sys.argv[1:7]
with open(base) as f: cfg = json.load(f)
with open(jobs_path) as f: jobs = json.load(f)
scope = jobs.get("generated_scope", {})
allow_hosts = scope.get("allow_hosts", [])
cfg.setdefault("scope", {})
cfg["scope"]["enabled"] = True
cfg["scope"]["allow_hosts"] = allow_hosts
cfg["scope"].setdefault("allow_ports", [80,443])
cfg["scope"]["allow_private"] = bool(cfg["scope"].get("allow_private", False))
cfg.setdefault("gateway", {})
cfg["gateway"]["listen"] = gw_listen
cfg["gateway"]["proxy_pin_header"] = cfg["gateway"].get("proxy_pin_header") or "X-Omnislash-Proxy"
cfg.setdefault("stats", {})
cfg["stats"]["listen"] = gw_stats
cfg.setdefault("safety", {})
cfg["safety"]["enabled"] = True
cfg["safety"].setdefault("deception", {})
cfg["safety"]["deception"]["enabled"] = True
cfg["safety"]["deception"].setdefault("action", "cooldown")
cfg.setdefault("audit", {})
cfg["audit"]["enabled"] = True
cfg["audit"]["path"] = audit_path
with open(out, "w") as f: json.dump(cfg, f, indent=2, ensure_ascii=False); f.write("\n")
print(json.dumps({"allow_hosts": allow_hosts}))
PY

# ---- Phase 3: Active & Recon Execution ----
log "Phase 3: Gateway + recon + omnislashd"
mkdir -p "$ROOT/bin"
if [[ ! -x "$ROOT/bin/omnislash" ]]; then
  (cd "$ROOT" && go build -trimpath -o "$ROOT/bin/omnislash" ./cmd/omnislash) || die "failed to build omnislash"
fi
if [[ ! -x "$ROOT/bin/omnislashd" ]]; then
  (cd "$ROOT" && go build -trimpath -o "$ROOT/bin/omnislashd" ./cmd/omnislashd) || die "failed to build omnislashd"
fi

"$ROOT/bin/omnislash" serve -config "$RUN_DIR/omnislash.config.json" -proxies "$PROXIES" -no-health -listen "$GATEWAY_LISTEN" -stats "$GATEWAY_STATS" > "$RUN_DIR/gateway.log" 2>&1 &
GATEWAY_PID="$!"
for _ in $(seq 1 80); do
  if curl -fsS -o /dev/null --max-time 2 "http://$GATEWAY_STATS/stats" 2>/dev/null; then break; fi
  sleep 0.25
done

if [[ "$SKIP_NUCLEI" -eq 0 ]]; then
  if [[ -z "$NUCLEI_TARGETS" ]]; then
    log "Nuclei enabled but --nuclei-targets missing; skipping nuclei"
  elif command -v nuclei >/dev/null 2>&1; then
    log "Running Nuclei via Caido/Gateway chain (operator must ensure Caido upstream if used)"
    nuclei -l "$NUCLEI_TARGETS" -proxy "http://$GATEWAY_LISTEN" -rate-limit 4 -concurrency 1 -retries 0 \
      -jsonl -o "$RUN_DIR/nuclei.raw.jsonl" -nc -silent -disable-update-check -no-interactsh || true
    python3 "$ROOT/osint/filter_nuclei.py" --in "$RUN_DIR/nuclei.raw.jsonl" --out "$RUN_DIR/nuclei.clean.jsonl" --report "$RUN_DIR/nuclei.filter-report.json" || true
  else
    log "nuclei not installed; skipping"
  fi
else
  log "Nuclei stage skipped (default). Use --run-nuclei --nuclei-targets <file> to enable."
fi

if [[ "$SKIP_DAEMON" -eq 0 ]]; then
  log "Running omnislashd -once"
  "$ROOT/bin/omnislashd" -config "$RUN_DIR/jobs.json" -once > "$RUN_DIR/omnislashd.stdout.log" 2>&1 || true
else
  log "omnislashd stage skipped"
fi

# ---- Phase 4: Bridge & Summary ----
log "Phase 4: Caido bridge + summary"
BRIDGE_OK=0
BRIDGE_TOTAL=0
if [[ "$SKIP_CAIDO" -eq 0 && -f "$RUN_DIR/omnislashd-audit.jsonl" ]]; then
  python3 "$ROOT/osint/caido_bridge.py" --audit "$RUN_DIR/omnislashd-audit.jsonl" --url "$CAIDO_URL" --pat "$CAIDO_PAT" --out "$RUN_DIR/caido-bridge.json" > "$RUN_DIR/caido-bridge.stdout.log" 2>&1 || true
fi

python3 - "$RUN_DIR" <<'PY'
import json, os, sys, glob
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
tv = load_json(os.path.join(run_dir,'targets_verified.json'), {})
jobs = load_json(os.path.join(run_dir,'jobs.json'), {})
daemon_audit = load_jsonl(os.path.join(run_dir,'omnislashd-audit.jsonl'))
bridge = load_json(os.path.join(run_dir,'caido-bridge.json'), [])
nuclei_filter = load_json(os.path.join(run_dir,'nuclei.filter-report.json'), {})

targets = tv if isinstance(tv,list) else [tv] if isinstance(tv,dict) and tv else []
honeypots = [t for t in targets if t.get('is_honeypot') or t.get('deception_risk')=='high']
jobs_count = len(jobs.get('jobs', [])) if isinstance(jobs,dict) else 0
confirmed = [r for r in daemon_audit if r.get('success')]
quarantined = []
for r in daemon_audit:
    for fnd in r.get('findings',[]) or []:
        if fnd.get('unverified'):
            quarantined.append(fnd)
bridge_ok = sum(1 for x in bridge if isinstance(x,dict) and x.get('ok'))
summary = {
  "run_dir": run_dir,
  "targets_total": len(targets),
  "targets_honeypot_or_high_risk": len(honeypots),
  "jobs_generated": jobs_count,
  "daemon_records": len(daemon_audit),
  "daemon_confirmed": len(confirmed),
  "findings_quarantined_unverified": len(quarantined),
  "caido_bridge_sent": len(bridge) if isinstance(bridge,list) else 0,
  "caido_bridge_ok": bridge_ok,
  "nuclei_quarantined": nuclei_filter.get('quarantined_count', 0) if isinstance(nuclei_filter,dict) else 0,
}
with open(os.path.join(run_dir,'summary.json'),'w') as f: json.dump(summary,f,indent=2,ensure_ascii=False); f.write('\n')
md = f"""# OmniSlash Pipeline Summary

- Run dir: `{run_dir}`
- Targets total: **{summary['targets_total']}**
- Honeypot/high-risk filtered: **{summary['targets_honeypot_or_high_risk']}**
- Jobs generated: **{summary['jobs_generated']}**
- Daemon records: **{summary['daemon_records']}**
- Daemon confirmed: **{summary['daemon_confirmed']}**
- Findings quarantined (unverified): **{summary['findings_quarantined_unverified']}**
- Caido bridge sent/ok: **{summary['caido_bridge_sent']} / {summary['caido_bridge_ok']}**
- Nuclei quarantined: **{summary['nuclei_quarantined']}**
"""
with open(os.path.join(run_dir,'summary.md'),'w') as f: f.write(md)
print(json.dumps(summary, ensure_ascii=False))
PY

log "Done. Summary: $RUN_DIR/summary.json"