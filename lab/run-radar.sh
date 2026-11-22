#!/usr/bin/env bash
# OmniSlash Echelon 1 radar: diff targets -> plan only-diff -> run pipeline -> verify -> notify
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TARGET=""
BASE_CONFIG="${BASE_CONFIG:-$ROOT/config.example.json}"
PROXIES="${PROXIES:-$ROOT/lab/no-proxies.txt}"
RUNS_DIR="${RUNS_DIR:-$ROOT/runs}"
STATE_DIR="${STATE_DIR:-$ROOT/state}"
HTTPX_JSON=""
CAIDO_AUTH=""
CAIDO_URL="${CAIDO_URL:-}"
CAIDO_PAT="${CAIDO_PAT:-}"
SKIP_DAEMON=0
SKIP_NOTIFY=0

usage() {
  cat <<'USAGE'
Usage: lab/run-radar.sh --target <domain> [options]
Options:
  --target <domain>      Target domain (required)
  --httpx-json <file>    Optional httpx enrichment
  --caido-auth <file>    Optional Caido auth export
  --caido-url <url>      Caido GraphQL URL
  --caido-pat <token>    Caido PAT
  --base-config <file>   Base omnislash config
  --proxies <file>       Proxy list
  --runs-dir <dir>       Runs dir (default ./runs)
  --state-dir <dir>      State dir (default ./state)
  --skip-daemon          Skip omnislashd execution
  --skip-notify          Skip Telegram/Caido notifier
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) TARGET="$2"; shift 2;;
    --httpx-json) HTTPX_JSON="$2"; shift 2;;
    --caido-auth) CAIDO_AUTH="$2"; shift 2;;
    --caido-url) CAIDO_URL="$2"; shift 2;;
    --caido-pat) CAIDO_PAT="$2"; shift 2;;
    --base-config) BASE_CONFIG="$2"; shift 2;;
    --proxies) PROXIES="$2"; shift 2;;
    --runs-dir) RUNS_DIR="$2"; shift 2;;
    --state-dir) STATE_DIR="$2"; shift 2;;
    --skip-daemon) SKIP_DAEMON=1; shift;;
    --skip-notify) SKIP_NOTIFY=1; shift;;
    -h|--help) usage; exit 0;;
    *) echo "unknown arg: $1" >&2; usage; exit 2;;
  esac
done

[[ -n "$TARGET" ]] || { echo "--target required" >&2; usage; exit 2; }

mkdir -p "$STATE_DIR" "$RUNS_DIR"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
SAFE_TARGET="$(echo "$TARGET" | tr '/:*?"<>| ' '_' | tr -cd 'A-Za-z0-9._-')"
RUN_DIR="$RUNS_DIR/radar_${TS}_${SAFE_TARGET}"
mkdir -p "$RUN_DIR"
PREV="$STATE_DIR/targets_prev.json"
CUR="$RUN_DIR/targets_verified.json"
DIFF="$RUN_DIR/targets_diff.json"

log() { printf '[radar] %s\n' "$*"; }

log "Phase 1: OSINT enrichment"
ENGINE_ARGS=(--domain "$TARGET" --out "$CUR")
[[ -n "$HTTPX_JSON" ]] && ENGINE_ARGS+=(--httpx-json "$HTTPX_JSON")
[[ -n "$CAIDO_AUTH" ]] && ENGINE_ARGS+=(--caido-auth "$CAIDO_AUTH")
python3 "$ROOT/osint/engine.py" "${ENGINE_ARGS[@]}" > "$RUN_DIR/engine.stdout.log"

log "Phase 2: Diff scan"
python3 "$ROOT/osint/diff_scanner.py" --current "$CUR" --previous "$PREV" --out "$DIFF" --stats-out "$RUN_DIR/diff-stats.json" > "$RUN_DIR/diff.stdout.log"

log "Phase 3: Planner (only-diff)"
python3 "$ROOT/osint/planner.py" --in "$DIFF" --out "$RUN_DIR/jobs.json" --omnislash-config "$RUN_DIR/omnislash.config.json" --log-file "$RUN_DIR/omnislashd-audit.jsonl" --only-diff > "$RUN_DIR/planner.stdout.log"

# Build transport config from base
python3 - "$BASE_CONFIG" "$RUN_DIR/jobs.json" "$RUN_DIR/omnislash.config.json" "$RUN_DIR/omnislash-audit.jsonl" <<'PY'
import json, sys
base, jobs_path, out, audit_path = sys.argv[1:5]
with open(base) as f: cfg = json.load(f)
with open(jobs_path) as f: jobs = json.load(f)
scope = jobs.get("generated_scope", {})
cfg.setdefault("scope", {})
cfg["scope"]["enabled"] = True
cfg["scope"]["allow_hosts"] = scope.get("allow_hosts", [])
cfg["scope"].setdefault("allow_ports", [80,443])
cfg["scope"]["allow_private"] = bool(cfg["scope"].get("allow_private", False))
cfg.setdefault("gateway", {})
cfg["gateway"].setdefault("listen", "127.0.0.1:3128")
cfg["gateway"]["proxy_pin_header"] = cfg["gateway"].get("proxy_pin_header") or "X-Omnislash-Proxy"
cfg.setdefault("safety", {})
cfg["safety"]["enabled"] = True
cfg["safety"].setdefault("deception", {})
cfg["safety"]["deception"]["enabled"] = True
cfg.setdefault("audit", {})
cfg["audit"]["enabled"] = True
cfg["audit"]["path"] = audit_path
with open(out, "w") as f: json.dump(cfg, f, indent=2, ensure_ascii=False); f.write("\n")
PY

if [[ "$SKIP_DAEMON" -eq 0 ]]; then
  log "Phase 4: omnislashd -once"
  mkdir -p "$ROOT/bin"
  [[ -x "$ROOT/bin/omnislashd" ]] || (cd "$ROOT" && go build -trimpath -o "$ROOT/bin/omnislashd" ./cmd/omnislashd)
  "$ROOT/bin/omnislashd" -config "$RUN_DIR/jobs.json" -once > "$RUN_DIR/omnislashd.stdout.log" 2>&1 || true
else
  log "Phase 4: omnislashd skipped"
fi

log "Phase 5: Verify (2 cross-proxy confirmations required)"
if [[ -f "$RUN_DIR/omnislashd-audit.jsonl" ]]; then
  python3 "$ROOT/research/verifier.py" --in "$RUN_DIR/omnislashd-audit.jsonl" --out "$RUN_DIR/verified.json" --min-verifications 2 > "$RUN_DIR/verifier.stdout.log" || true
else
  echo '[]' > "$RUN_DIR/verified.json"
fi

if [[ "$SKIP_NOTIFY" -eq 0 ]]; then
  log "Phase 6: Notify (confidence>=85, 2 cross-proxy verifications)"
  [[ -n "$CAIDO_URL" ]] && export CAIDO_URL
  [[ -n "$CAIDO_PAT" ]] && export CAIDO_PAT
  python3 "$ROOT/osint/notifier.py" --in "$RUN_DIR/verified.json" --out "$RUN_DIR/notify.json" --min-confidence 85 > "$RUN_DIR/notifier.stdout.log" || true
else
  log "Phase 6: Notify skipped"
fi

cp "$CUR" "$PREV"
log "Done. Run dir: $RUN_DIR"
