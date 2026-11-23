#!/usr/bin/env bash
# Local 0-day incubator: run differential-fuzz against local docker stacks with zero marginal cost.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

STACKS="${STACKS:-nginx,envoy,haproxy}"
SKIP_DOCKER=0
RUNS_DIR="${RUNS_DIR:-$ROOT/runs}"
STATE_DIR="${STATE_DIR:-$ROOT/state}"
VAULT="${VAULT:-$STATE_DIR/zero_day_vault.json}"

usage() {
  cat <<'USAGE'
Usage: lab/run-incubator.sh [options]
  --stacks <csv>      Stacks to target (nginx,envoy,haproxy) default: nginx,envoy,haproxy
  --skip-docker       Do not run docker compose
  --vault <path>      Zero-day vault path (default: state/zero_day_vault.json)
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --stacks) STACKS="$2"; shift 2;;
    --skip-docker) SKIP_DOCKER=1; shift;;
    --vault) VAULT="$2"; shift 2;;
    -h|--help) usage; exit 0;;
    *) echo "unknown arg: $1" >&2; usage; exit 2;;
  esac
done

mkdir -p "$RUNS_DIR" "$STATE_DIR"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="$RUNS_DIR/incubate_${TS}"
mkdir -p "$RUN_DIR"
log() { printf '[incubate] %s\n' "$*"; }

if [[ "$SKIP_DOCKER" -eq 0 ]]; then
  if command -v docker >/dev/null 2>&1; then
    log "Starting local stacks (docker compose)"
    docker compose -f "$ROOT/sandbox/docker-compose.stacks.yml" up -d >/dev/null 2>&1 || log "docker compose up failed (continuing if stacks already up)"
  else
    log "docker not found; skipping compose"
  fi
fi

# Minimal trusted local-only omnislash config
cat > "$RUN_DIR/omnislash.config.json" <<'JSON'
{
  "default_scheme": "socks5",
  "strategy": "round_robin",
  "trust_tier": "trusted",
  "allow_direct": true,
  "scope": {
    "enabled": true,
    "allow_hosts": ["127.0.0.1"],
    "allow_ports": [18080,18081,18082,18001,18002],
    "allow_private": true,
    "resolve_locally": true
  },
  "audit": {"enabled": true, "path": "RUN_DIR/omnislash-audit.jsonl"},
  "safety": {"enabled": false}
}
JSON
python3 - "$RUN_DIR/omnislash.config.json" "$RUN_DIR/omnislash-audit.jsonl" <<'PY'
import json,sys
p,a=sys.argv[1],sys.argv[2]
obj=json.load(open(p))
obj['audit']['path']=a
json.dump(obj,open(p,'w'),indent=2)
PY

# Generate differential-fuzz jobs for selected stacks
python3 - "$RUN_DIR/jobs.json" "$RUN_DIR/omnislash.config.json" "$RUN_DIR/omnislashd-audit.jsonl" "$STACKS" <<'PY'
import json,sys
out,cfg,audit,stacks=sys.argv[1:5]
stacks=[s.strip().lower() for s in stacks.split(',') if s.strip()]
map_ports={
  'nginx': {'port':18080,'tech':['nginx','python','h1.1']},
  'envoy': {'port':18082,'tech':['envoy','python','h2']},
  'haproxy':{'port':18081,'tech':['haproxy','node','h1.1']},
}
jobs=[]
for s in stacks:
    if s not in map_ports: continue
    m=map_ports[s]
    jobs.append({
      'name':f'incubate-{s}-diff',
      'enabled':True,
      'target':{'addr':f'127.0.0.1:{m["port"]}','host':'127.0.0.1','path':'/'},
      'tls':'none','probe':'differential-fuzz','pairs':5,'attempts':1,
      'timeout':'5s','idle':'500ms','interval':'1s','until_success':False,
      'tech_stack':m['tech'],
      'metadata':{'tech_stack_hash':'+'.join(m['tech'])}
    })
cfg_obj={
  'omnislash_config':cfg,'proxies':'','log_file':audit,'poll_interval':'1s','concurrency':1,
  'exit_on_success':False,'jobs':jobs,
  'generated_scope':{'allow_hosts':['127.0.0.1'],'allow_private':True}
}
json.dump(cfg_obj,open(out,'w'),indent=2)
print(json.dumps({'jobs':len(jobs)}))
PY

log "Building omnislashd"
mkdir -p "$ROOT/bin"
[[ -x "$ROOT/bin/omnislashd" ]] || (cd "$ROOT" && go build -trimpath -o "$ROOT/bin/omnislashd" ./cmd/omnislashd)

log "Running omnislashd -once"
"$ROOT/bin/omnislashd" -config "$RUN_DIR/jobs.json" -once > "$RUN_DIR/omnislashd.stdout.log" 2>&1 || true

log "Analyzing with oracle and updating vault"
python3 - "$RUN_DIR/omnislashd-audit.jsonl" "$VAULT" <<'PY'
import json,sys,os,base64,hashlib
audit_path,vault_path=sys.argv[1],sys.argv[2]
sys.path.insert(0, os.getcwd())
from research.knowledge_base import load_vault, save_vault, add_universal_key
try:
    from research.oracle import evaluate_differential
except Exception:
    evaluate_differential=None

records=[]
if os.path.exists(audit_path):
    for line in open(audit_path,encoding='utf-8',errors='replace'):
        line=line.strip()
        if not line: continue
        try: records.append(json.loads(line))
        except Exception: pass
vault=load_vault(vault_path)
added=0
for rec in records:
    if not rec.get('success'):
        # differential-fuzz may report findings without success flag; inspect findings
        pass
    findings=rec.get('findings') or []
    has_signal=any(f.get('kind') in {'differential_status','neighbor_shift','differential_ttfb'} for f in findings if isinstance(f,dict))
    if not has_signal:
        continue
    # extract a representative request as universal key candidate
    res=rec.get('result') or {}
    exchanges=res.get('exchanges') or []
    raw=b''
    for ex in exchanges:
        if isinstance(ex,dict) and ex.get('raw'):
            raw=ex['raw'].encode('latin1',errors='ignore')
            break
    if not raw:
        continue
    tech=(rec.get('result') or {}).get('tech_stack') or []
    # fallback tech from job metadata unavailable here; infer from target port in job name
    job=rec.get('job','')
    if 'nginx' in job: tech=['nginx','python','h1.1']
    elif 'envoy' in job: tech=['envoy','python','h2']
    elif 'haproxy' in job: tech=['haproxy','node','h1.1']
    entry=add_universal_key(vault, raw, mutation_type='differential-fuzz', protocol_edge='http1', tech_stack=tech, source='incubator', confidence=0.9, metadata={'job':job})
    added+=1
if added:
    save_vault(vault,vault_path)
print(json.dumps({'added':added,'vault':vault_path}))
PY

log "Done. Run dir: $RUN_DIR"