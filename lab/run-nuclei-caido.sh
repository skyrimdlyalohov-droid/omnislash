#!/usr/bin/env bash
# Nuclei -> Caido (8080) -> OmniSlash Gateway (3128) -> Internet
#
# Safe wiring for authorized in-scope recon only.
# - Nuclei runs through Caido for passive collection/findings.
# - Caido forwards upstream to OmniSlash gateway (scope/rate/circuit/audit).
# - OmniSlash probe/ (Dialer/Session) MUST bypass Caido for byte-exact probes.
#
# Requirements: caido-cli (optional), nuclei, jq, python3, omnislash built.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CAIDO_LISTEN="${CAIDO_LISTEN:-127.0.0.1:8080}"
GATEWAY_LISTEN="${GATEWAY_LISTEN:-127.0.0.1:3128}"
GATEWAY_STATS="${GATEWAY_STATS:-127.0.0.1:9090}"
TARGETS_FILE="${1:-}"
OUT_DIR="${OUT_DIR:-$ROOT/lab/out}"
mkdir -p "$OUT_DIR"

if [[ -z "$TARGETS_FILE" ]]; then
  echo "usage: $0 targets.txt" >&2
  exit 2
fi

echo "[1/4] Start OmniSlash gateway (upstream safety gate)"
echo "  omnislash serve -config $ROOT/lab/omnislash/config.json -proxies $ROOT/lab/no-proxies.txt -listen $GATEWAY_LISTEN -stats $GATEWAY_STATS"
echo "  (run in separate terminal; keep allowlist/scope configured)"

echo "[2/4] Start Caido headless with upstream to OmniSlash"
echo "  caido --no-open --listen $CAIDO_LISTEN"
echo "  Configure Caido upstream HTTP proxy -> $GATEWAY_LISTEN (UI/API/Project settings)."
echo "  Set CAIDO_PAT and create project/scope via osint/caido_client.py"

echo "[3/4] Run Nuclei through Caido (NOT directly to internet)"
echo "  nuclei -l $TARGETS_FILE -proxy http://$CAIDO_LISTEN -rate-limit 4 -concurrency 1 -retries 0 \"
echo "    -jsonl -o $OUT_DIR/nuclei.raw.jsonl -nc -silent -disable-update-check -no-interactsh"

echo "[4/4] Filter deception/soft-404 before report"
echo "  python3 $ROOT/osint/filter_nuclei.py --in $OUT_DIR/nuclei.raw.jsonl --out $OUT_DIR/nuclei.clean.jsonl --report $OUT_DIR/nuclei.filter-report.json"
echo "  python3 $ROOT/osint/caido_client.py --httpql 'host:regex(\".*\")' --out $OUT_DIR/caido.export.json"
echo ""
echo "NOTE: probe/ smuggling/desync/race must use Dialer/Session directly (no Caido MITM)."