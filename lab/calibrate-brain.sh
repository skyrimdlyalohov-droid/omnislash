#!/usr/bin/env bash
# Native, Docker-free calibration of OmniSlash's autonomous inference brain.
#
# Inputs are only (a) JSONL audits produced by omnislashd under runs/,
# (b) exploit-server/browser logs, (c) manual Caido feedback files, and
# (d) deterministic local Python cascade simulations. The curated
# solution-derived playbook is deliberately NOT an input.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

WEIGHTS="${WEIGHTS:-state/learned_weights.json}"
HOLDOUT_FRACTION="${HOLDOUT_FRACTION:-0.2}"
ALPHA="${ALPHA:-0.3}"
EXACT_WEIGHT="${EXACT_WEIGHT:-0.8}"

mkdir -p "$(dirname "$WEIGHTS")"

cmd=(
  python3 research/self_learning.py
  --weights "$WEIGHTS"
  train
  --audit-glob 'runs/*/daemon-*.jsonl'
  --simulate
  --holdout "$HOLDOUT_FRACTION"
  --alpha "$ALPHA"
  --exact-weight "$EXACT_WEIGHT"
  --out "$WEIGHTS"
)

shopt -s nullglob
for log in runs/*/exploit-log*.html runs/*/exploit-log*.log; do
  cmd+=(--exploit-log "$log")
done
shopt -u nullglob

add_feedback() {
  local flag="$1"
  local listing="${2:-}"
  for path in $listing; do
    if [[ -f "$path" ]]; then
      cmd+=("$flag" "$path")
    else
      echo "WARNING: feedback file not found, skipped: $path" >&2
    fi
  done
}
add_feedback --feedback-confirmed "${FEEDBACK_CONFIRMED:-}"
add_feedback --feedback-false-positive "${FEEDBACK_FALSE_POSITIVE:-}"

echo "== Native brain calibration (no Docker) =="
"${cmd[@]}"

python3 - "$WEIGHTS" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as handle:
    weights = json.load(handle)
holdout = set((weights.get("holdout") or {}).get("hosts") or [])
trained = set((weights.get("hosts") or {}).keys())
overlap = holdout & trained
if overlap:
    raise SystemExit("holdout leaked hosts into training: %s" % sorted(overlap))
negative = weights.get("negative") or {}
print("CALIBRATION_OK", json.dumps({
    "weights": path,
    "global_cells": len(weights.get("global") or {}),
    "trained_hosts": sorted(trained),
    "holdout_hosts": sorted(holdout),
    "negative_cl": negative.get("cl") or [],
    "holdout_metrics": (weights.get("holdout") or {}).get("metrics"),
}, ensure_ascii=False, sort_keys=True))
PY
