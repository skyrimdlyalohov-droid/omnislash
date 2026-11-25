#!/usr/bin/env bash
# Native, Docker-free calibration of OmniSlash's autonomous inference brain.
#
# Inputs are only (a) JSONL audits produced by omnislashd under runs/,
# (b) exploit-server/browser logs, (c) manual Caido feedback files,
# (d) deterministic local Python cascade simulations, and (e) a deterministic
# localhost proxy/backend corpus with forced-negative WAF stub templates.
# The curated solution-derived playbook is deliberately NOT an input.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

WEIGHTS="${WEIGHTS:-state/learned_weights.json}"
NATIVE_CORPUS="${NATIVE_CORPUS:-state/native_pair_corpus.jsonl}"
HOLDOUT_FRACTION="${HOLDOUT_FRACTION:-0.2}"
ALPHA="${ALPHA:-0.3}"
EXACT_WEIGHT="${EXACT_WEIGHT:-0.8}"

mkdir -p "$(dirname "$WEIGHTS")" "$(dirname "$NATIVE_CORPUS")"

cmd=(
  python3 research/self_learning.py
  --weights "$WEIGHTS"
  train
  --audit-glob 'runs/*/daemon-*.jsonl'
  --audit-glob 'runs/**/*.jsonl'
  --training-jsonl "$NATIVE_CORPUS"
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
# Starts 127.0.0.1-only Python http.server proxy/backend pairs plus a
# stdlib-only Go net/http backend (both on ephemeral ports), emits
# TrainingExample JSONL, then shuts every local server down cleanly.
python3 research/native_pair_corpus.py --out "$NATIVE_CORPUS"
"${cmd[@]}"

python3 - "$WEIGHTS" "$NATIVE_CORPUS" <<'PY'
import json
import sys

path = sys.argv[1]
native_path = sys.argv[2]
with open(path, "r", encoding="utf-8") as handle:
    weights = json.load(handle)
holdout = set((weights.get("holdout") or {}).get("hosts") or [])
trained = set((weights.get("hosts") or {}).keys())
overlap = holdout & trained
if overlap:
    raise SystemExit("holdout leaked hosts into training: %s" % sorted(overlap))
native_examples = 0
try:
    with open(native_path, "r", encoding="utf-8") as handle:
        native_examples = sum(1 for line in handle if line.strip())
except FileNotFoundError:
    pass
negative = weights.get("negative") or {}
metrics = (weights.get("holdout") or {}).get("metrics") or {}
print("CALIBRATION_OK", json.dumps({
    "weights": path,
    "examples": weights.get("examples"),
    "validation_examples": (weights.get("holdout") or {}).get("validation_examples"),
    "holdout_accuracy": metrics.get("accuracy"),
    "global_cells": len(weights.get("global") or {}),
    "native_pair_examples": native_examples,
    "trained_hosts": sorted(trained),
    "holdout_hosts": sorted(holdout),
    "negative_cl": negative.get("cl") or [],
    "holdout_metrics": (weights.get("holdout") or {}).get("metrics"),
}, ensure_ascii=False, sort_keys=True))
PY
