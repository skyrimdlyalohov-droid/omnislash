#!/usr/bin/env bash
# Self-contained verification of the lab safety pipeline.
#
# It starts the fallback targets and a dedicated omnislash gateway on
# 127.0.0.1:3129, then checks:
#   1. scope allowlist (in-scope 200, out-of-scope 403);
#   2. global 4 rps cap across all connections;
#   3. Nuclei runs only through the gateway with -rate-limit 4;
#   4. repeated target 403s trip the fail-closed circuit breaker;
#   5. the JSONL audit log contains block and circuit_open events.
#
# No Docker and no public proxies are used. Nothing leaves 127.0.0.1.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB="$ROOT/lab"
BIN="$LAB/bin"
AUDIT="$LAB/audit.jsonl"
RESULTS="$LAB/nuclei-results.jsonl"
cd "$ROOT"
RUN_NUCLEI=1
if [[ "${1:-}" == "--no-nuclei" ]]; then
  RUN_NUCLEI=0
fi

# Do not let a shell-wide proxy configuration silently redirect lab traffic.
unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy NO_PROXY no_proxy

need() {
  command -v "$1" >/dev/null 2>&1 || { echo "missing required command: $1" >&2; exit 1; }
}
need go
need curl
need jq
if [[ "$RUN_NUCLEI" == "1" ]]; then
  need nuclei
fi

TARGET_PIDS=()
GATEWAY_PID=""
cleanup() {
  trap - EXIT INT TERM
  if [[ -n "$GATEWAY_PID" ]]; then
    kill "$GATEWAY_PID" 2>/dev/null || true
    wait "$GATEWAY_PID" 2>/dev/null || true
  fi
  for pid in "${TARGET_PIDS[@]:-}"; do
    [[ -n "$pid" ]] || continue
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
}
trap cleanup EXIT INT TERM

fail() {
  echo "FAIL: $*" >&2
  echo "--- gateway log ---" >&2
  tail -n 40 "$LAB/gateway-verify.log" 2>/dev/null >&2 || true
  echo "--- audit tail ---" >&2
  tail -n 20 "$AUDIT" 2>/dev/null >&2 || true
  exit 1
}

expect() {
  local want="$1" got="$2" label="$3"
  if [[ "$got" != "$want" ]]; then
    fail "$label: got HTTP $got, want $want"
  fi
  echo "ok: $label (HTTP $got)"
}

proxy_get() {
  curl -sS --noproxy '' --proxy http://127.0.0.1:3129 \
    -o /dev/null -w '%{http_code}' --max-time 20 "$1"
}

mkdir -p "$BIN"
echo "building..."
(cd "$ROOT" && go build -trimpath -o "$BIN/omnislash" ./cmd/omnislash)
(cd "$ROOT" && go build -trimpath -o "$BIN/fallback-target" ./lab/fallback-target)

: >"$AUDIT"
rm -f "$RESULTS"

echo "starting fallback targets..."
"$BIN/fallback-target" -addr 127.0.0.1:3000 -name juice >"$LAB/target-juice.log" 2>&1 &
TARGET_PIDS+=("$!")
"$BIN/fallback-target" -addr 127.0.0.1:8080 -name dvwa >"$LAB/target-dvwa.log" 2>&1 &
TARGET_PIDS+=("$!")

for _ in $(seq 1 60); do
  curl -fsS -o /dev/null --max-time 2 http://127.0.0.1:3000/healthz 2>/dev/null && break
  sleep 0.2
done
for _ in $(seq 1 60); do
  curl -fsS -o /dev/null --max-time 2 http://127.0.0.1:8080/healthz 2>/dev/null && break
  sleep 0.2
done

echo "starting gateway on 127.0.0.1:3129..."
"$BIN/omnislash" serve \
  -config "$LAB/omnislash/config.json" \
  -proxies "$LAB/no-proxies.txt" \
  -no-health \
  -listen 127.0.0.1:3129 \
  -stats 127.0.0.1:9091 >"$LAB/gateway-verify.log" 2>&1 &
GATEWAY_PID="$!"

ready=0
for _ in $(seq 1 80); do
  if curl -fsS -o /dev/null --max-time 2 http://127.0.0.1:9091/stats 2>/dev/null; then
    ready=1
    break
  fi
  sleep 0.25
done
[[ "$ready" == "1" ]] || fail "gateway stats endpoint did not start"

echo
echo "== scope =="
expect 200 "$(proxy_get http://127.0.0.1:3000/)" "in-scope Juice Shop"
expect 200 "$(proxy_get http://127.0.0.1:8080/login.php)" "in-scope DVWA"
expect 403 "$(proxy_get http://127.0.0.1:3001/)" "out-of-scope port"
expect 403 "$(proxy_get http://127.0.0.2:3000/)" "out-of-scope host"

echo
echo "== global rate limit =="
start_ns="$(date +%s%N)"
for i in 1 2 3 4 5; do
  expect 200 "$(proxy_get http://127.0.0.1:3000/healthz)" "rate sample $i"
done
elapsed_ms=$(( ($(date +%s%N) - start_ns) / 1000000 ))
if (( elapsed_ms < 800 )); then
  fail "5 requests finished in ${elapsed_ms}ms; expected at least ~1000ms at 4 rps"
fi
echo "ok: 5 requests took ${elapsed_ms}ms (global 4 rps cap)"

if [[ "$RUN_NUCLEI" == "1" ]]; then
  echo
  echo "== nuclei through the gateway =="
  before_lines="$(wc -l <"$AUDIT")"
  if ! nuclei \
    -u http://127.0.0.1:3000 \
    -u http://127.0.0.1:8080 \
    -t "$LAB/nuclei-templates" \
    -proxy http://127.0.0.1:3129 \
    -rate-limit 4 -concurrency 1 -retries 0 -timeout 10 \
    -disable-update-check -no-interactsh -disable-redirects \
    -nc -silent -jsonl -o "$RESULTS" >"$LAB/nuclei-verify.log" 2>&1; then
    fail "nuclei exited nonzero (see lab/nuclei-verify.log)"
  fi
  after_lines="$(wc -l <"$AUDIT")"
  if (( after_lines <= before_lines )); then
    fail "nuclei produced no gateway audit entries; it likely bypassed the proxy"
  fi
  findings="$(wc -l <"$RESULTS" 2>/dev/null || echo 0)"
  if (( findings < 1 )); then
    fail "nuclei produced no findings from lab/nuclei-templates"
  fi
  echo "ok: nuclei findings=$findings, new gateway audit lines=$((after_lines - before_lines))"
fi

echo
echo "== circuit breaker =="
for i in 1 2 3; do
  expect 403 "$(proxy_get http://127.0.0.1:3000/blocked)" "block status $i"
done
expect 503 "$(proxy_get http://127.0.0.1:3000/healthz)" "request after threshold"

if ! curl -fsS --max-time 5 http://127.0.0.1:9091/stats | jq -e '.circuit.tripped == true' >/dev/null; then
  fail "stats endpoint does not report a tripped circuit"
fi
echo "ok: stats reports circuit.tripped=true"

if ! jq -e 'select(.reason == "circuit_open")' "$AUDIT" >/dev/null; then
  fail "audit log has no circuit_open event"
fi
if ! jq -e 'select(.kind == "http" and .status == 403)' "$AUDIT" >/dev/null; then
  fail "audit log has no HTTP 403 events"
fi
echo "ok: audit log contains 403 and circuit_open events"

echo
echo "PASS: scope, global 4 rps cap, nuclei-via-gateway, circuit breaker, audit"
echo "audit: $AUDIT"
tail -n 5 "$AUDIT"
