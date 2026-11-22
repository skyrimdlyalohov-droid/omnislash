#!/usr/bin/env bash
# Start the local lab and the omnislash safety gateway.
#
#   lab/run-lab.sh              # use Docker when available, else fallback targets
#   lab/run-lab.sh --fallback   # no Docker: tiny local Go targets
#   lab/run-lab.sh --docker     # require Docker Compose
#   lab/run-lab.sh --down       # stop Docker lab containers
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB="$ROOT/lab"
BIN="$LAB/bin"
COMPOSE="$LAB/docker-compose.yml"
cd "$ROOT"
MODE="auto"
case "${1:-}" in
  --fallback) MODE="fallback" ;;
  --docker) MODE="docker" ;;
  --down)
    docker compose -f "$COMPOSE" down
    exit 0
    ;;
  ""|--auto) MODE="auto" ;;
  -h|--help)
    sed -n '2,9p' "$0"
    exit 0
    ;;
  *)
    echo "unknown argument: $1" >&2
    exit 2
    ;;
esac

if [[ "$MODE" == "auto" ]]; then
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    MODE="docker"
  else
    echo "Docker Compose not found; using local fallback targets." >&2
    MODE="fallback"
  fi
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

wait_http() {
  local url="$1"
  for _ in $(seq 1 120); do
    if curl -fsS --noproxy '*' -o /dev/null --max-time 2 "$url" 2>/dev/null; then
      return 0
    fi
    sleep 0.5
  done
  echo "timed out waiting for $url" >&2
  return 1
}

mkdir -p "$BIN"
echo "building omnislash..."
(cd "$ROOT" && go build -trimpath -o "$BIN/omnislash" ./cmd/omnislash)

if [[ "$MODE" == "docker" ]]; then
  command -v docker >/dev/null 2>&1 || { echo "docker is not installed" >&2; exit 1; }
  docker compose version >/dev/null 2>&1 || { echo "docker compose plugin is not installed" >&2; exit 1; }
  echo "starting Juice Shop and DVWA on loopback..."
  docker compose -f "$COMPOSE" up -d
  wait_http "http://127.0.0.1:3000/"
  wait_http "http://127.0.0.1:8080/login.php"
else
  echo "building fallback targets..."
  (cd "$ROOT" && go build -trimpath -o "$BIN/fallback-target" ./lab/fallback-target)
  "$BIN/fallback-target" -addr 127.0.0.1:3000 -name juice >"$LAB/target-juice.log" 2>&1 &
  TARGET_PIDS+=("$!")
  "$BIN/fallback-target" -addr 127.0.0.1:8080 -name dvwa >"$LAB/target-dvwa.log" 2>&1 &
  TARGET_PIDS+=("$!")
  wait_http "http://127.0.0.1:3000/healthz"
  wait_http "http://127.0.0.1:8080/healthz"
fi

# The proxy file intentionally does not exist. allow_direct=true in the lab
# config makes an empty pool valid; no public proxies are used in the lab.
echo "starting omnislash safety gateway on 127.0.0.1:3128..."
"$BIN/omnislash" serve \
  -config "$LAB/omnislash/config.json" \
  -proxies "$LAB/no-proxies.txt" \
  -no-health \
  -listen 127.0.0.1:3128 \
  -stats 127.0.0.1:9090 &
GATEWAY_PID="$!"

for _ in $(seq 1 60); do
  if ! kill -0 "$GATEWAY_PID" 2>/dev/null; then
    echo "gateway exited during startup" >&2
    wait "$GATEWAY_PID" 2>/dev/null || true
    exit 1
  fi
  if curl -fsS --noproxy '*' -o /dev/null --max-time 2 "http://127.0.0.1:9090/stats"; then
    break
  fi
  sleep 0.25
done
if ! curl -fsS --noproxy '*' -o /dev/null --max-time 2 "http://127.0.0.1:9090/stats"; then
  echo "gateway stats endpoint did not become ready" >&2
  exit 1
fi

cat <<'EOF'

Lab is running.

  Targets   http://127.0.0.1:3000  (Juice Shop)
            http://127.0.0.1:8080  (DVWA)
  Gateway   http://127.0.0.1:3128  (HTTP forward + CONNECT)
  Stats     http://127.0.0.1:9090/stats
  Audit     lab/audit.jsonl

Nuclei (4 requests/second, one template at a time, no OAST):

  nuclei -u http://127.0.0.1:3000 -u http://127.0.0.1:8080 \
    -t lab/nuclei-templates \
    -proxy http://127.0.0.1:3128 \
    -rate-limit 4 -concurrency 1 -retries 0 -timeout 10 \
    -disable-update-check -no-interactsh -disable-redirects -nc -silent

Caido: add http://127.0.0.1:3128 as the upstream proxy, scope only
http://127.0.0.1:3000 and http://127.0.0.1:8080, and use Repeater/manual
requests only. Do not run scanner/automate features against anything else.

Verification is self-contained:  lab/verify.sh
Stop: Ctrl-C (fallback targets stop automatically; Docker containers stay up,
      stop them with: lab/run-lab.sh --down)

EOF

wait "$GATEWAY_PID"
