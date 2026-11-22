#!/usr/bin/env bash
set -euo pipefail

# Omnislash gateway daemon helper (CONNECT proxy).
# Usage: ./omnislash-daemon.sh {start|stop|restart|status|log [N]|foreground}

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${BIN:-$BASE_DIR/bin/omnislash}"
CONFIG="${CONFIG:-/tmp/opencode/omni-max.json}"
PROXIES="${PROXIES:-/tmp/opencode/live-proxies.txt}"
LISTEN="${LISTEN:-127.0.0.1:3128}"
STATS="${STATS:-off}"            # e.g. 127.0.0.1:9090 or 'off'
RUNDIR="${RUNDIR:-/tmp/opencode/omnislash-daemon}"
LOGFILE="${LOGFILE:-$RUNDIR/omnislash.log}"
PIDFILE="${PIDFILE:-$RUNDIR/omnislash.pid}"

mkdir -p "$RUNDIR"

is_running() {
  if [[ -f "$PIDFILE" ]]; then
    local pid
    pid="$(cat "$PIDFILE" 2>/dev/null || true)"
    if [[ -n "${pid:-}" ]] && kill -0 "$pid" 2>/dev/null; then
      echo "$pid"
      return 0
    fi
  fi
  local p=""
  p="$(ss -ltnp 2>/dev/null | grep -F "$LISTEN" | sed -n 's/.*pid=\([0-9]*\).*/\1/p' | head -n1 || true)"
  if [[ -n "$p" ]] && kill -0 "$p" 2>/dev/null; then
    echo "$p" > "$PIDFILE"
    echo "$p"
    return 0
  fi
  return 1
}

cmd_start() {
  local pid
  if pid="$(is_running)"; then
    echo "omnislash already running (pid $pid, listen $LISTEN)"
    return 0
  fi
  if [[ ! -x "$BIN" ]]; then
    echo "error: binary not found or not executable: $BIN" >&2
    return 1
  fi
  if [[ ! -f "$CONFIG" ]]; then
    echo "error: config not found: $CONFIG" >&2
    return 1
  fi
  if [[ ! -f "$PROXIES" ]]; then
    echo "error: proxies file not found: $PROXIES" >&2
    return 1
  fi
  echo "starting omnislash gateway..."
  echo "  bin=$BIN"
  echo "  config=$CONFIG"
  echo "  proxies=$PROXIES"
  echo "  listen=$LISTEN"
  echo "  stats=$STATS"
  echo "  log=$LOGFILE"
  nohup "$BIN" serve \
    -config "$CONFIG" \
    -proxies "$PROXIES" \
    -listen "$LISTEN" \
    -stats "$STATS" \
    >> "$LOGFILE" 2>&1 &
  pid=$!
  echo "$pid" > "$PIDFILE"
  sleep 1
  if kill -0 "$pid" 2>/dev/null; then
    echo "started (pid $pid)"
    ss -ltnp 2>/dev/null | grep -F "$LISTEN" || true
    return 0
  else
    echo "error: process exited early, see log: $LOGFILE" >&2
    rm -f "$PIDFILE"
    tail -n 40 "$LOGFILE" >&2 || true
    return 1
  fi
}

cmd_stop() {
  local pid
  if ! pid="$(is_running)"; then
    echo "omnislash not running"
    rm -f "$PIDFILE"
    return 0
  fi
  echo "stopping omnislash (pid $pid)..."
  kill "$pid" 2>/dev/null || true
  for _ in 1 2 3 4 5 6 7 8; do
    if ! kill -0 "$pid" 2>/dev/null; then
      rm -f "$PIDFILE"
      echo "stopped"
      return 0
    fi
    sleep 0.5
  done
  echo "force killing (pid $pid)..."
  kill -9 "$pid" 2>/dev/null || true
  rm -f "$PIDFILE"
  echo "stopped"
  return 0
}

cmd_status() {
  local pid
  if pid="$(is_running)"; then
    echo "running (pid $pid, listen $LISTEN)"
    ss -ltnp 2>/dev/null | grep -F "$LISTEN" || true
    return 0
  else
    echo "not running"
    return 1
  fi
}

cmd_log() {
  touch "$LOGFILE"
  tail -n "${2:-80}" "$LOGFILE"
}

cmd_foreground() {
  exec "$BIN" serve -config "$CONFIG" -proxies "$PROXIES" -listen "$LISTEN" -stats "$STATS"
}

case "${1:-}" in
  start) cmd_start ;;
  stop) cmd_stop ;;
  restart) cmd_stop; cmd_start ;;
  status) cmd_status ;;
  log) shift || true; cmd_log "${1:-80}" ;;
  foreground|fg) cmd_foreground ;;
  *)
    echo "Usage: $0 {start|stop|restart|status|log [N]|foreground}" >&2
    echo "Env overrides: BIN CONFIG PROXIES LISTEN STATS RUNDIR LOGFILE PIDFILE" >&2
    exit 2
    ;;
esac
