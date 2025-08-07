#!/usr/bin/env bash

set -euo pipefail

usage() {
  echo "Usage: $0 [DURATION_SEC=60] [PPS|flood=flood] [MON_INTERVAL=1]" >&2
  echo "Server fixed at 127.0.0.1:12345. Monitor runs locally." >&2
}

if [[ ${1-} == "-h" || ${1-} == "--help" ]]; then
  usage
  exit 1
fi

TARGET_IP="127.0.0.1"
TARGET_PORT="12345"
DURATION_SEC="${1-60}"
PPS_OR_FLOOD="${2-flood}"
MON_INTERVAL="${3-1}"

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TOOLS_DIR="${ROOT_DIR}/tools"
LOG_DIR="${ROOT_DIR}/logs"
mkdir -p "$LOG_DIR"

OUT_CSV="${LOG_DIR}/conn_${TARGET_PORT}_$(date -u +%Y%m%dT%H%M%SZ).csv"

echo "Starting monitor for ${TARGET_IP}:${TARGET_PORT} -> $OUT_CSV (interval=${MON_INTERVAL}s)" >&2
"${TOOLS_DIR}/monitor_netstat.sh" "*" "$TARGET_PORT" "$OUT_CSV" "$MON_INTERVAL" &
MON_PID=$!

cleanup() {
  kill -TERM "$MON_PID" 2>/dev/null || true
  wait "$MON_PID" 2>/dev/null || true
}
trap cleanup INT TERM EXIT

echo "Launching SYN flood to ${TARGET_IP}:${TARGET_PORT} for ${DURATION_SEC}s (rate=${PPS_OR_FLOOD})..." >&2
sudo "${TOOLS_DIR}/hping3_syn_flood.sh" "$TARGET_IP" "$TARGET_PORT" "$DURATION_SEC" "$PPS_OR_FLOOD"

cleanup
trap - INT TERM EXIT

echo "Done. Inspect: $OUT_CSV" >&2

