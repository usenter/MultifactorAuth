#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat >&2 <<EOF
Usage:
  sudo $0 apply <SERVICE_PORT> [PER_IP_LIMIT=200] [SYN_RATE=50/second] [SYN_BURST=100]
  sudo $0 remove <SERVICE_PORT>
  sudo $0 status

Notes:
  - Enables TCP SYN cookies and installs iptables rules to mitigate SYN floods and limit per-IP concurrent connections.
  - Apply on the SERVER host that listens on SERVICE_PORT.
EOF
}

if [[ ${1-} == "-h" || ${1-} == "--help" || $# -lt 1 ]]; then
  usage
  exit 1
fi

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root (sudo)." >&2
  exit 1
fi

ensure_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "Missing dependency: $1" >&2; exit 1; }; }
ensure_cmd iptables

ACTION="$1"; shift || true

apply_rules() {
  local PORT="$1"; local PER_IP_LIMIT="${2-200}"; local SYN_RATE="${3-50/second}"; local SYN_BURST="${4-100}"

  # Kernel hardening (runtime; not persisted across reboot)
  sysctl -w net.ipv4.tcp_syncookies=1 >/dev/null
  sysctl -w net.ipv4.tcp_max_syn_backlog=4096 >/dev/null
  sysctl -w net.ipv4.tcp_synack_retries=3 >/dev/null

  # Create a chain for SYN flood control (idempotent)
  iptables -N SYN_FLOOD 2>/dev/null || true
  iptables -F SYN_FLOOD || true

  # Return early for acceptable per-source SYN rate; drop the rest
  iptables -A SYN_FLOOD -m hashlimit \
    --hashlimit-name "syn_${PORT}" \
    --hashlimit-mode srcip \
    --hashlimit-upto "$SYN_RATE" \
    --hashlimit-burst "$SYN_BURST" \
    -j RETURN

  iptables -A SYN_FLOOD -j DROP

  # Hook chain for this service port (avoid duplicate attachment)
  if ! iptables -C INPUT -p tcp --syn --dport "$PORT" -j SYN_FLOOD 2>/dev/null; then
    iptables -A INPUT -p tcp --syn --dport "$PORT" -j SYN_FLOOD
  fi

  # Per-IP concurrent connection limit for the service
  if ! iptables -C INPUT -p tcp --dport "$PORT" -m connlimit --connlimit-above "$PER_IP_LIMIT" --connlimit-mask 32 -j REJECT --reject-with tcp-reset 2>/dev/null; then
    iptables -A INPUT -p tcp --dport "$PORT" -m connlimit --connlimit-above "$PER_IP_LIMIT" --connlimit-mask 32 -j REJECT --reject-with tcp-reset
  fi

  echo "Applied mitigation for tcp/${PORT}: per-IP limit=${PER_IP_LIMIT}, SYN rate=${SYN_RATE}, burst=${SYN_BURST}" >&2
}

remove_rules() {
  local PORT="$1"
  # Detach hook
  iptables -D INPUT -p tcp --syn --dport "$PORT" -j SYN_FLOOD 2>/dev/null || true
  # Remove per-IP connlimit
  iptables -D INPUT -p tcp --dport "$PORT" -m connlimit --connlimit-above 200 --connlimit-mask 32 -j REJECT --reject-with tcp-reset 2>/dev/null || true
  # Flush and delete chain if unused
  iptables -F SYN_FLOOD 2>/dev/null || true
  iptables -X SYN_FLOOD 2>/dev/null || true
  echo "Removed mitigation for tcp/${PORT}" >&2
}

status_rules() {
  echo "=== sysctl ==="
  sysctl net.ipv4.tcp_syncookies net.ipv4.tcp_max_syn_backlog net.ipv4.tcp_synack_retries
  echo
  echo "=== iptables (filter) ==="
  iptables -S
}

case "$ACTION" in
  apply)
    [[ $# -ge 1 ]] || { usage; exit 1; }
    apply_rules "$@"
    ;;
  remove)
    [[ $# -ge 1 ]] || { usage; exit 1; }
    remove_rules "$1"
    ;;
  status)
    status_rules
    ;;
  *)
    usage; exit 1;
    ;;
esac

