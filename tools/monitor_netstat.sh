#!/usr/bin/env bash

set -euo pipefail

usage() {
  echo "Usage: $0 <TARGET_IP|*> <TARGET_PORT> <OUT_CSV> [INTERVAL_SEC=1]" >&2
  echo "Note: Run this ON THE SERVER to measure inbound states like SYN_RECV." >&2
}

if [[ ${1-} == "-h" || ${1-} == "--help" || $# -lt 3 ]]; then
  usage
  exit 1
fi

if ! command -v netstat >/dev/null 2>&1; then
  echo "netstat is required. Install with: sudo apt-get update && sudo apt-get install -y net-tools" >&2
  exit 1
fi

TARGET_IP="$1"   # use '*' to match any IP on this host
TARGET_PORT="$2"
OUT_CSV="$3"
INTERVAL_SEC="${4-1}"

mkdir -p "$(dirname "$OUT_CSV")"

# CSV header
if [[ ! -s "$OUT_CSV" ]]; then
  echo "time_iso,time_epoch_ms,total,LISTEN,SYN_RECV,ESTABLISHED,FIN_WAIT1,FIN_WAIT2,CLOSE_WAIT,CLOSING,LAST_ACK,TIME_WAIT,OTHER" >"$OUT_CSV"
fi

collect_counts() {
  # Prints 11 integers: total listen syn_recv estab fin1 fin2 close_wait closing last_ack time_wait other
  netstat -ant 2>/dev/null \
  | awk -v ip="$TARGET_IP" -v port="$TARGET_PORT" '
      BEGIN {
        total=0
        states["LISTEN"]=0; states["SYN_RECV"]=0; states["ESTABLISHED"]=0;
        states["FIN_WAIT1"]=0; states["FIN_WAIT2"]=0; states["CLOSE_WAIT"]=0;
        states["CLOSING"]=0; states["LAST_ACK"]=0; states["TIME_WAIT"]=0;
      }
      NR>2 {
        local=$4; remote=$5; state=$6;
        # filter by port and optional IP
        if (local ~ ":" port "$" || remote ~ ":" port "$") {
          if (ip=="*" || index(local, ip) || index(remote, ip)) {
            gsub(/[^A-Z_]/, "", state);
            if (state in states) { states[state]++ } else { other++ }
            total++
          }
        }
      }
      END {
        if (total==0) other=0;
        printf "%d %d %d %d %d %d %d %d %d %d %d\n",
          total, states["LISTEN"], states["SYN_RECV"], states["ESTABLISHED"],
          states["FIN_WAIT1"], states["FIN_WAIT2"], states["CLOSE_WAIT"],
          states["CLOSING"], states["LAST_ACK"], states["TIME_WAIT"], other+0
      }'
}

stop=false
trap 'stop=true' INT TERM

while [[ "$stop" == false ]]; do
  # timestamps
  time_iso=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  if date +%s%3N >/dev/null 2>&1; then
    time_ms=$(date +%s%3N)
  else
    # fallback without %N support
    time_ms=$(( $(date +%s) * 1000 ))
  fi

  read -r total listen syn_recv estab fin1 fin2 close_wait closing last_ack time_wait other < <(collect_counts)
  echo "$time_iso,$time_ms,$total,$listen,$syn_recv,$estab,$fin1,$fin2,$close_wait,$closing,$last_ack,$time_wait,$other" >>"$OUT_CSV"

  sleep "$INTERVAL_SEC"
done

echo "Stopped. Output saved to: $OUT_CSV" >&2

