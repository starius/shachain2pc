#!/usr/bin/env bash
# Compare per-index batch vs shared-trunk (tree) over a range: wall time, peak RSS
# (max of both parties), and correctness vs ref_cli. Usage:
#   measure_tree.sh <lo-hi> [portbase] [trunk_chunk_blocks]
set -u
cd "$(dirname "$0")/.."
SPEC="${1:-ffffffffffc0-ffffffffffff}"; PORT="${2:-27300}"; TCB="${3:-0}"
AS=$(printf 'aa%.0s' {1..32}); BS=$(printf 'ab%.0s' {1..32})
poll_hwm(){ local pid=$1 out=$2 hwm=0 cur; while [ -d "/proc/$pid" ]; do
  cur=$(awk '/VmHWM/{print $2}' "/proc/$pid/status" 2>/dev/null); [ -n "$cur" ]&&hwm=$cur; sleep 0.05; done; echo "$hwm">"$out"; }

run() {  # $1=label, rest=env assignments for both parties
  local label="$1"; shift
  local AE BO AH BH; AE=$(mktemp); BO=$(mktemp); AH=$(mktemp); BH=$(mktemp)
  env "$@" ./.build/party 1 "$PORT" "$SPEC" "$AS" >/dev/null 2>"$AE" & local AP=$!
  poll_hwm "$AP" "$AH" &
  sleep 0.4
  local t0; t0=$(date +%s.%N)
  env "$@" ./.build/party 2 "$PORT" "$SPEC" "$BS" 127.0.0.1 >"$BO" 2>/dev/null & local BP=$!
  poll_hwm "$BP" "$BH" &
  wait "$BP"; local t1; t1=$(date +%s.%N); wait "$AP"; wait
  local ah bh peak n bad; ah=$(cat "$AH"); bh=$(cat "$BH"); peak=$(( ah>bh?ah:bh ))
  n=$(grep -c '^RESULT' "$BO"); bad=0
  while read -r tag I val; do [ "$tag" = RESULT ] || continue
    r=$(./.build/ref_cli "$AS" "$BS" "$I"); [ "$val" = "$r" ] || bad=$((bad+1)); done < <(grep '^RESULT' "$BO")
  printf "%-14s wall=%8.2fs  peakRSS=%4dMB  results=%-5s mismatches=%s\n" \
    "$label" "$(awk "BEGIN{print $t1-$t0}")" "$((peak/1024))" "$n" "$bad"
  cp "$AE" /tmp/last_alice.err; rm -f "$AE" "$BO" "$AH" "$BH"; PORT=$((PORT+1))
}

echo "=== range $SPEC ==="
run "batch"               # per-index, independent (current default)
run "tree"      SHACHAIN2PC_TREE=1
[ "$TCB" != 0 ] && run "tree+chunk$TCB" SHACHAIN2PC_TREE=1 SHACHAIN2PC_CHUNK_BLOCKS="$TCB"
echo "--- tree timing breakdown (last tree run) ---"; grep -E 'TREE|NET' /tmp/last_alice.err
