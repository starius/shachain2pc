#!/usr/bin/env bash
# Adaptive-cache mode over a range: wall, peak RSS (max of both parties), the CACHE
# timing breakdown, and correctness vs ref_cli. Usage:
#   measure_cache.sh <lo-hi> [portbase] [trunk_chunk_size]
set -u
cd "$(dirname "$0")/.."
SPEC="${1:-ffffffffff00-ffffffffffff}"; PORT="${2:-28400}"; TCB="${3:-2}"
AS=$(printf 'aa%.0s' {1..32}); BS=$(printf 'ab%.0s' {1..32})
poll_hwm(){ local pid=$1 out=$2 hwm=0 cur; while [ -d "/proc/$pid" ]; do
  cur=$(awk '/VmHWM/{print $2}' "/proc/$pid/status" 2>/dev/null); [ -n "$cur" ]&&hwm=$cur; sleep 0.05; done; echo "$hwm">"$out"; }
AE=$(mktemp); BO=$(mktemp); AH=$(mktemp); BH=$(mktemp)
SHACHAIN2PC_CACHE=1 SHACHAIN2PC_CHUNK_BLOCKS="$TCB" ./.build/party 1 "$PORT" "$SPEC" "$AS" >/dev/null 2>"$AE" & AP=$!
poll_hwm "$AP" "$AH" &
sleep 0.4
t0=$(date +%s.%N)
SHACHAIN2PC_CACHE=1 SHACHAIN2PC_CHUNK_BLOCKS="$TCB" ./.build/party 2 "$PORT" "$SPEC" "$BS" 127.0.0.1 >"$BO" 2>/dev/null & BP=$!
poll_hwm "$BP" "$BH" &
wait "$BP"; t1=$(date +%s.%N); wait "$AP"; wait
ah=$(cat "$AH"); bh=$(cat "$BH"); peak=$(( ah>bh?ah:bh ))
n=$(grep -c '^RESULT' "$BO"); bad=0
while read -r tag I val; do [ "$tag" = RESULT ] || continue
  r=$(./.build/ref_cli "$AS" "$BS" "$I"); [ "$val" = "$r" ] || bad=$((bad+1)); done < <(grep '^RESULT' "$BO")
printf "cache %s: wall=%.2fs peakRSS=%dMB results=%s mismatches=%s\n" \
  "$SPEC" "$(awk "BEGIN{print $t1-$t0}")" "$((peak/1024))" "$n" "$bad"
grep -E 'CACHE|NET' "$AE"
rm -f "$AE" "$BO" "$AH" "$BH"
