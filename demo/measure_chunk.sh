#!/usr/bin/env bash
# Per-chunk-size: peak RSS (max of both parties, via /proc VmHWM) + round-trips +
# wall, for one index. Pair with `tc qdisc add dev lo root netem delay <D>` to
# measure the latency-vs-memory trade-off under emulated ping.
# Usage: measure_chunk.sh <I_hex> <portbase> <N...>
set -u
cd "$(dirname "$0")/.."
IDX="${1:-ffffffffffff}"; PORT="${2:-25300}"; shift 2 2>/dev/null || shift $#
NS="${*:-1 2 4 8 16 48}"
AS=$(printf 'aa%.0s' {1..32}); BS=$(printf 'ab%.0s' {1..32})
PARTY_BIN="${PARTY_BIN:-./.build/party}"
if [ ! -x "$PARTY_BIN" ]; then
  echo "missing binary: PARTY_BIN=$PARTY_BIN" >&2
  exit 2
fi
poll_hwm() {
  local pid=$1 out=$2 hwm=0 cur
  while [ -d "/proc/$pid" ]; do
    cur=$(awk '/VmHWM/{print $2}' "/proc/$pid/status" 2>/dev/null)
    [ -n "$cur" ] && hwm=$cur
    sleep 0.05
  done
  echo "$hwm" > "$out"
}
printf "%-4s %-7s %-9s %-8s %-9s\n" "N" "chunks" "peakRSS" "rounds" "wall(s)"
for N in $NS; do
  AE=$(mktemp); BO=$(mktemp); AH=$(mktemp); BH=$(mktemp)
  SHACHAIN2PC_PHASE_TIMING=1 SHACHAIN2PC_CHUNK_BLOCKS="$N" \
    "$PARTY_BIN" 1 "$PORT" "$IDX" "$AS" >/dev/null 2>"$AE" & AP=$!
  poll_hwm "$AP" "$AH" &
  sleep 0.4
  t0=$(date +%s.%N)
  SHACHAIN2PC_PHASE_TIMING=1 SHACHAIN2PC_CHUNK_BLOCKS="$N" \
    "$PARTY_BIN" 2 "$PORT" "$IDX" "$BS" 127.0.0.1 >"$BO" 2>/dev/null & BP=$!
  poll_hwm "$BP" "$BH" &
  wait "$BP"; t1=$(date +%s.%N)
  wait "$AP"; wait
  ah=$(cat "$AH" 2>/dev/null || echo 0); bh=$(cat "$BH" 2>/dev/null || echo 0)
  peak=$(( ah > bh ? ah : bh ))
  gt=$(grep grand-total "$AE" | awk '{print $3}')
  if [ -z "$gt" ]; then
    gt=$(awk '/^TIMING / {
        for (i = 1; i <= NF; i++) {
          if ($i ~ /^total_ms=/) {
            split($i, a, "=");
            total = a[2];
          }
        }
      }
      END { if (total != "") printf "%.4f", total / 1000 }' "$AE")
  fi
  if [ -z "$gt" ]; then
    gt=$(awk "BEGIN{printf \"%.4f\", $t1-$t0}")
  fi
  rounds=$(grep '^NET' "$AE" | sed -E 's/.*rounds=([0-9]+).*/\1/')
  chunks=$(grep 'compute total' "$AE" | sed -E 's/.*\(([0-9]+) chunks.*/\1/')
  if [ -z "$chunks" ]; then
    chunks=$(grep -c 'phase=chunk' "$AE" || true)
  fi
  printf "%-4s %-7s %-9s %-8s %-9s\n" "$N" "$chunks" "$((peak/1024))MB" "$rounds" "$gt"
  rm -f "$AE" "$BO" "$AH" "$BH"; PORT=$((PORT+1))
done
