#!/usr/bin/env bash
# Adaptive-cache mode over a range: wall, wall/secret, peak RSS (max of both
# parties), the CACHE timing breakdown, and correctness vs ref_cli. Usage:
#   measure_cache.sh <lo-hi> [portbase] [trunk_chunk_size]
set -euo pipefail
cd "$(dirname "$0")/.."
SPEC="${1:-ffffffffff00-ffffffffffff}"; PORT="${2:-28400}"; TCB="${3:-1}"
AS=$(printf 'aa%.0s' {1..32}); BS=$(printf 'ab%.0s' {1..32})

if [[ "$SPEC" != *-* ]]; then
  echo "measure_cache.sh requires an inclusive range: LO-HI" >&2
  exit 2
fi
lo_hex=${SPEC%-*}
hi_hex=${SPEC#*-}
if [[ -z "$lo_hex" || -z "$hi_hex" ]]; then
  echo "measure_cache.sh requires an inclusive range: LO-HI" >&2
  exit 2
fi
lo=$((16#$lo_hex))
hi=$((16#$hi_hex))
if (( lo > hi )); then
  echo "measure_cache.sh range LO must be <= HI" >&2
  exit 2
fi
expected=$((hi - lo + 1))

if [ ! -x ./.build/party ] || [ ! -x ./.build/ref_cli ]; then
  make .build/party .build/ref_cli >/dev/null
fi

poll_hwm() {
  local pid=$1 out=$2 hwm=0 cur
  while [ -d "/proc/$pid" ]; do
    cur=$(awk '/VmHWM/{print $2}' "/proc/$pid/status" 2>/dev/null || true)
    [ -n "$cur" ] && hwm=$cur
    sleep 0.05
  done
  echo "$hwm" >"$out"
}

AO=$(mktemp); AE=$(mktemp); BO=$(mktemp); BE=$(mktemp)
AH=$(mktemp); BH=$(mktemp); AR=$(mktemp); BR=$(mktemp)
cleanup(){ rm -f "$AO" "$AE" "$BO" "$BE" "$AH" "$BH" "$AR" "$BR"; }
trap cleanup EXIT

SHACHAIN2PC_CACHE=1 SHACHAIN2PC_CHUNK_BLOCKS="$TCB" \
  ./.build/party 1 "$PORT" "$SPEC" "$AS" >"$AO" 2>"$AE" & AP=$!
poll_hwm "$AP" "$AH" & APOLL=$!
sleep 0.4
t0=$(date +%s.%N)
SHACHAIN2PC_CACHE=1 SHACHAIN2PC_CHUNK_BLOCKS="$TCB" \
  ./.build/party 2 "$PORT" "$SPEC" "$BS" 127.0.0.1 >"$BO" 2>"$BE" & BP=$!
poll_hwm "$BP" "$BH" & BPOLL=$!
set +e
wait "$BP"; BRC=$?
t1=$(date +%s.%N)
wait "$AP"; ARC=$?
wait "$APOLL" "$BPOLL"
set -e
ah=$(cat "$AH"); bh=$(cat "$BH"); peak=$(( ah>bh?ah:bh ))
wall=$(awk "BEGIN{print $t1-$t0}")

if [ "$ARC" -ne 0 ] || [ "$BRC" -ne 0 ]; then
  echo "cache $SPEC: ABORTED (ALICE rc=$ARC, BOB rc=$BRC)" >&2
  echo "--- ALICE stderr ---" >&2; cat "$AE" >&2
  echo "--- BOB stderr ---" >&2; cat "$BE" >&2
  exit 1
fi

grep '^RESULT ' "$AO" >"$AR" || true
grep '^RESULT ' "$BO" >"$BR" || true
n=$(wc -l <"$BR")
bad=0
if [ "$n" -ne "$expected" ]; then
  echo "cache $SPEC: expected $expected results, got $n" >&2
  bad=$((bad+1))
fi
if ! diff -q "$AR" "$BR" >/dev/null; then
  echo "cache $SPEC: ALICE/BOB RESULT mismatch" >&2
  bad=$((bad+1))
fi
while read -r tag I val; do
  [ "$tag" = RESULT ] || continue
  r=$(./.build/ref_cli "$AS" "$BS" "$I")
  [ "$val" = "$r" ] || bad=$((bad+1))
done <"$BR"
per_secret=$(awk -v w="$wall" -v n="$expected" 'BEGIN{printf "%.4f", w/n}')
printf "cache %s: wall=%.2fs perSecret=%ss peakRSS=%dMB results=%s mismatches=%s\n" \
  "$SPEC" "$wall" "$per_secret" "$((peak/1024))" "$n" "$bad"
grep -E 'CACHE|NET' "$AE"
[ "$bad" -eq 0 ]
