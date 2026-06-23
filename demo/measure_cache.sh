#!/usr/bin/env bash
# Adaptive-cache mode over a range: wall, wall/secret, peak RSS (max of both
# parties), the CACHE timing breakdown, and correctness vs ref_cli. Usage:
#   measure_cache.sh <lo-hi> [portbase] [trunk_chunk_size] [tile_fanout]
set -euo pipefail
cd "$(dirname "$0")/.."
SPEC="${1:-ffffffffff00-ffffffffffff}"; PORT="${2:-28400}"; TCB="${3:-16}"
TF="${4:-16}"
AS=$(printf 'aa%.0s' {1..32}); BS=$(printf 'ab%.0s' {1..32})
PARTY_BIN="${PARTY_BIN:-./.build/party}"
REF_BIN="${REF_BIN:-./.build/ref_cli}"

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

if [ "$PARTY_BIN" = "./.build/party" ] && { [ ! -x "$PARTY_BIN" ] || [ ! -x "$REF_BIN" ]; }; then
  make .build/party .build/ref_cli >/dev/null
fi
if [ ! -x "$PARTY_BIN" ] || [ ! -x "$REF_BIN" ]; then
  echo "missing binary: PARTY_BIN=$PARTY_BIN REF_BIN=$REF_BIN" >&2
  exit 2
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

SHACHAIN2PC_PHASE_TIMING=1 SHACHAIN2PC_CACHE=1 \
  SHACHAIN2PC_CHUNK_BLOCKS="$TCB" SHACHAIN2PC_TILE_FANOUT="$TF" \
  "$PARTY_BIN" 1 "$PORT" "$SPEC" "$AS" >"$AO" 2>"$AE" & AP=$!
poll_hwm "$AP" "$AH" & APOLL=$!
sleep 0.4
t0=$(date +%s.%N)
SHACHAIN2PC_PHASE_TIMING=1 SHACHAIN2PC_CACHE=1 \
  SHACHAIN2PC_CHUNK_BLOCKS="$TCB" SHACHAIN2PC_TILE_FANOUT="$TF" \
  "$PARTY_BIN" 2 "$PORT" "$SPEC" "$BS" 127.0.0.1 >"$BO" 2>"$BE" & BP=$!
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
  r=$("$REF_BIN" "$AS" "$BS" "$I")
  [ "$val" = "$r" ] || bad=$((bad+1))
done <"$BR"
per_secret=$(awk -v w="$wall" -v n="$expected" 'BEGIN{printf "%.4f", w/n}')
pre_reveal=$(awk '/CACHE pre-reveal total/{print $4; exit}' "$AE")
if [ -z "$pre_reveal" ]; then
  pre_reveal=$(awk '/^TIMING / {
      phase = "";
      total = "";
      for (i = 1; i <= NF; i++) {
        if ($i ~ /^phase=/) {
          split($i, p, "=");
          phase = p[2];
        }
        if ($i ~ /^total_ms=/) {
          split($i, t, "=");
          total = t[2];
        }
      }
      if (phase == "cache_reveal" && prev_total != "") {
        printf "%.4f", prev_total / 1000;
        exit;
      }
      if (total != "") {
        prev_total = total;
      }
    }' "$AE")
fi
pre_reveal=${pre_reveal:-0}
pre_secret=$(awk -v w="$pre_reveal" -v n="$expected" 'BEGIN{printf "%.4f", w/n}')
printf "cache %s: wall=%.2fs perSecret=%ss preReveal=%ss preRevealPerSecret=%ss peakRSS=%dMB results=%s mismatches=%s\n" \
  "$SPEC" "$wall" "$per_secret" "$pre_reveal" "$pre_secret" "$((peak/1024))" "$n" "$bad"
grep -E 'CACHE|NET|TIMING' "$AE" || true
[ "$bad" -eq 0 ]
