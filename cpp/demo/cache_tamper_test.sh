#!/usr/bin/env bash
# Safety test for adaptive-cache mode: a malicious party that garbles a steered
# tile step from a reused authenticated cache node must abort with no output. The
# default range is an aligned 256-leaf subtree, which the cache covers with a
# recursive tile tree (1 upper tile + 16 bottom tiles); we tamper both an upper
# (intermediate-root) tile and a bottom (leaf) tile and require both to abort.
# Usage: cache_tamper_test.sh <lo-hi> [upper_step] [bottom_step] [portbase] [trunk_chunk] [tile_fanout]
set -euo pipefail
cd "$(dirname "$0")/.."

SPEC="${1:-ffffffffff00-ffffffffffff}"
UPPER_STEP="${2:-0}"    # branch instance 0 = the top tile (intermediate roots)
BOTTOM_STEP="${3:-1}"   # branch instance 1 = the first bottom (leaf) tile
PORT="${4:-28680}"
TCB="${5:-16}"
TF="${6:-16}"
AS=$(printf 'aa%.0s' {1..32})
BS=$(printf 'ab%.0s' {1..32})

if [[ "$SPEC" != *-* ]]; then
  echo "cache_tamper_test.sh requires an inclusive range: LO-HI" >&2
  exit 2
fi
lo_hex=${SPEC%-*}
hi_hex=${SPEC#*-}
lo=$((16#$lo_hex))
hi=$((16#$hi_hex))
if (( lo > hi )); then
  echo "cache_tamper_test.sh range LO must be <= HI" >&2
  exit 2
fi
expected=$((hi - lo + 1))

if [ ! -x ./.build/party ] || [ ! -x ./.build/ref_cli ]; then
  make .build/party .build/ref_cli >/dev/null
fi

# run_pair <mode> <port> <tamper_step>  (mode: control|tamper; step ignored if control)
run_pair() {
  local mode=$1 port=$2 step=$3
  local AO AE BO BE AR BR
  AO=$(mktemp); AE=$(mktemp); BO=$(mktemp); BE=$(mktemp)
  AR=$(mktemp); BR=$(mktemp)

  local -a alice_extra=()
  if [ "$mode" = tamper ]; then
    alice_extra=(SHACHAIN2PC_TAMPER="$step")
  fi

  env SHACHAIN2PC_CACHE=1 SHACHAIN2PC_CHUNK_BLOCKS="$TCB" \
    SHACHAIN2PC_TILE_FANOUT="$TF" "${alice_extra[@]}" \
    ./.build/party 1 "$port" "$SPEC" "$AS" >"$AO" 2>"$AE" &
  local ap=$!
  sleep 0.3
  set +e
  env SHACHAIN2PC_CACHE=1 SHACHAIN2PC_CHUNK_BLOCKS="$TCB" \
    SHACHAIN2PC_TILE_FANOUT="$TF" \
    ./.build/party 2 "$port" "$SPEC" "$BS" 127.0.0.1 >"$BO" 2>"$BE"
  local brc=$?
  wait "$ap"; local arc=$?
  set -e

  grep '^RESULT ' "$AO" >"$AR" || true
  grep '^RESULT ' "$BO" >"$BR" || true
  local an bn
  an=$(wc -l <"$AR")
  bn=$(wc -l <"$BR")
  local label="$mode"
  [ "$mode" = tamper ] && label="tamper@$step"
  echo "$label: ALICE rc=$arc results=$an; BOB rc=$brc results=$bn"

  if [ "$mode" = control ]; then
    local bad=0
    if [ "$arc" -ne 0 ] || [ "$brc" -ne 0 ]; then bad=1; fi
    if [ "$bn" -ne "$expected" ]; then bad=1; fi
    if ! diff -q "$AR" "$BR" >/dev/null; then bad=1; fi
    while read -r tag I val; do
      [ "$tag" = RESULT ] || continue
      ref=$(./.build/ref_cli "$AS" "$BS" "$I")
      [ "$val" = "$ref" ] || bad=1
    done <"$BR"
    rm -f "$AO" "$AE" "$BO" "$BE" "$AR" "$BR"
    [ "$bad" -eq 0 ]
    return
  fi

  local ok=0
  if [ "$arc" -ne 0 ] && [ "$brc" -ne 0 ] && [ "$an" -eq 0 ] && [ "$bn" -eq 0 ]; then
    ok=1
  fi
  if [ "$ok" -ne 1 ]; then
    echo "--- ALICE stderr ---"; cat "$AE"
    echo "--- BOB stderr ---"; cat "$BE"
  fi
  rm -f "$AO" "$AE" "$BO" "$BE" "$AR" "$BR"
  [ "$ok" -eq 1 ]
}

echo "cache tamper test: range=$SPEC chunk=$TCB fanout=$TF (upper step=$UPPER_STEP, bottom step=$BOTTOM_STEP)"
run_pair control "$PORT" -1
run_pair tamper "$((PORT + 1))" "$UPPER_STEP"
run_pair tamper "$((PORT + 2))" "$BOTTOM_STEP"
echo "CACHE TAMPER: upper + bottom tile tamper both aborted with no output -> SAFE"
