#!/usr/bin/env bash
# Verify the block-chunked derivation matches the reference across chunk sizes,
# and report round-trips per chunk size. Usage: chunk_check.sh <I_hex> [portbase] [Ns...]
set -u
cd "$(dirname "$0")/.."
IDX="${1:-1f}"; PORTBASE="${2:-25101}"; shift 2 2>/dev/null || shift $#
NS="${*:-1 2 3 5 8 48}"
AS=$(printf 'aa%.0s' {1..32}); BS=$(printf 'ab%.0s' {1..32})
ref=$(./.build/ref_cli "$AS" "$BS" "$IDX")
echo "I=$IDX  ref=$ref"
port=$PORTBASE
fail=0
for N in $NS; do
  bo=$(mktemp); be=$(mktemp)
  SHACHAIN2PC_CHUNK_BLOCKS="$N" ./.build/party 1 "$port" "$IDX" "$AS" >/dev/null 2>/dev/null &
  sleep 0.3
  SHACHAIN2PC_CHUNK_BLOCKS="$N" ./.build/party 2 "$port" "$IDX" "$BS" 127.0.0.1 >"$bo" 2>"$be"
  wait
  got=$(grep '^RESULT' "$bo" | awk '{print $2}')
  rounds=$(grep '^NET' "$be" | sed -E 's/.*rounds=([0-9]+).*/\1/')
  chunks=$(grep 'compute total' "$be" | sed -E 's/.*\(([0-9]+) chunks.*/\1/')
  gt=$(grep 'grand-total' "$be" | awk '{print $3}')
  [ "$got" = "$ref" ] && st=OK || { st="MISMATCH"; fail=1; }
  printf "N=%-3s chunks=%-3s rounds=%-6s wall=%-8s %s\n" "$N" "$chunks" "$rounds" "$gt" "$st"
  rm -f "$bo" "$be"; port=$((port+1))
done
[ "$fail" -eq 0 ] && echo "ALL CHUNK SIZES CORRECT" || echo "FAILURES"
exit "$fail"
