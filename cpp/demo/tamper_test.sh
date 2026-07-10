#!/usr/bin/env bash
# Safety test: with block-chunking, a malicious party that garbles a steered flip
# on a CARRIED chunk must cause an ABORT (no value revealed), not a wrong H(I').
# Usage: tamper_test.sh <I_hex> <chunk_to_tamper> [portbase]
set -u
cd "$(dirname "$0")/.."
IDX="${1:-7}"; TC="${2:-1}"; PORT="${3:-25600}"
AS=$(printf 'aa%.0s' {1..32}); BS=$(printf 'ab%.0s' {1..32})
ref=$(./.build/ref_cli "$AS" "$BS" "$IDX")
export SHACHAIN2PC_TIMEOUT_SECS=25 SHACHAIN2PC_CHUNK_BLOCKS=1

run() {  # $1 = tamper alice? (0/1)
  local tenv=""
  [ "$1" = "1" ] && tenv="SHACHAIN2PC_TAMPER=$TC"
  env $tenv ./.build/party 1 "$PORT" "$IDX" "$AS" >/tmp/g_a.out 2>/tmp/g_a.err &
  local ap=$!
  sleep 0.4
  ./.build/party 2 "$PORT" "$IDX" "$BS" 127.0.0.1 >/tmp/g_b.out 2>/tmp/g_b.err
  local brc=$?
  wait "$ap"; local arc=$?
  echo "ALICE_EXIT=$arc BOB_EXIT=$brc"
  PORT=$((PORT + 1))
}

echo "I=$IDX  ref=$ref   (tampering chunk $TC, N=1)"
echo "--- CONTROL (both honest) ---"
rc=$(run 0)
gotb=$(grep -o '^RESULT .*' /tmp/g_b.out | awk '{print $2}')
echo "  $rc  BOB out=[$gotb]"
[ "$gotb" = "$ref" ] && echo "  CONTROL: OK (correct H(I))" || echo "  CONTROL: UNEXPECTED"

echo "--- TAMPER (ALICE garbles a steered flip on carried chunk $TC) ---"
rc=$(run 1)
gotb=$(grep -o '^RESULT .*' /tmp/g_b.out | awk '{print $2}')
echo "  $rc"
echo "  ALICE err: $(grep -iE 'abort|error|cheat|mac|check' /tmp/g_a.err | tail -1)"
echo "  BOB   err: $(grep -iE 'abort|error|cheat|mac|check' /tmp/g_b.err | tail -1)"
echo "  BOB out=[$gotb]"
if [ -z "$gotb" ]; then
  echo "  TAMPER: ABORTED, no value revealed -> SAFE"
elif [ "$gotb" = "$ref" ]; then
  echo "  TAMPER: produced correct H(I) (tamper had no effect)"
else
  echo "  TAMPER: !!! revealed STEERED $gotb != ref -> INSECURE !!!"
fi
