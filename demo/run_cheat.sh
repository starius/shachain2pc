#!/usr/bin/env bash
# Security demo: Alice tries to derive a different index than Bob authorized.
# Each party now supplies its authorized I directly and locally generates the
# canonical circuit, so the two generated circuit digests differ and both sides
# abort before any value is returned.
#
# Run inside the flake shell:  nix develop -c ./demo/run_cheat.sh
set -uo pipefail
cd "$(dirname "$0")/.."

PORT=${PORT:-12346}
I=${I:-1}
I_PRIME=${I_PRIME:-2}
G=${G:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}
E=${E:-abababababababababababababababababababababababababababababababab}

make -s plain mpc || exit 1

echo "ALICE asks for I'=$I_PRIME; BOB authorizes I=$I."
timeout 120 ./.build/party 1 "$PORT" "$I_PRIME" "$G"           >/tmp/cheat_a.out 2>/tmp/cheat_a.err &
APID=$!
sleep 0.3
timeout 120 ./.build/party 2 "$PORT" "$I" "$E" 127.0.0.1 >/tmp/cheat_b.out 2>/tmp/cheat_b.err
B2=$?
wait "$APID"
A2=$?

echo "alice exit code : $A2"
echo "alice stderr    : $(cat /tmp/cheat_a.err)"
echo "bob exit code : $B2"
echo "bob stderr    : $(cat /tmp/cheat_b.err)"
if [ "$A2" -ne 0 ] && [ "$B2" -ne 0 ] &&
   ! grep -q RESULT /tmp/cheat_a.out &&
   ! grep -q RESULT /tmp/cheat_b.out; then
  echo "PASS: wrong-index attempt aborted and no value was derived"
  exit 0
fi
echo "FAIL: cheater obtained a result"
exit 1
