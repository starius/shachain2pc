#!/usr/bin/env bash
# Security demo: a malicious garbler tries to evaluate a DIFFERENT function than
# the agreed circuit (a tampered copy with identical gate/wire counts, so the
# protocol still runs to completion). Authenticated garbling must detect the
# deviation -- the honest evaluator aborts and learns nothing, rather than
# returning a value the cheater steered. This is the property a semi-honest
# garbled-circuit protocol lacks.
#
# Run inside the flake shell:  nix develop -c ./demo/run_cheat.sh
set -uo pipefail
cd "$(dirname "$0")/.."

PORT=${PORT:-12346}
I=${I:-1}
G=${G:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}
E=${E:-abababababababababababababababababababababababababababababababab}

make -s plain mpc || exit 1

./.build/gen_circuit "$I" .build/cheat_good.txt    || exit 1
./.build/tamper_circuit .build/cheat_good.txt .build/cheat_bad.txt || exit 1

echo "ALICE (garbler) uses a tampered circuit; BOB uses the agreed one."
# ALICE garbles the tampered circuit; BOB evaluates the honest agreed circuit.
timeout 120 ./.build/party 1 "$PORT" .build/cheat_bad.txt  "$G"           >/tmp/cheat_a.out 2>/tmp/cheat_a.err &
sleep 0.3
timeout 120 ./.build/party 2 "$PORT" .build/cheat_good.txt "$E" 127.0.0.1 >/tmp/cheat_b.out 2>/tmp/cheat_b.err
B2=$?
wait

echo "bob exit code : $B2"
echo "bob stderr    : $(cat /tmp/cheat_b.err)"
if [ "$B2" -ne 0 ] && ! grep -q RESULT /tmp/cheat_b.out; then
  echo "PASS: cheating detected; BOB aborted and derived no value"
  exit 0
fi
echo "FAIL: cheater obtained a result"
exit 1
