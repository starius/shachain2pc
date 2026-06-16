#!/usr/bin/env bash
# Honest two-party derivation. ALICE (garbler) and BOB (evaluator) each hold one
# seed share and jointly evaluate the agreed circuit for index I under
# malicious-secure authenticated garbling; both obtain H(I). The result is
# cross-checked against the single-party reference oracle.
#
# Run inside the flake shell:  nix develop -c ./demo/run_demo.sh
set -uo pipefail
cd "$(dirname "$0")/.."

PORT=${PORT:-12345}
I=${I:-ffffffffffff}  # default: StartIndex = 2^48-1 (the first revealed secret)
# Two seed shares; the seed is their XOR. Neither party sees the other's share.
G=${G:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}
E=${E:-abababababababababababababababababababababababababababababababab}

make -s plain mpc || exit 1

REF=$(./.build/ref_cli "$G" "$E" "$I") || exit 1

./.build/party 1 "$PORT" "$I" "$G"            >/tmp/demo_a.out 2>/dev/null &
sleep 0.3
./.build/party 2 "$PORT" "$I" "$E" 127.0.0.1  >/tmp/demo_b.out 2>/dev/null
wait

A=$(awk '/RESULT/{print $2}' /tmp/demo_a.out)
B=$(awk '/RESULT/{print $2}' /tmp/demo_b.out)
echo "index I    : $I"
echo "reference  : $REF"
echo "alice  H(I): ${A:-<none>}"
echo "bob    H(I): ${B:-<none>}"
if [ "$A" = "$REF" ] && [ "$B" = "$REF" ]; then
  echo "PASS: both parties derived H(I), equal to the reference"
  exit 0
fi
echo "FAIL"
exit 1
