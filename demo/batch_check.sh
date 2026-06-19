#!/usr/bin/env bash
# Run a C++<->C++ batch over an I-range and cross-check every result against the
# single-party reference (ref_cli). Usage: batch_check.sh <I_spec> [port]
set -u
cd "$(dirname "$0")/.."

SPEC="${1:-1-4}"
PORT="${2:-24601}"
# aa^ab = 01: ALICE share = aa..aa, BOB share = ab..ab => seed = 01..01.
ASHARE=$(printf 'aa%.0s' {1..32})
BSHARE=$(printf 'ab%.0s' {1..32})

AO=$(mktemp); AE=$(mktemp); BO=$(mktemp); BE=$(mktemp)
cleanup() { rm -f "$AO" "$AE" "$BO" "$BE"; }
trap cleanup EXIT

# Party 1 (ALICE, garbler, listens) in background; party 2 (BOB) connects.
./.build/party 1 "$PORT" "$SPEC" "$ASHARE" >"$AO" 2>"$AE" &
APID=$!
sleep 0.3
./.build/party 2 "$PORT" "$SPEC" "$BSHARE" 127.0.0.1 >"$BO" 2>"$BE"
BRC=$?
wait "$APID"; ARC=$?

echo "=== ALICE rc=$ARC  BOB rc=$BRC ==="
echo "--- ALICE timing (stderr) ---"; cat "$AE"
echo "--- BOB results (stdout) ---"; cat "$BO"

if [ "$ARC" -ne 0 ] || [ "$BRC" -ne 0 ]; then
  echo "ABORTED"; echo "ALICE stderr:"; cat "$AE"; echo "BOB stderr:"; cat "$BE"
  exit 1
fi

# Cross-check: both parties must agree, and match ref_cli for each I.
echo "--- verification vs ref_cli ---"
fail=0
# Compare only the RESULT lines from each side (ignore any stream noise).
if ! diff -q <(grep '^RESULT ' "$AO") <(grep '^RESULT ' "$BO") >/dev/null; then
  echo "MISMATCH: ALICE and BOB produced different RESULT lines"; fail=1
fi
while read -r tag I val; do
  [ "$tag" = "RESULT" ] || continue
  if [ -z "$val" ]; then val="$I"; I="$SPEC"; fi   # single-index line: "RESULT <hex>"
  ref=$(./.build/ref_cli "$ASHARE" "$BSHARE" "$I")
  if [ "$val" = "$ref" ]; then st=OK; else st="MISMATCH (ref=$ref)"; fail=1; fi
  echo "I=$I  $val  $st"
done < <(grep '^RESULT ' "$BO")

[ "$fail" -eq 0 ] && echo "ALL CORRECT" || echo "FAILURES PRESENT"
exit "$fail"
