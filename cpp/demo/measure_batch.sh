#!/usr/bin/env bash
# Run a C++<->C++ batch over an I-range, capture the timing split AND the peak
# RSS of both parties (via /proc VmHWM), and cross-check every result vs ref_cli.
# Usage: measure_batch.sh <I_spec> [port]
set -u
cd "$(dirname "$0")/.."

SPEC="${1:-fffffffffffe-ffffffffffff}"
PORT="${2:-24701}"
ASHARE=$(printf 'aa%.0s' {1..32})
BSHARE=$(printf 'ab%.0s' {1..32})

AO=$(mktemp); AE=$(mktemp); BO=$(mktemp); BE=$(mktemp)
AH=$(mktemp); BH=$(mktemp)
cleanup() { rm -f "$AO" "$AE" "$BO" "$BE" "$AH" "$BH"; }
trap cleanup EXIT

# Poll VmHWM (kB, monotonic peak) for a pid until it exits; write the peak.
poll_hwm() {
  local pid=$1 out=$2 hwm=0 cur
  while [ -d "/proc/$pid" ]; do
    cur=$(awk '/VmHWM/{print $2}' "/proc/$pid/status" 2>/dev/null)
    [ -n "$cur" ] && hwm=$cur
    sleep 0.1
  done
  echo "$hwm" > "$out"
}

./.build/party 1 "$PORT" "$SPEC" "$ASHARE" >"$AO" 2>"$AE" &
APID=$!
poll_hwm "$APID" "$AH" &
sleep 0.3
./.build/party 2 "$PORT" "$SPEC" "$BSHARE" 127.0.0.1 >"$BO" 2>"$BE" &
BPID=$!
poll_hwm "$BPID" "$BH" &
wait "$BPID"; BRC=$?
wait "$APID"; ARC=$?
wait  # pollers

echo "=== ALICE rc=$ARC  BOB rc=$BRC ==="
echo "--- ALICE timing (stderr) ---"; cat "$AE"
ahwm=$(cat "$AH" 2>/dev/null || echo 0); bhwm=$(cat "$BH" 2>/dev/null || echo 0)
printf -- "--- peak RSS: ALICE %d MB   BOB %d MB ---\n" $((ahwm/1024)) $((bhwm/1024))

if [ "$ARC" -ne 0 ] || [ "$BRC" -ne 0 ]; then
  echo "ABORTED"; echo "ALICE stderr:"; cat "$AE"; echo "BOB stderr:"; cat "$BE"
  exit 1
fi

echo "--- verification vs ref_cli ---"
fail=0
if ! diff -q <(grep '^RESULT ' "$AO") <(grep '^RESULT ' "$BO") >/dev/null; then
  echo "MISMATCH: ALICE and BOB produced different RESULT lines"; fail=1
fi
while read -r tag I val; do
  [ "$tag" = "RESULT" ] || continue
  if [ -z "$val" ]; then val="$I"; I="$SPEC"; fi
  ref=$(./.build/ref_cli "$ASHARE" "$BSHARE" "$I")
  if [ "$val" = "$ref" ]; then st=OK; else st="MISMATCH (ref=$ref)"; fail=1; fi
  echo "I=$I  $val  $st"
done < <(grep '^RESULT ' "$BO")

[ "$fail" -eq 0 ] && echo "ALL CORRECT" || echo "FAILURES PRESENT"
exit "$fail"
