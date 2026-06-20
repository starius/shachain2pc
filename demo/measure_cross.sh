#!/usr/bin/env bash
# Measure a cache/range spec across backend pairings (rust-rust, cpp-cpp,
# rust-cpp, cpp-rust): wall time, per-secret wall, and correctness vs ref_cli.
# Usage: measure_cross.sh <lo-hi> [ENV=VAL ...]
#   e.g. measure_cross.sh 800000000000-8000000003ff \
#          SHACHAIN2PC_CACHE=1 SHACHAIN2PC_CHUNK_BLOCKS=16 SHACHAIN2PC_TILE_FANOUT=16
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
CPP_BIN="${CPP_BIN:-$ROOT/.build/party}"
RUST_BIN="${RUST_BIN:-$ROOT/rust/target/release/party}"
REF_BIN="${REF_BIN:-$ROOT/.build/ref_cli}"
for b in "$CPP_BIN" "$RUST_BIN" "$REF_BIN"; do
  [[ -x "$b" ]] || { echo "missing binary: $b" >&2; exit 1; }
done

ASHARE=$(printf 'aa%.0s' {1..32})
BSHARE=$(printf 'ab%.0s' {1..32})
SPEC="${1:?usage: measure_cross.sh <lo-hi> [ENV=VAL ...]}"; shift
ENVV=("$@")
lo=$((16#${SPEC%-*})); hi=$((16#${SPEC#*-})); n=$((hi - lo + 1))

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
free_port() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()'; }

measure() { # label alice_bin bob_bin
  local label="$1" abin="$2" bbin="$3"
  local port ao bo t0 t1
  port="$(free_port)"; ao="$TMP/$label.ao"; bo="$TMP/$label.bo"
  # Time the whole pairing: Alice startup + protocol + both parties exiting.
  t0=$(date +%s.%N)
  env "${ENVV[@]}" "$abin" 1 "$port" "$SPEC" "$ASHARE" >"$ao" 2>/dev/null &
  local ap=$!
  sleep 0.3  # let Alice bind the port before Bob connects (constant harness overhead)
  set +e
  env "${ENVV[@]}" "$bbin" 2 "$port" "$SPEC" "$BSHARE" 127.0.0.1 >"$bo" 2>/dev/null
  local brc=$?
  wait "$ap"; local arc=$?
  t1=$(date +%s.%N)
  set -e
  local wall got bad=0
  wall=$(awk "BEGIN{print $t1-$t0}")
  got=$(grep -c '^RESULT ' "$bo" || true)
  # Alice and Bob must agree on every RESULT line...
  local abdiff
  abdiff=$(diff <(grep '^RESULT ' "$ao") <(grep '^RESULT ' "$bo") | grep -c '^[<>]' || true)
  bad=$((bad + abdiff))
  # ...and Bob's RESULTs must match the single-party reference.
  while read -r tag idx val; do
    [[ "$tag" == "RESULT" ]] || continue
    [[ "$val" == "$("$REF_BIN" "$ASHARE" "$BSHARE" "$idx")" ]] || bad=$((bad + 1))
  done <"$bo"
  printf "%-9s wall=%7.2fs perSecret=%ss results=%-5s mismatches=%s rc=%d/%d\n" \
    "$label" "$wall" "$(awk "BEGIN{printf \"%.4f\", $wall/$n}")" "$got" "$bad" "$arc" "$brc"
}

echo "measure-cross spec=$SPEC n=$n env=[${ENVV[*]}]"
measure rust-rust "$RUST_BIN" "$RUST_BIN"
measure cpp-cpp   "$CPP_BIN"  "$CPP_BIN"
measure rust-cpp  "$RUST_BIN" "$CPP_BIN"
measure cpp-rust  "$CPP_BIN"  "$RUST_BIN"
