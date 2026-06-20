#!/usr/bin/env bash
# Run C++<->Rust party tamper smokes in both role directions. Alice gets the
# test-only SHACHAIN2PC_TAMPER hook; both parties must abort without RESULT.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CPP_BIN="${CPP_BIN:-$ROOT/.build/party}"
RUST_BIN="${RUST_BIN:-$ROOT/rust/target/release/party}"

if [[ ! -x "$CPP_BIN" ]]; then
  echo "missing C++ party binary: $CPP_BIN" >&2
  echo "build it with: nix develop -c make .build/party" >&2
  exit 1
fi
if [[ ! -x "$RUST_BIN" ]]; then
  echo "missing Rust party binary: $RUST_BIN" >&2
  echo "build it with: nix develop -c cargo build -p shachain2pc-party --release" >&2
  exit 1
fi

ASHARE=$(printf 'aa%.0s' {1..32})
BSHARE=$(printf 'ab%.0s' {1..32})

TMPDIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMPDIR"
}
trap cleanup EXIT

free_port() {
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

run_abort_pair() {
  local name="$1"
  local alice_bin="$2"
  local bob_bin="$3"
  local spec="$4"
  local tamper_step="$5"
  shift 5
  local -a env_args=("$@")
  local port
  port="$(free_port)"
  local ao="$TMPDIR/$name.alice.out"
  local ae="$TMPDIR/$name.alice.err"
  local bo="$TMPDIR/$name.bob.out"
  local be="$TMPDIR/$name.bob.err"

  env "${env_args[@]}" SHACHAIN2PC_TAMPER="$tamper_step" \
    "$alice_bin" 1 "$port" "$spec" "$ASHARE" >"$ao" 2>"$ae" &
  local alice_pid=$!
  sleep 0.2
  set +e
  env "${env_args[@]}" \
    "$bob_bin" 2 "$port" "$spec" "$BSHARE" 127.0.0.1 >"$bo" 2>"$be"
  local bob_rc=$?
  wait "$alice_pid"
  local alice_rc=$?
  set -e

  local alice_results bob_results
  alice_results=$(grep -c '^RESULT ' "$ao" || true)
  bob_results=$(grep -c '^RESULT ' "$bo" || true)
  if [[ "$alice_rc" -eq 0 || "$bob_rc" -eq 0 ||
        "$alice_results" -ne 0 || "$bob_results" -ne 0 ]]; then
    echo "FAIL $name: alice_rc=$alice_rc bob_rc=$bob_rc" >&2
    echo "FAIL $name: alice_results=$alice_results bob_results=$bob_results" >&2
    echo "--- alice stderr ---" >&2
    cat "$ae" >&2
    echo "--- bob stderr ---" >&2
    cat "$be" >&2
    return 1
  fi
  echo "ok $name"
}

run_abort_case() {
  local name="$1"
  local spec="$2"
  local tamper_step="$3"
  shift 3
  run_abort_pair "${name}.cpp-alice" \
    "$CPP_BIN" "$RUST_BIN" "$spec" "$tamper_step" "$@"
  run_abort_pair "${name}.rust-alice" \
    "$RUST_BIN" "$CPP_BIN" "$spec" "$tamper_step" "$@"
}

run_abort_case chunk 7 1 SHACHAIN2PC_CHUNK_BLOCKS=1
run_abort_case tree 2-3 1 SHACHAIN2PC_TREE=1
run_abort_case cache-tile 10-1f 0 \
  SHACHAIN2PC_CACHE=1 \
  SHACHAIN2PC_CHUNK_BLOCKS=16 \
  SHACHAIN2PC_TILE_FANOUT=16
run_abort_case cache-fallback 10-13 0 \
  SHACHAIN2PC_CACHE=1 \
  SHACHAIN2PC_CHUNK_BLOCKS=16 \
  SHACHAIN2PC_TILE_FANOUT=1

echo "cross-mode tamper smoke passed"
