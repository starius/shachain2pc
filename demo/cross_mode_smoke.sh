#!/usr/bin/env bash
# Run C++<->Rust party smoke tests in both role directions and verify every
# RESULT against ref_cli.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CPP_BIN="${CPP_BIN:-$ROOT/.build/party}"
RUST_BIN="${RUST_BIN:-$ROOT/rust/target/release/party}"
REF_BIN="${REF_BIN:-$ROOT/.build/ref_cli}"

if [[ ! -x "$CPP_BIN" ]]; then
  echo "missing C++ party binary: $CPP_BIN" >&2
  echo "build it with: nix develop -c make .build/party .build/ref_cli" >&2
  exit 1
fi
if [[ ! -x "$RUST_BIN" ]]; then
  echo "missing Rust party binary: $RUST_BIN" >&2
  echo "build it with: nix develop -c cargo build -p shachain2pc-party --release" >&2
  exit 1
fi
if [[ ! -x "$REF_BIN" ]]; then
  echo "missing reference binary: $REF_BIN" >&2
  echo "build it with: nix develop -c make .build/ref_cli" >&2
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

verify_results() {
  local name="$1"
  local spec="$2"
  local bob_out="$3"
  local fail=0

  while read -r tag first second; do
    [[ "$tag" == "RESULT" ]] || continue
    local index value
    if [[ -z "${second:-}" ]]; then
      index="$spec"
      value="$first"
    else
      index="$first"
      value="$second"
    fi
    local ref
    ref="$("$REF_BIN" "$ASHARE" "$BSHARE" "$index")"
    if [[ "$value" != "$ref" ]]; then
      echo "MISMATCH $name I=$index got=$value ref=$ref" >&2
      fail=1
    fi
  done < <(grep '^RESULT ' "$bob_out")

  return "$fail"
}

run_pair() {
  local name="$1"
  local alice_bin="$2"
  local bob_bin="$3"
  local spec="$4"
  shift 4
  local -a env_args=("$@")
  local port
  port="$(free_port)"
  local ao="$TMPDIR/$name.alice.out"
  local ae="$TMPDIR/$name.alice.err"
  local bo="$TMPDIR/$name.bob.out"
  local be="$TMPDIR/$name.bob.err"

  env "${env_args[@]}" "$alice_bin" 1 "$port" "$spec" "$ASHARE" >"$ao" 2>"$ae" &
  local alice_pid=$!
  sleep 0.2
  set +e
  env "${env_args[@]}" "$bob_bin" 2 "$port" "$spec" "$BSHARE" 127.0.0.1 >"$bo" 2>"$be"
  local bob_rc=$?
  wait "$alice_pid"
  local alice_rc=$?
  set -e

  if [[ "$alice_rc" -ne 0 || "$bob_rc" -ne 0 ]]; then
    echo "FAIL $name: alice_rc=$alice_rc bob_rc=$bob_rc" >&2
    echo "--- alice stderr ---" >&2
    cat "$ae" >&2
    echo "--- bob stderr ---" >&2
    cat "$be" >&2
    return 1
  fi
  if ! diff -u <(grep '^RESULT ' "$ao") <(grep '^RESULT ' "$bo") >/dev/null; then
    echo "FAIL $name: parties disagree" >&2
    diff -u <(grep '^RESULT ' "$ao") <(grep '^RESULT ' "$bo") >&2 || true
    return 1
  fi
  verify_results "$name" "$spec" "$bo"
  echo "ok $name"
}

run_case() {
  local name="$1"
  local spec="$2"
  shift 2
  run_pair "${name}.cpp-alice" "$CPP_BIN" "$RUST_BIN" "$spec" "$@"
  run_pair "${name}.rust-alice" "$RUST_BIN" "$CPP_BIN" "$spec" "$@"
}

run_case single1 1
run_case single3 3
run_case range 1-3
run_case chunk 3 SHACHAIN2PC_CHUNK_BLOCKS=1
run_case tree 2-3 SHACHAIN2PC_TREE=1
run_case cache 10-1f \
  SHACHAIN2PC_CACHE=1 \
  SHACHAIN2PC_CHUNK_BLOCKS=16 \
  SHACHAIN2PC_TILE_FANOUT=16
# 1024-leaf aligned subtree (depth 10): exercises a multi-level recursive tile
# cover (partial top height 2, then two height-4 levels), unlike the single
# 16-leaf tile above. Opt-in via CROSS_MODE_BIG=1 since it runs 1024 secrets.
if [[ "${CROSS_MODE_BIG:-0}" == "1" ]]; then
  run_case cache1024 800000000000-8000000003ff \
    SHACHAIN2PC_CACHE=1 \
    SHACHAIN2PC_CHUNK_BLOCKS=16 \
    SHACHAIN2PC_TILE_FANOUT=16
fi

echo "cross-mode smoke passed"
