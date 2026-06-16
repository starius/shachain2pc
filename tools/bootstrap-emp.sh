#!/usr/bin/env bash
# Fetch and build the emp-toolkit malicious-2PC stack (emp-tool, emp-ot,
# emp-ag2pc = authenticated garbling, WRK17) into ./.deps/emp.
#
# Run under the flake shell:  nix develop -c ./tools/bootstrap-emp.sh
#
# Pinned to a commit set known to build together.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

case "$(uname -m)" in
  x86_64 | amd64) ;;
  *) echo "emp-ag2pc bootstrap supports x86_64 hosts only." >&2; exit 1 ;;
esac

EMP_TOOL_COMMIT="11093a7d2160e7e7a4dcae3ffd9e6935bf2b8c1c"
EMP_OT_COMMIT="52b32c8371c09c1567e3d650c0f0adfbb229a270"
EMP_AG2PC_COMMIT="356cfd824772af9334ac9a994d1eec17ab5f565a"

SRC="${ROOT_DIR}/.sources"
PREFIX="${ROOT_DIR}/.deps/emp"
BUILD="${ROOT_DIR}/.build/emp-bootstrap"
FLAGS="-mssse3 -msse4.1 -maes -mpclmul"

checkout() { # path url commit
  if [[ ! -d "$1/.git" ]]; then rm -rf "$1"; git clone "$2" "$1"; fi
  git -C "$1" fetch --tags origin
  git -C "$1" checkout --detach "$3"
}

mkdir -p "$SRC" "$BUILD"
checkout "$SRC/emp-tool"   https://github.com/emp-toolkit/emp-tool.git   "$EMP_TOOL_COMMIT"
checkout "$SRC/emp-ot"     https://github.com/emp-toolkit/emp-ot.git     "$EMP_OT_COMMIT"
checkout "$SRC/emp-ag2pc"  https://github.com/emp-toolkit/emp-ag2pc.git  "$EMP_AG2PC_COMMIT"

rm -rf "$PREFIX"; mkdir -p "$PREFIX"

for pkg in emp-tool emp-ot emp-ag2pc; do
  cmake -S "$SRC/$pkg" -B "$BUILD/$pkg" -GNinja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_CXX_FLAGS="$FLAGS" \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" \
    -DCMAKE_PREFIX_PATH="$PREFIX"
  # emp-tool needs an explicit build of its lib target; the others are header/install.
  if [[ "$pkg" == "emp-tool" ]]; then
    cmake --build "$BUILD/$pkg" --target emp-tool
  fi
  cmake --install "$BUILD/$pkg"
done

echo "emp stack installed at $PREFIX"
