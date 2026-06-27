#!/usr/bin/env bash
# Fetch and build the emp-toolkit malicious-2PC stack (emp-tool, emp-ot,
# emp-ag2pc = authenticated garbling, WRK17) into cpp/.deps/emp.
#
# Run under the flake shell:  nix develop -c ./cpp/tools/bootstrap-emp.sh
#
# Pinned to a commit set known to build together.
#
# Pinned to the current upstream emp-tool / emp-ot / emp-ag2pc session backend
# API. These repositories track each other closely, so keep this commit set in
# sync with the nix flake rather than mixing arbitrary main revisions.
set -euo pipefail

# DEPRECATED: emp is now built reproducibly by the nix flake (packages.emp).
# Running `nix develop` builds the pinned emp stack into /nix/store and exports
# EMP_PREFIX pointing at it -- no bootstrap needed. This script is retained only
# as a non-nix fallback; it builds the same pins into cpp/.deps/emp, the layout
# EMP_PREFIX falls back to when it is unset.
echo "NOTE: bootstrap-emp.sh is deprecated; 'nix develop' builds emp via nix." >&2

# Allow -march=native through nix's cc-wrapper (it strips native arch by default
# via NIX_ENFORCE_NO_NATIVE). We build emp tuned for the host CPU; see FLAGS below.
export NIX_ENFORCE_NO_NATIVE=0

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

case "$(uname -m)" in
  x86_64 | amd64) ;;
  *) echo "emp-ag2pc bootstrap supports x86_64 hosts only." >&2; exit 1 ;;
esac

EMP_TOOL_COMMIT="2ea73a31c54091bd15979ff884e24fa77c3f9673"
EMP_OT_COMMIT="39b207ec320001c0901c62819bf083194026b6a9"
EMP_AG2PC_COMMIT="a245ca0f67abaf2d48c711e3c050ce961e60ad29"

# emp-tool commit that still ships the legacy Bristol circuit files (the new
# emp-tool dropped them); used below to restore sha-256.txt for protocol/.
EMP_TOOL_LEGACY_CIRCUITS_COMMIT="11093a7d2160e7e7a4dcae3ffd9e6935bf2b8c1c"

SRC="${ROOT_DIR}/.sources"
PREFIX="${ROOT_DIR}/.deps/emp"
BUILD="${ROOT_DIR}/.build/emp-bootstrap"
# Tune for the host CPU. -march=native is a superset of the old portable baseline
# (ssse3/sse4.1/sse4.2/aes/pclmul) plus AVX2/FMA/BMI2 where available, which the
# COT (SoftSpoken) and GF/garbling hot loops vectorize on. Survives nix's wrapper
# thanks to NIX_ENFORCE_NO_NATIVE=0 above. We pass it via CMAKE_CXX_FLAGS and keep
# EMP_TOOL_NATIVE_ARCH=OFF so emp doesn't add a second (possibly different) arch
# flag. Release already implies -O3 -DNDEBUG.
FLAGS="-march=native"

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
    -DCMAKE_PREFIX_PATH="$PREFIX" \
    -DCMAKE_INSTALL_LIBDIR=lib \
    -DEMP_TOOL_NATIVE_ARCH=OFF \
    -DEMP_TOOL_BUILD_TESTS=OFF -DEMP_TOOL_BUILD_BENCHMARKS=OFF \
    -DEMP_OT_BUILD_TESTS=OFF \
    -DEMP_AG2PC_BUILD_TESTS=OFF -DEMP_AG2PC_BUILD_EXAMPLES=OFF -DEMP_AG2PC_BUILD_BENCHES=OFF
  # Build each package's default targets before install. emp-tool AND (since the
  # bump) emp-ot ship compiled static libs that must exist before cmake --install;
  # emp-ag2pc is header-only so this is a near no-op there. Tests are off
  # (BUILD_TESTING=OFF) so the default target excludes them.
  cmake --build "$BUILD/$pkg" -j
  cmake --install "$BUILD/$pkg"
done

# emp-ag2pc is an INTERFACE (header-only) target whose cmake install does not copy
# its headers under this prefix layout; copy them explicitly so
# <emp-ag2pc/emp-ag2pc.h> resolves from $PREFIX/include.
cp -r "$SRC/emp-ag2pc/emp-ag2pc" "$PREFIX/include/"

# The current emp-tool no longer ships the legacy Bristol circuit files, but
# protocol/circuit_gen still loads the standard sha-256.txt. Restore it from the
# last emp-tool commit that carried it, at the path the loader expects.
SHA_DIR="$PREFIX/include/emp-tool/circuits/files/bristol_format"
mkdir -p "$SHA_DIR"
git -C "$SRC/emp-tool" cat-file -p \
  "${EMP_TOOL_LEGACY_CIRCUITS_COMMIT}:emp-tool/circuits/files/bristol_format/sha-256.txt" \
  > "$SHA_DIR/sha-256.txt"

echo "emp stack installed at $PREFIX"
