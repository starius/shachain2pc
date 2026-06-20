#!/usr/bin/env bash
# Fetch and build the emp-toolkit malicious-2PC stack (emp-tool, emp-ot,
# emp-ag2pc = authenticated garbling, WRK17) into ./.deps/emp.
#
# Run under the flake shell:  nix develop -c ./tools/bootstrap-emp.sh
#
# Pinned to a commit set known to build together.
#
# Bumped to the rewritten emp-ag2pc (session/backend "byte-bool" API, KRRW18
# half-gate leaky-AND, SoftSpoken COT). The previous pin (emp-ag2pc 356cfd82,
# fpre.h == upstream 2f079f0) had a latent uninitialized-memory bug: at
# fpre_threads=1 its single-shot C2PC combine fills only permute_batch_size
# triples but reads all num_ands from an un-memset MAC_res, so every circuit with
# num_ands>3100 read uninitialized heap (correct only by zeroed-page luck;
# MALLOC_PERTURB_ flips the output). The rewrite sizes to num_ands with zero-init
# vectors and drops the cap. emp-tool / emp-ot are header/lib deps that emp-ag2pc
# tracks as "main" (per its .github/workflows/*.dep) -- a MOVING target. emp-tool
# main has since renamed the Session concept (DirectCtx/direct_ctx() -> ctx_t/
# ctx()), which fails emp-ag2pc 546d5e4's static_asserts. So we pin emp-tool /
# emp-ot to their main commits as of emp-ag2pc 546d5e4's commit date (2026-06-15),
# the set it was actually written against.
set -euo pipefail

# DEPRECATED: emp is now built reproducibly by the nix flake (packages.emp).
# Running `nix develop` builds the patched emp stack into /nix/store and exports
# EMP_PREFIX pointing at it -- no bootstrap needed. This script is retained only
# as a non-nix fallback; it builds the same pins + patch into ./.deps/emp, the
# layout EMP_PREFIX falls back to when it is unset.
echo "NOTE: bootstrap-emp.sh is deprecated; 'nix develop' builds emp via nix." >&2

# Allow -march=native through nix's cc-wrapper (it strips native arch by default
# via NIX_ENFORCE_NO_NATIVE). We build emp tuned for the host CPU; see FLAGS below.
export NIX_ENFORCE_NO_NATIVE=0

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

case "$(uname -m)" in
  x86_64 | amd64) ;;
  *) echo "emp-ag2pc bootstrap supports x86_64 hosts only." >&2; exit 1 ;;
esac

EMP_TOOL_COMMIT="22e3387dcdf99a7f13b0f5505b4b8d515d4cde3a"   # emp-tool main @ emp-ag2pc 546d5e4 date
EMP_OT_COMMIT="95719775bf18082701d0f544c697b1246a3cb3e4"     # emp-ot   main @ emp-ag2pc 546d5e4 date
EMP_AG2PC_COMMIT="546d5e442e084958d5b5c9ca85c83b91aa3d9cc9"  # emp-ag2pc main @ bump (rewrite)

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

apply_patch_once() { # repo patch
  if git -C "$1" apply --check "$2"; then
    git -C "$1" apply "$2"
  elif ! git -C "$1" apply --reverse --check "$2"; then
    git -C "$1" apply --check "$2"
  fi
}

mkdir -p "$SRC" "$BUILD"
checkout "$SRC/emp-tool"   https://github.com/emp-toolkit/emp-tool.git   "$EMP_TOOL_COMMIT"
checkout "$SRC/emp-ot"     https://github.com/emp-toolkit/emp-ot.git     "$EMP_OT_COMMIT"
checkout "$SRC/emp-ag2pc"  https://github.com/emp-toolkit/emp-ag2pc.git  "$EMP_AG2PC_COMMIT"
apply_patch_once "$SRC/emp-ag2pc" \
  "$ROOT_DIR/patches/emp-ag2pc-546d5e4-align-prg-random-data.patch"

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
