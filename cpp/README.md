# Legacy C++ Implementation

This directory contains the original EMP-based shachain2pc implementation. It is
kept as a legacy reference, test oracle, and source of compatibility probes. The
primary implementation lives in [../rust/](../rust/).

Do not treat this tree as production custody software. It inherits the same
prototype warning as the rest of the repository and is retained mainly to verify
the Rust port and to preserve historical behavior.

## Layout

| Path | Role |
| --- | --- |
| `Makefile` | Legacy build for the C++ party, reference tools, and probe binaries. |
| `demo/` | C++ two-party `party` binary and local demo/measurement scripts. |
| `protocol/` | Bristol circuit loading and shachain circuit generation. |
| `reference/` | Single-party BOLT-03 shachain oracle and reference CLI. |
| `run/` | EMP `emp-ag2pc` session driver for one derivation. |
| `tools/` | Circuit checks, protocol probes, compatibility probes, and the deprecated EMP bootstrap helper. |
| `util/` | Small shared C++ helpers. |

Shared compatibility fixtures are intentionally outside this directory:

- [../compat/](../compat/) contains frozen C++ fixture outputs used by Rust.
- [../patches/](../patches/) contains the EMP patch applied by the nix flake.

## Build

Run from the repository root:

```sh
nix develop -c make -C cpp
```

Or enter the directory first:

```sh
cd cpp
nix develop -c make
```

The nix flake builds the pinned, patched EMP stack and exports `EMP_PREFIX`.
Without nix, `tools/bootstrap-emp.sh` is a deprecated fallback that installs the
same EMP pins under `cpp/.deps/emp`.

The main binaries are written to `cpp/.build/`:

- `.build/party` - legacy C++ two-party derivation binary.
- `.build/ref_cli` - single-party reference oracle.
- `.build/ref_kat` - BOLT-03 reference-vector test.
- `.build/verify_circuit` - plaintext circuit/reference verifier.
- `.build/*_probe` - C++ probe binaries used by compatibility tests.

## Run

From the repository root:

```sh
nix develop -c ./cpp/demo/run_demo.sh
nix develop -c ./cpp/demo/run_cheat.sh
```

Manual two-party run:

```sh
cpp/.build/party 1 12345 ffffffffffff <aliceShareHex>
cpp/.build/party 2 12345 ffffffffffff <bobShareHex> 127.0.0.1
```

Both sides must pass the same authorized index. `I = 0` reveals the root seed and
is refused unless both sides pass `--allow-seed-reveal`.

## Tests

Reference and circuit checks:

```sh
nix develop -c make -C cpp test
```

Selected live checks:

```sh
nix develop -c make -C cpp test-cache-tamper
nix develop -c make -C cpp test-ag2pc-probe
nix develop -c make -C cpp test-ag2pc-compute-probe
```

Cross-mode scripts require the Rust `party` release binary as well as the C++
binary:

```sh
nix develop -c cargo build --manifest-path rust/Cargo.toml \
  -p shachain2pc-party --release
nix develop -c make -C cpp .build/party .build/ref_cli
nix develop -c ./cpp/demo/cross_mode_smoke.sh
```

## Status

The C++ implementation remains useful for:

- reference vectors and plaintext circuit verification;
- live C++/Rust compatibility checks for protocol boundaries;
- historical performance comparisons;
- preserving notes about the EMP backend behavior.

New daemon work, gRPC JobStream transport work, encrypted DB work, and
production hardening should happen in Rust.
