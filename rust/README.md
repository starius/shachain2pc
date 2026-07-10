# Rust Implementation

This directory is the primary shachain2pc implementation. It contains the
standalone party tool, the daemon and CLI, the transport-independent MPC core,
and the tests/benchmarks used for the current development line.

Run commands from the repository root with `--manifest-path rust/Cargo.toml`, or
from this directory with plain `cargo` commands. `nix develop` supplies the Rust
toolchain, OpenSSL, protobuf, and the pinned EMP dependency stack used by the
compatibility tests.

## Crates

| Crate | Purpose |
| --- | --- |
| `shachain2pc-types` | Small shared domain types: roles, 48-bit indices, 32-byte values, constants. |
| `shachain2pc-circuit` | Pure shachain logic, Bristol SHA-256 circuit loading, circuit generation, plaintext checks, and reference helpers. |
| `shachain2pc-emp-wire` | EMP-compatible low-level wire types and byte/transcript IO traits, including reusable channel-backed byte streams. |
| `shachain2pc-mpc-types` | Protobuf-generated typed MPC frames and validation helpers. |
| `shachain2pc-mpc-core` | Sans-IO protocol state machines and crypto primitives: session handshake, MAC checks, GF/AES/MITCCRH helpers, SoftSpoken, triple pool, half-gate/bucketing logic. |
| `shachain2pc-mpc-runner` | Async runner layer that drives pure protocol states over transport traits. |
| `shachain2pc-emp-compat` | Rust AG2PC compatibility layer and C++-fixture/probe differentials. |
| `shachain2pc-party` | Standalone two-party derivation binary plus library helpers for one seed-root, one-H, precompute-path, and reveal jobs. |
| `shachain2pc-daemon` | Long-running service, local CLI, encrypted redb store, gRPC peer API, JobStream MPC transport, precompute scheduler, and integration/benchmark harness. |

The important architectural boundary is `mpc-core` plus `mpc-runner`: protocol
transitions are pure state/message handlers, while async IO and concrete
transports sit outside. This keeps the crypto protocol testable without sockets
and lets the daemon use gRPC JobStream while the standalone party keeps the
legacy EMP/TCP-compatible byte path.

## Build

```sh
nix develop -c cargo build --manifest-path rust/Cargo.toml --release
```

Useful package-scoped builds:

```sh
nix develop -c cargo build --manifest-path rust/Cargo.toml \
  -p shachain2pc-party --release
nix develop -c cargo build --manifest-path rust/Cargo.toml \
  -p shachain2pc-daemon --release
```

## Standalone Party

Alice listens, Bob connects. Both pass the same authorized index. The two
32-byte shares are hex strings; their XOR is the shachain seed.

```sh
rust/target/release/party 1 12345 ffffffffffff <aliceShareHex>
rust/target/release/party 2 12345 ffffffffffff <bobShareHex> 127.0.0.1
```

`I = 0` reveals the root seed and is refused unless both sides pass
`--allow-seed-reveal`. This flag is for compatibility tests only.

Timing flags:

- `SHACHAIN2PC_PHASE_TIMING=1` prints high-level party phase timings.
- `SHACHAIN2PC_COMPAT_TIMING=1` adds AG2PC compatibility subphase timings.

## Daemon And CLI

The daemon has two gRPC surfaces:

- Local control API, used by `shachain-cli`, bound to loopback TCP and protected
  by a cookie file.
- Peer API, used daemon-to-daemon, including JobStream MPC over gRPC. Peer mTLS
  is supported with `--peer-tls-cert`, `--peer-tls-key`, `--peer-tls-ca`, and
  `--peer-tls-domain`.

Each daemon has one master secret. From it the daemon derives:

- the encrypted DB keys;
- per-channel seed shares;
- a fixed per-channel Delta, while all per-session OT/garbling/preprocessing
  randomness remains fresh.

Minimal shape of a local two-daemon setup:

```sh
nix develop -c cargo build --manifest-path rust/Cargo.toml \
  -p shachain2pc-daemon --release

rust/target/release/shachain-daemon \
  --role 1 \
  --db /tmp/shachain-a.redb \
  --master-secret-hex <aliceMasterSecretHex> \
  --listen-local 127.0.0.1:7001 \
  --listen-peer 127.0.0.1:7101 \
  --peer http://127.0.0.1:7102 \
  --mpc-port 7201 \
  --workers 8 \
  --precompute 25

rust/target/release/shachain-daemon \
  --role 2 \
  --db /tmp/shachain-b.redb \
  --master-secret-hex <bobMasterSecretHex> \
  --listen-local 127.0.0.1:7002 \
  --listen-peer 127.0.0.1:7102 \
  --peer http://127.0.0.1:7101 \
  --mpc-port 7202 \
  --workers 8 \
  --precompute 25
```

The daemon writes a control file and cookie file unless explicit paths are
provided. Use the control file with the CLI:

```sh
rust/target/release/shachain-cli --control-file <control-file> status
rust/target/release/shachain-cli --control-file <control-file> \
  channel enable 42 25 64 281474976710656
rust/target/release/shachain-cli --control-file <control-file> channels
rust/target/release/shachain-cli --control-file <control-file> \
  reveal 42 1 1
```

Operational notes:

- `workers` is the concurrency knob. The daemon no longer turns RAM into a
  worker cap; operators size RAM externally.
- Disabled channels drop live session state and stop precomputing.
- Reveals are sequential and must include the externally authorized
  `expected_next_index`.
- Cached reveals use persisted authenticated MAC material plus the re-derived
  per-channel Delta; they do not need a fresh garbling setup.
- After restart, persisted frontier leaves can be revealed. Extending further
  starts a fresh live session and re-warms safely with fresh one-time material.

## Tests

Full workspace:

```sh
nix develop -c cargo test --manifest-path rust/Cargo.toml
```

Common focused checks:

```sh
nix develop -c cargo test --manifest-path rust/Cargo.toml \
  -p shachain2pc-party -- --nocapture

nix develop -c cargo test --manifest-path rust/Cargo.toml \
  -p shachain2pc-daemon --test daemon_pair -- --nocapture

nix develop -c cargo test --manifest-path rust/Cargo.toml \
  -p shachain2pc-emp-compat
```

Some real-circuit and benchmark tests are ignored in the default debug suite
because they are intentionally slow. Run a specific ignored case explicitly:

```sh
nix develop -c cargo test --manifest-path rust/Cargo.toml \
  -p shachain2pc-daemon --test daemon_pair \
  daemon_bench_100_channels_good_case -- --ignored --nocapture
```

Optional live C++ probe tests are feature/env gated. They build the legacy
probes from `cpp/`:

```sh
SHACHAIN2PC_BUILD_CPP_PROBES=1 \
  nix develop -c cargo test --manifest-path rust/Cargo.toml \
  -p shachain2pc-emp-compat --features cpp-probes
```

## Benchmarks

The daemon benchmark harness is in `shachain2pc-daemon/tests/daemon_pair.rs` and
prints JSON results. These tests are ignored by default.

Main environment variables:

- `SHACHAIN_BENCH_CHANNELS` - enabled channel count, default 100.
- `SHACHAIN_BENCH_WORKERS` - configured workers, default 4.
- `SHACHAIN_BENCH_FRONTIER` - target precompute frontier, default 1.
- `SHACHAIN_BENCH_REVEALS` - number of cached reveals to measure.
- `SHACHAIN_BENCH_TIMEOUT_SECS` - wait timeout for frontier fill.
- `SHACHAIN_BENCH_BASE_CHANNEL` - first channel id.

Example:

```sh
SHACHAIN_BENCH_CHANNELS=100 \
SHACHAIN_BENCH_WORKERS=8 \
SHACHAIN_BENCH_FRONTIER=25 \
SHACHAIN_BENCH_REVEALS=100 \
nix develop -c cargo test --manifest-path rust/Cargo.toml \
  -p shachain2pc-daemon --test daemon_pair \
  daemon_bench_100_channels_good_case -- --ignored --nocapture
```

Use `tc netem` outside the test process to measure RTT sensitivity. Current
release measurements show cached reveal is about two RTTs, while one-H
precompute is a high-round operation and should be filled ahead of demand.

## Compatibility With C++

The Rust implementation keeps the C++ implementation as a compatibility oracle,
not as the primary runtime. Frozen fixtures live in `compat/`; optional live
probe tests build binaries under `cpp/.build/`. The standalone `party` binary
keeps the legacy EMP/TCP-compatible byte path, while the daemon precompute path
uses gRPC JobStream.

## Important Invariants

- Never persist or deterministically replay session-local labels, OT material,
  or garbling randomness.
- Persisted frontier nodes must retain `lambda` and authenticated MAC/key
  material; only session-local labels are stripped.
- Persist only revealable target leaves, not trunk/intermediate computation
  parents.
- Reconcile asymmetric frontier state by dropping non-common leaves and jointly
  recomputing.
- Treat every MAC, binding, role, channel, or sequence mismatch as terminal for
  that job/session.
