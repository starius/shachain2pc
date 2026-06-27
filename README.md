# shachain2pc

> Warning: this repository is AI-written demo / proof-of-concept code. It has
> not received deep human cryptographic or Lightning security review and must
> not be used to protect real funds without that review and substantial
> production hardening.

shachain2pc is a maliciously-secure two-party implementation of the BOLT-03
shachain per-commitment-secret derivation. Two parties hold XOR shares of the
shachain seed and jointly derive an authorized secret
`generate_from_seed(seed, index)` without either party learning the seed or
being able to steer the computation to an unauthorized future index.

The active implementation is Rust. The original EMP-based C++ implementation is
kept in [cpp/](cpp/) as a legacy reference and compatibility oracle.

## Security Model

For a requested index, both parties independently build the same fixed
SHA-256-chain circuit. The index-dependent shachain bit flips are public
constants in that circuit, not private inputs controlled by either party. The
parties bind the session to the circuit digest and evaluate it with
authenticated-garbling machinery that returns a value only if the authenticated
state checks out.

The daemon design adds these operational invariants:

- The daemon is not the authority for Lightning channel state. Reveal calls must
  include the caller's expected next reveal index; a DB rollback must not let the
  daemon reveal ahead.
- Precomputed unrevealed nodes are stored as authenticated shares, not
  cleartext future secrets.
- A fixed per-channel Delta is derived from the local master secret. All
  per-session garbling, OT, and preprocessing randomness remains fresh.
- The persistent DB is a recovery cache. Losing its tail may force recomputation
  through MPC, but must not produce an incorrect secret.
- Peer-to-peer daemon traffic should use mutual TLS. The local control API uses
  loopback TCP with a cookie file in this prototype.

## Repository Layout

| Path | Role |
| --- | --- |
| [rust/](rust/) | Primary implementation: crates, binaries, tests, and benchmarks. |
| [cpp/](cpp/) | Legacy C++ EMP implementation and C++ compatibility probes. |
| [compat/](compat/) | Compatibility specs and frozen C++ probe fixtures used by Rust tests. |
| [docs/](docs/) | Design notes, security notes, migration plans, and benchmark reports. |

## Rust Architecture

The Rust implementation is split so protocol logic is not tied to a concrete
network runner:

- `shachain2pc-mpc-core` contains pure, state-passing protocol handlers and the
  heavy cryptographic state machines. Transitions take typed state and messages
  and return new state plus outbound messages or errors.
- `shachain2pc-mpc-types` defines typed protobuf messages for MPC framing.
- `shachain2pc-mpc-runner` drives the pure protocol over transport traits.
- Transport and byte compatibility live below the runner, so the same protocol
  can run over the legacy EMP/TCP byte stream or over daemon gRPC JobStream.

The higher-level crates build on that split:

- `shachain2pc-circuit` builds and checks the shachain SHA-256 circuits.
- `shachain2pc-emp-wire` provides EMP-compatible byte and transcript IO.
- `shachain2pc-emp-compat` provides the Rust AG2PC compatibility layer.
- `shachain2pc-party` exposes the standalone two-party derivation binary and
  library job helpers.
- `shachain2pc-daemon` implements the long-running daemon, CLI, encrypted DB,
  background precompute scheduler, gRPC peer protocol, and integration tests.

See [rust/README.md](rust/README.md) for crate-by-crate details, commands,
tests, and benchmarks.

## Build

The repo uses a nix flake to pin the C/C++ toolchain, Rust toolchain, OpenSSL,
protobuf, and the EMP dependency stack.

```sh
nix develop -c cargo build --manifest-path rust/Cargo.toml --release
```

The main Rust binaries are:

- `rust/target/release/party` - standalone two-party derivation tool.
- `rust/target/release/shachain-daemon` - daemon process.
- `rust/target/release/shachain-cli` - local daemon control CLI.

The legacy C++ implementation can be built separately:

```sh
nix develop -c make -C cpp
```

## Test

Run the Rust workspace tests:

```sh
nix develop -c cargo test --manifest-path rust/Cargo.toml
```

Run the daemon integration suite:

```sh
nix develop -c cargo test --manifest-path rust/Cargo.toml \
  -p shachain2pc-daemon --test daemon_pair -- --nocapture
```

The daemon benchmark cases are ignored by default. Run them explicitly and tune
the environment variables documented in [rust/README.md](rust/README.md).

The legacy C++ reference checks are:

```sh
nix develop -c make -C cpp test
```

## Run

For the standalone Rust party tool, start Alice first and then Bob. Both parties
must pass the same authorized index.

```sh
rust/target/release/party 1 12345 ffffffffffff <aliceShareHex>
rust/target/release/party 2 12345 ffffffffffff <bobShareHex> 127.0.0.1
```

Each share is 32 bytes encoded as 64 hex characters. The shachain seed is the XOR
of the two shares.

For the daemon, build `shachain-daemon` and `shachain-cli`, start one daemon per
party with a master secret, peer URL, local control address, and worker count,
then use the CLI to enable channels, inspect status, and reveal authorized
secrets. The detailed daemon options and a local two-daemon workflow are in
[rust/README.md](rust/README.md).

## Assumptions And Limits

- Two parties only: role 1 is Alice/garbler and role 2 is Bob/evaluator.
- The code is a research prototype, not audited production custody software.
- `I = 0` reveals the root seed and is refused by default.
- A revealed shachain secret naturally derives its descendants; callers must
  enforce Lightning's reveal order.
- Remote deployments are latency-sensitive. Cached reveal is about two RTTs in
  current measurements; one-H precompute is a high-round protocol and should run
  ahead of demand.
- Worker count is operator-managed. The daemon reports RSS and worker state but
  does not enforce a hard RAM cap.
