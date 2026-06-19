# shachain2pc

> **Warning:** this repository is AI-written demo / proof-of-concept code. It is
> not production-ready, has not received deep human cryptographic or Lightning
> security review, and must not be used to protect real funds without that
> review and substantial hardening.

A self-contained, **maliciously-secure** two-party computation of the
[BOLT-03](https://github.com/lightning/bolts/blob/master/03-transactions.md)
shachain per-commitment-secret derivation (`generate_from_seed`).

Two parties hold XOR shares of the seed and jointly compute
`H(I) = generate_from_seed(seed, I)` for an agreed index `I` without either
party learning the seed — and, crucially, **without either party being able to
derive a secret for an index that was not authorized**, in particular not a
*future* secret, even if it deviates arbitrarily from the protocol.

## How it works

For each index `I` there is **one fixed boolean circuit**. Each party supplies
the authorized `I` and locally generates that circuit, which computes
`seed = aliceShare ⊕ bobShare` and then `generate_from_seed(seed, I)` with
`I`'s per-link bit-flips baked in as **public constants** (not a controllable
input). The locally generated circuits are digest-checked and then evaluated under
**authenticated garbling** (EMP [`emp-ag2pc`](https://github.com/emp-toolkit/emp-ag2pc),
the WRK17 protocol): the parties evaluate exactly the agreed circuit, or the
protocol **aborts**. So the only reachable output is `H(I)` for the agreed `I` —
there is no steering to another index, and no intermediate hash leaks.

## Security: the attack this stops, and how

A naive garbled-circuit derivation feeds the per-link bit-flip as the garbler's
*private* circuit input (`gIn = gShare ⊕ flip(B)`) and re-inputs the carried
shares between links. Under a malicious adversary that is broken: a cheating
party can (a) garble a different circuit, or (b) XOR an arbitrary mask in place
of the agreed flip, steering the chain to `generate_from_seed(seed, I′)` for an
`I′` it chose and learning that (e.g. future) secret. This is the property a
semi-honest garbled-circuit protocol cannot give.

shachain2pc removes both freedoms:

1. **One fixed, agreed circuit per index.** A derivation of index `I` is a single
   boolean circuit that, from the two seed-share inputs, recomputes
   `seed = gShare ⊕ eShare` and then `generate_from_seed(seed, I)` with `I`'s
   bit-flips baked in as **public constants**. The flips are no longer an input
   anyone controls; they are part of the circuit both parties agree on.
2. **Maliciously-secure evaluation.** The circuit is evaluated with authenticated
   garbling (`emp-ag2pc`). This guarantees the parties evaluate exactly the
   agreed circuit on authenticated inputs, or the protocol **aborts** — a
   cheating garbler cannot substitute a different circuit, and neither party can
   feed an input inconsistent with its authenticated share. So the only reachable
   output is `H(I)` for the agreed `I`; there is no steering to `I′`, and no
   intermediate hash is revealed.

The soundness check is per-AND-gate: the garbler is information-theoretically
MAC-committed (via the WRK17 authenticated AND triples) to each gate's truth
table, so garbling a different function is caught (`emp-ag2pc` reports
`no match GT!`). Failures in the preprocessing phase already terminate the
process (emp's `error()` calls `exit(1)`), so no value is produced. The online
phase is the nuance: this `emp-ag2pc` build *reports* a detected inconsistency on
`std::cout` and then continues with a corrupted value rather than hard-aborting,
and `2pc.h` exposes no status to query. `run/` closes that gap with a
`CheatGuard` that captures the engine's consistency-check output and turns any
detection into a hard abort, so the untrusted value is discarded and never
returned.

The agreed index `I` is chosen out of band; each party passes only an `I` it is
willing to authorize to `party`, which generates the per-index circuit locally.
The two parties exchange a digest of those generated circuits before any
preprocessing and abort immediately on a mismatch. The wrong-index demo
(`demo/run_cheat.sh`) exercises this path: Alice tries `I′` while Bob authorizes
`I`, both sides abort, and no value is returned. This digest check is *not* the
security boundary — authenticated garbling still catches a party that commits to
one circuit and garbles another.

## Why this stack

- **Engine: EMP `emp-ag2pc`** — the canonical, purpose-built malicious 2PC of
  boolean circuits (authenticated garbling). Reusing a vetted engine avoids
  rolling our own malicious crypto, which would not be reliable or secure.
- **Language: C++** — required to use `emp-ag2pc`. We are 2-party only and do
  **not** need post-quantum or threshold security, so we use just the
  malicious-2PC-of-SHA-256 core.
- **Build: nix** — a flake dev shell (`nix develop`) pins the toolchain and
  OpenSSL; `tools/bootstrap-emp.sh` fetches and builds the pinned emp stack into
  `.deps/emp`.

The cryptographic rounds live inside the vetted `emp-ag2pc` engine; the "pure
protocol" this project owns is the circuit/relation definition and the share/IO
layout.

## Layout

| Dir | Role |
| --- | --- |
| `reference/` | single-party `generate_from_seed` oracle + KATs (no MPC), and `ref_cli` |
| `protocol/` | the pure, deterministic part: build the Bristol circuit for index `I` (`bristol.*`, `circuit_gen.*`, `wire_layout.h`) — public flips + a SHA-256 chain over the XOR of the two seed shares — and the input/output wire layout |
| `run/` | drive the two `emp-ag2pc` parties over a socket: generate the circuit for `I`, feed shares, evaluate, obtain `H(I)`, abort on any cheat (`derive.h`) |
| `demo/` | C++ two-party binary (`party`) and the honest / wrong-index demo scripts |
| `rust/` | Rust v1 port: EMP-compatible wire/protocol crates and Rust `party` binary |
| `tools/` | offline checks: bit-convention probe, circuit verifier, circuit tamperer, bandwidth meter |

## Build

Requires nix (for the toolchain and OpenSSL) on an x86-64 host.

```sh
nix develop -c ./tools/bootstrap-emp.sh   # once: fetch + build emp into .deps/emp
nix develop -c make                        # build everything
nix develop -c cargo build --manifest-path rust/Cargo.toml --release
```

The Rust release binary is `rust/target/release/party`. The C++ binary is
`.build/party`.

## Run

```sh
nix develop -c ./demo/run_demo.sh    # honest: both derive H(I) == reference
nix develop -c ./demo/run_cheat.sh   # wrong-index attempt: both abort, no value
```

`run_demo.sh` defaults to `I = ffffffffffff` (StartIndex `2^48−1`, the first
revealed secret: a 48-block chain, ~5.6M gates). Override with env vars, e.g.
`I=1 PORT=12345 nix develop -c ./demo/run_demo.sh`.

To run the parties by hand, each side supplies the same authorized index `I`.
Each process locally generates the canonical circuit for that `I`; no per-index
circuit file is shared or stored. Start party `1` (ALICE, the listener) and
party `2` (BOB) pointed at ALICE's IP:

```sh
# ALICE (listener) and BOB (connects to ALICE's IP):
./.build/party 1 12345 ffffffffffff <aliceShareHex>
./.build/party 2 12345 ffffffffffff <bobShareHex> <alice_ip>
```

The Rust binary uses the same positional form:

```sh
rust/target/release/party 1 12345 ffffffffffff <aliceShareHex>
rust/target/release/party 2 12345 ffffffffffff <bobShareHex> <alice_ip>
```

The two share hexes are each 64 hex chars (32 bytes); the seed is their XOR. On
the same machine, BOB connects to `127.0.0.1` (the default if `<alice_ip>` is
omitted).

### Seed-reveal guard

Index `I = 0` is not a normal per-commitment reveal: `generate_from_seed` runs no
SHA round at `I = 0`, so it returns the shachain seed itself (`aliceShare XOR
bobShare`) — the root that derives every revocation secret. Both the C++ and Rust
`party` refuse it by default, before opening any socket, including any range whose
span contains 0 (e.g. `0-5`):

```sh
.build/party 1 12345 0 <aliceShareHex>
# ABORT I=0 reveals the seed (root of all revocation secrets); re-run with --allow-seed-reveal to proceed
```

For compatibility tests only, pass `--allow-seed-reveal` on each side. The flag is
position-independent:

```sh
.build/party --allow-seed-reveal 1 12345 0 <aliceShareHex>
.build/party 2 12345 0 <bobShareHex> <alice_ip> --allow-seed-reveal
```

Note this guards only the *seed* (the tree root). shachain is itself a tree, so
revealing any `H(I)` lets the recipient derive `H(I')` for every descendant `I'`
of `I` (those that set some of `I`'s trailing-zero bits) — that is inherent to
shachain, not something the MPC can prevent. When precomputing a batch and
revealing a subset over time (shared-trunk / tree mode), the caller must avoid
revealing an ancestor before a still-secret descendant, or accept that the
descendant becomes derivable.

## Tests

```sh
nix develop -c make test     # reference KATs + plaintext circuit verification
nix develop -c make test-cache-tamper  # live cache tamper-abort check
nix develop -c cargo test --manifest-path rust/Cargo.toml
```

`make test` runs, with no network:
- `ref_kat` — the reference vs the five published BOLT-03 generation vectors.
- `verify_circuit` — the generated circuit, plaintext-evaluated against the
  reference across those vectors, popcount 0 and 48, three share splits, and a
  serializer round-trip.

`make test-cache-tamper` runs a local two-party adaptive-cache session, then
reruns it with Alice tampering one cached branch step; the tampered run must abort
on both sides with no `RESULT`.

The Rust tests include live C++/Rust interop for the protocol layers and a
Rust/Rust party E2E test for `I = 1` plus `I = 3` (multi-block chaining). Those
real-circuit debug tests are heavier than the unit/probe tests. For a faster
optimized check, run the specific release test:

```sh
nix develop -c cargo test --release --manifest-path rust/Cargo.toml \
  -p shachain2pc-party rust_party_real_circuits_match_reference
```

The full `I = ffffffffffff` 48-block Rust party test exists but is ignored by
default. It has been run manually in release mode on the current review machine
and matched the reference in about 11-14s.

Set `SHACHAIN2PC_PHASE_TIMING=1` on the Rust `party` processes to print phase
timings to stderr without changing stdout's `RESULT <hex>` output.
Set `SHACHAIN2PC_COMPAT_TIMING=1` as well to print Fpre/C2PC subphase timings.

## Scope and trade-offs

- **2 parties, asymmetric roles** (party 1 = garbler/ALICE, party 2 =
  evaluator/BOB). Not threshold, not post-quantum.
- **Rust v1 is still a compatibility/correctness port, not the final low-memory
  protocol.** The protocol layers are cross-checked against C++ probes, but large
  Rust/Rust real-circuit runs now use Rust-side Fpre chunk sizing to avoid
  regenerating unused preprocessing. Current local release measurements:
  `I=1` Rust/Rust is about 0.28s, `I=3` is about 0.49s, and the full
  `I=ffffffffffff` case is about 11-14s with roughly 1.06 GB peak RSS for
  ALICE and 1.01 GB for BOB. The future streaming / low-memory protocol work
  belongs to a later version.
- **Shared-trunk reuse, and its update budget.** A single derivation recomputes
  from the seed in one circuit (`popcount(I) ≤ 48` SHA-256 blocks). For a batch
  that shares a high-bit prefix, `SHACHAIN2PC_TREE=1` computes the shared trunk
  once and derives each branch from it, carrying the intermediate as an
  **authenticated** wire (malicious-secure — unlike the semi-honest re-input
  cache it generalizes). Reusing such a value is sound, but the bucketing's
  `~2^-ssp` error accumulates as `N · 2^-ssp`, where `N` is the total number of
  `compute_inplace` bucketing instances run against one seed: revealed outputs,
  precomputed-but-unrevealed outputs, aborted attempts, refills, and chunks. The
  current `ssp = 40` (`run::kSsp`) is a demo/research default: with the planned
  cache shape it gives roughly 500k-1M updates at residual `2^-20`, which is not
  a production target for funds. For production, use `ssp ≈ 60-64`, track every
  instance against the per-seed budget, and rotate the seed before crossing the
  chosen risk threshold. The adaptive cache's default trunk chunk size is 1
  (`SHACHAIN2PC_CHUNK_BLOCKS=1`), the simplest low-memory setting. Cross-restart
  persistence of the authenticated cache is still future work. Full analysis and
  the cost trade-off:
  [`docs/shared-trunk-cache.md`](docs/shared-trunk-cache.md).
- Both parties derive the circuit independently from the authorized `I`, so they
  evaluate byte-identical circuits. If one party enters a different `I`, the
  circuit-digest handshake aborts before any preprocessing. A party that garbles
  a *different function* after committing to the same circuit is caught by
  authenticated garbling (clean abort).
- Large real-circuit Rust/C++ party runs are not the current compatibility
  target. With the vendored EMP setting `fpre_threads = 1`, EMP's bucket-3/4
  refill path exposes only `permute_batch_size` usable triples per refill.
  Rust/Rust uses explicit repeated chunks for those circuits; the C++ interop
  probes still cover the protocol layers on small circuits.

## Known limitations

- **Connection setup is an unbounded wait.** A party blocks until its peer
  appears: the evaluator in emp's client `while(1){ connect() }` retry loop and
  the garbler in `accept()`, both inside `emp::NetIO`'s constructor. If the peer
  never starts, the party hangs indefinitely. The post-connect read/write
  timeout (`SHACHAIN2PC_TIMEOUT_SECS`, set on the socket *after* construction)
  does **not** cover this phase. A clean bounded fix isn't a local one-liner — it
  needs patching emp's `NetIO` (cap retries / `accept` timeout) or a custom
  `IOChannel` over a pre-connected socket (emp's `NetIO` has no fd-adopting
  constructor) — so it is deferred. The connect retry is partly intentional
  (start-order independence). Operationally: start the garbler (listener) first,
  and/or run the parties under an external timeout/supervisor.
