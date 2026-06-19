# Rust self-contained party implementation plan

## Decision

Use a conservative two-stage path:

1. **Rust v1: language port only.**
   Rust v1 preserves the current C++/EMP protocol, current relation, current
   command-line interface, and current wire behavior. It should be able to run
   directly against the C++ `party` binary in both directions:
   - Rust ALICE with C++ BOB;
   - C++ ALICE with Rust BOB.

2. **Rust v2: protocol evolution.**
   After Rust v1 is proven, Rust v2 may introduce a clean Rust-native framed
   protocol, streaming execution, prepare/reveal split, checkpointing, and lower
   memory use.

Do not combine the language port and the protocol redesign in the first serious
implementation. The main safety reason is attribution: if something breaks, we
need to know whether the cause is the Rust port or the protocol change.

## Goal for Rust v1

Build a self-contained Rust implementation of the current `party` binary:

```text
party <1|2> <port> <I_hex> <share_hex> [peer_ip]
```

Rust v1 must preserve:

- party `1` as ALICE/listener;
- party `2` as BOB/connector;
- default peer IP `127.0.0.1`;
- `I_hex` as the same 48-bit internal shachain index;
- `share_hex` as the same 32-byte XOR seed share;
- success output: `RESULT <hex>`;
- failure output: `ABORT <reason>` and non-zero exit;
- the current circuit relation and input layout;
- the current EMP-ag2pc wire behavior closely enough for mixed C++/Rust runs.

Rust v1 must not depend on an MPC crate. It may use general Rust crates for
async networking, AES/SHA/EC arithmetic, errors, randomness, and zeroization,
but the MPC protocol logic must live in this repository.

## Performance target and current status

The original target was that Rust/Rust v1 should not be materially slower than
the current C++ baseline. After the local optimization passes, release
Rust/Rust measured about 0.28s for `I = 1`, 0.49s for `I = 3`, and 11-14s for
`I = ffffffffffff` on the current review machine. The 48-block run matched the
reference and peaked at about 1.06 GB RSS for ALICE and 1.01 GB for BOB. C++/C++
on the same machine measured about 0.43s for `I = 1` and 0.60s for `I = 3`.

The Rust/Rust real-circuit path uses Rust-side Fpre chunk sizing for bucket-3/4
circuits to avoid regenerating unused preprocessing. That is a deliberate
performance/correctness choice for Rust/Rust real circuits under the vendored
`fpre_threads = 1` setting; large real-circuit Rust/C++ party runs are therefore
not the current release gate even though the protocol-layer C++ probes remain
mandatory.

Release-gate benchmark:

- `I = ffffffffffff`;
- same host / loopback;
- same machine used for C++ baseline;
- measure C++ ALICE + C++ BOB as the baseline;
- measure Rust ALICE + Rust BOB as the release gate;
- measure Rust/C++ mixed mode in both directions as an informative compatibility
  signal for the probed protocol layers;
- Rust ALICE + Rust BOB must not be statistically slower than the C++/C++
  baseline.

Track both:

- wall-clock latency;
- peak RSS.

Benchmark method:

- run release builds only;
- use fixed shares and `I = ffffffffffff`;
- run at least 5 warmup iterations per pairing;
- run at least 30 measured iterations per pairing;
- interleave pairings to reduce drift from thermal/load changes;
- measure elapsed wall-clock time from party launch until both parties exit;
- record peak RSS for both processes and report both per-process and combined
  peak;
- use C++/C++ as the baseline distribution;
- use Rust/Rust as the release-gate distribution;
- use mixed C++/Rust in both directions as compatibility/performance signal.

Pass criterion for v1 latency: Rust/Rust passes if the bootstrap 95% upper
confidence bound for `median(Rust/Rust) / median(C++/C++)` is at most `1.05`.
If Rust/Rust's measured median is above C++/C++ at all, investigate and either
optimize or document the cause before accepting the result.

If Rust/Rust is slower, investigate and address the cause without breaking the
v1 transition invariants: same algorithm, same relation, same wire behavior, and
same mixed-mode compatibility.

Rust v1 may not reach the future memory target because it intentionally freezes
the current protocol shape. That is acceptable for v1 if it preserves
correctness and speed. Large memory reductions belong to Rust v2 unless a safe
v1-local optimization is obvious.

## Why not change the protocol immediately?

Changing the implementation language and the cryptographic protocol at the same
time is too much risk for this use case. The system is intended to protect
Lightning revocation secrets; a wrong output can translate into theft of funds.

Rust-native protocol changes are attractive because they can support:

- typed request/response rounds;
- transcript binding from the start;
- streaming gate/chunk execution;
- lower peak memory;
- precompute-almost-to-output and reveal later;
- cleaner future review;
- possible future OT changes.

But those are protocol changes. If they happen during the port, honest test
failures and security bugs become harder to localize. Therefore v1 stays close
to C++; v2 changes the protocol only after v1 is a trusted regression oracle.

## Proxy decision

Do **not** build a proxy for v1 by default.

A proxy could make sense only if Rust v1 used a clean framed encoding while C++
used EMP's raw stream. But if v1 is a faithful port of the current protocol, a
proxy adds another parser, another process, and another failure mode without
much security benefit.

Preferred v1 shape:

```text
C++ party  <->  Rust v1 party
same CLI        same EMP-compatible wire
```

No proxy is planned for v1. Revisit only if a specific EMP-wire detail proves
too invasive to keep inside the Rust compatibility layer.

Important distinction:

- If a proxy only changes byte encoding for the same logical EMP protocol, it
  does not need secret material.
- If a proxy tries to translate C++ EMP into a different Rust-native MPC
  protocol, it cannot remain a simple neutral translator. Garbled labels, OT
  outputs, MACs, masks, and authenticated wire state are protocol-specific
  secret-bearing artifacts. Translating between different MPC protocols would
  require terminating one or both protocols or creating a new cryptographic
  bridge.

## Current C++ contract to preserve

The existing binary does more than a single TCP request/response:

1. `demo/party.cpp` parses the CLI, creates an EMP `NetIO`, then calls
   `run::RunDerivation`.
2. `RunDerivation` builds the circuit from `I`, converts it to EMP's Bristol
   in-memory format, and exchanges a 32-byte circuit digest. ALICE sends first;
   BOB receives first.
3. `emp::C2PC` runs:
   - `function_independent()`;
   - `function_dependent()`;
   - `online(input, output, alice_output = true)`.
4. EMP `Fpre` opens two additional TCP connections when `fpre_threads = 1`.
   So mixed-mode Rust must handle three TCP streams:
   - main stream;
   - `io[0]`;
   - `io2[0]`.
5. EMP sends raw bytes with no outer message framing. Boolean vectors are packed
   by `IOChannel::send_bool`; blocks are 16-byte `__m128i` values in EMP memory
   order; `send_partial_block<..., 5>` sends the first five bytes of each block.
6. IKNP uses EMP `OTCO` as base OT, i.e. Chou-Orlandi OT over OpenSSL P-256.
   The base-OT transcript, point encodings, message order, and
   `Hash::KDF(point, i)` masks are part of the v1 compatibility contract.
7. The current input layout must be preserved exactly:
   - BOB's share is placed in wires `[0, n1)`;
   - ALICE's share is placed in wires `[n1, n1+n2)`;
   - the circuit computes `seed = wire[i] XOR wire[256+i]`.

Do not "clean up" role names or wire slices during the v1 port. Mixed mode
depends on matching the current behavior.

## First step

The first step is a **short v1 compatibility spec plus a probe manifest**, not a
large abstract protocol document.

The v1 spec should freeze the whole algorithm and wire encoding. The goal is to
remove implementation discretion: Rust should have a robust, fixed target for
how each primitive, round, byte encoding, stream, and abort condition behaves.

Order:

1. Write down the exact v1 compatibility target:
   - vendored EMP-ag2pc source/commit or hash;
   - compile-time constants such as `SSP = 5` and `fpre_threads = 1`;
   - role behavior;
   - TCP stream schedule;
   - circuit digest format;
   - base-OT protocol and transcript format;
   - input/output wire layout;
   - abort behavior.
2. Write the C++ probe manifest:
   - what each probe freezes;
   - expected output format;
   - how Rust tests consume it.
3. Implement the probes.

Compatibility spec format:

- `compat/v1/spec.toml`;
- stable TOML keys for constants, roles, stream schedule, wire encodings,
  circuit layout, abort behavior, benchmark parameters, and accepted caveats;
- no prose-only normative requirements: anything required for v1 compatibility
  must be represented by a machine-readable key or by a named probe.

Probe output format:

- JSON Lines (`*.jsonl`);
- one JSON object per case;
- all byte strings are lowercase hex without `0x`;
- integers are decimal JSON numbers when safe, otherwise decimal strings;
- arrays are ordered and semantically significant;
- each object includes at least:
  - `schema`;
  - `probe`;
  - `case`;
  - `inputs`;
  - `outputs`;
  - `compat_spec`;
- probe output must be deterministic unless the probe is explicitly marked as an
  interop/randomized probe.

Base-OT transcript fixtures:

- include deterministic test-only hooks for `OTCO` randomness so the C++ probe
  can emit complete Chou-Orlandi transcripts for small lengths;
- freeze sender `A`, receiver `B[i]` points, point length prefixes, ciphertext
  blocks, choices, `Hash::KDF(point, i)` masks, and recovered outputs;
- include both choice bits for at least several positions;
- include the exact `send_pt`/`recv_pt` byte representation, not just abstract
  points;
- keep these hooks out of production binaries.

So the very first artifact is a spec small enough to guide the probes. The first
code artifact is the C++ probe suite.

## C++/Rust probe strategy

The probes are mandatory. They are the bridge that lets us port in layers
instead of debugging the full 48-SHA circuit at once.

### Deterministic C++ probes

Small C++ binaries linked against the current code and vendored EMP should emit
canonical vectors that Rust unit tests compare against.

Probe:

- `makeBlock(high, low)` memory bytes;
- block XOR, masks, `getLSB`;
- `sigma(block)`;
- `send_bool` packing for aligned and unaligned buffers;
- `send_partial_block<5>`;
- SHA-256 wrapper behavior;
- EMP PRG behavior;
- EMP fixed-key AES PRP behavior;
- garbling hash/TMMO hash for fixed labels;
- `Hash::KDF(point, id)` for fixed OpenSSL P-256 points and ids;
- `num_ands -> batch_size/bucket_size` choices;
- circuit gate counts, wire counts, AND counts, and digest for representative
  indices;
- `GenerateFromSeed(seed, I)` vectors.

These catch the common porting bugs: endian mistakes, AES lane mistakes,
boolean packing differences, partial-block truncation mistakes, and accidental
changes to EMP preprocessing parameters.

### Pure circuit/reference probes

These prove that Rust and C++ are computing the same relation before MPC enters:

- `GenerateFromSeed(seed, I)` matches C++;
- Rust circuit digest equals C++ digest;
- Rust gate order equals C++ gate order;
- representative indices include:
  - `000000000000`;
  - `000000000001`;
  - `800000000000`;
  - `aaaaaaaaaaaa`;
  - `555555555555`;
  - `ffffffffffff`.

The deterministic probes still include `I = 000000000000` because it is an
important circuit/reference fixture. The Rust `party` binary does not accept it
silently: index zero reveals the full seed because no SHA-256 round runs, so the
CLI aborts before opening a socket unless `--allow-seed-reveal` is supplied.
This is a deliberate local hardening divergence from the C++ demo binary, which
still accepts `I = 0`.

### Subprotocol interop probes

After deterministic probes pass, test live C++/Rust pairs for progressively
larger pieces:

- raw stream open/flush behavior over all three streams;
- base OT (`OTCO` / Chou-Orlandi) transcript and output masks;
- IKNP/COT;
- `LeakyDeltaOT`;
- `Fpre`;
- one AND gate;
- tiny hand-written circuits;
- SHA-256 compression circuit;
- full shachain circuit.

Randomized protocols usually cannot be tested by fixed output vectors unless
both RNGs are fully controlled. For randomized layers, the test is successful
completion plus protocol invariants in both role directions.

### End-to-end mixed-mode tests

Mandatory configurations:

- C++ ALICE + C++ BOB baseline;
- Rust ALICE + Rust BOB;
- Rust ALICE + C++ BOB;
- C++ ALICE + Rust BOB.

Each result must match the reference shachain implementation.

### Adversarial probes

Honest interop is not enough. A port can pass all honest tests and still weaken
malicious security. Add tests where one side tampers and the receiver must abort:

- circuit digest mismatch;
- wrong `I`;
- changed gate/table bytes;
- malformed partial block;
- wrong output label/MAC;
- skipped send or truncated send;
- replayed old transcript fragment;
- mixed session/circuit material;
- wrong output opening.

Each receiver implementation must be tested against a cheating sender. Detection
lives on the receiving side, so both Rust-as-receiver and C++-as-receiver cases
matter.

## Rust workspace architecture

Use a Cargo workspace under `rust/`:

```text
rust/
  Cargo.toml
  crates/
    shachain2pc-types/
    shachain2pc-circuit/
    shachain2pc-emp-wire/
    shachain2pc-emp-compat/
    shachain2pc-protocol/
  bins/
    party/
```

### `shachain2pc-types`

Small shared types with no networking and no async runtime:

- `Role::{Alice, Bob}`;
- `Index48`;
- `Value32`;
- hex parsing/formatting matching `util/hex.h`;
- output/error conventions;
- zeroization helpers where practical.

### `shachain2pc-circuit`

Pure deterministic circuit/reference code:

- port `protocol/bristol.*`;
- port `protocol/circuit_gen.*`;
- port the SHA-256 compression gadget path used by C++;
- port `reference::GenerateFromSeed`;
- compute the exact same circuit digest as `run::CircuitDigest`.

### `shachain2pc-emp-wire`

Raw EMP wire compatibility:

- block serialization;
- bool packing/unpacking;
- partial block send/receive;
- raw stream helpers;
- main/Aux0/Aux1 stream scheduling helpers.

Keep EMP wire awkwardness here. The MPC engine may use this crate, but higher
layers should not hand-code EMP byte packing.

### `shachain2pc-emp-compat`

Self-contained Rust implementation of the subset of EMP used here:

- EMP `block` representation:
  - 16-byte value;
  - `makeBlock(high, low)` compatible with EMP memory layout;
  - XOR, masks, `getLSB`, `sigma`.
- EMP hashes/PRG/PRP:
  - SHA-256 digest behavior;
  - fixed-key AES PRP behavior;
  - PRG behavior used for blocks/bools.
- OT stack used by `LeakyDeltaOT`:
  - base OT;
  - IKNP COT;
  - `send_dot` / `recv_dot`.
- `Feq` equality check.
- `Fpre` preprocessing:
  - setup over Aux0/Aux1;
  - refill/generate/check/combine;
  - coin tossing.
- `C2PC`:
  - `function_independent`;
  - `function_dependent`;
  - `online`;
  - first-class consistency-check errors.

Do not scrape stdout for failures like the C++ `CheatGuard` workaround. Rust
should turn every consistency failure into a typed `Err`.

The internal implementation should still be structured as state machines where
reasonable, but v1's public wire is EMP-compatible raw bytes.

### `shachain2pc-protocol`

Async orchestration over real sockets:

- open the main TCP stream using the current role behavior;
- open/accept Aux0 and Aux1 in the same order EMP uses;
- apply socket timeouts equivalent to the C++ tool;
- build the circuit for `I`;
- exchange the circuit digest;
- drive `shachain2pc-emp-compat`;
- expose:

```rust
async fn derive(
    role: Role,
    port: u16,
    peer_ip: Option<IpAddr>,
    index: Index48,
    share: Value32,
) -> Result<Value32, Error>;
```

The protocol layer owns scheduling, TCP, timeouts, and clean error reporting. It
should not contain MPC math.

### `party` binary

Thin CLI wrapper:

- parse exactly the current positional arguments;
- keep default peer IP as `127.0.0.1`;
- call `shachain2pc-protocol::derive`;
- print `RESULT <hex>` on success;
- print `ABORT <reason>` on error.

Do not preserve EMP's incidental `connected` stdout line by default. The stable
contract is result/abort plus exit code. If needed later, add an explicit
compatibility flag or env var.

## Implementation phases

### Phase 0: Compatibility spec and probes

Create the v1 compatibility spec and probe manifest, then implement C++ probes.

Acceptance:

- C++ probes build in the existing environment;
- probe outputs are deterministic where expected;
- Rust test harness can consume probe output.

### Phase 1: Rust workspace, types, reference, circuit

Implement:

- workspace layout;
- CLI-compatible parsing helpers;
- `GenerateFromSeed`;
- circuit generation;
- circuit digest.

Acceptance:

- Rust reference matches C++ reference vectors;
- Rust circuit digest and gate counts match C++ probes;
- no MPC code is needed yet.

### Phase 2: EMP wire substrate

Implement:

- block memory layout;
- bool packing;
- partial block handling;
- raw stream helpers;
- three-stream connection schedule.

Acceptance:

- Rust encoding tests pass against C++ probes;
- Rust can exchange raw bytes with small C++ stream probes over all three
  streams.

### Phase 3: Crypto primitives and OT

Port:

- AES PRG/PRP behavior;
- SHA-256 wrapper behavior;
- EC point encode/decode for base OT;
- IKNP COT;
- `LeakyDeltaOT`.

Use Rust crypto crates only where they reproduce EMP-visible behavior exactly.
For base OT, OpenSSL bindings are likely safer than pure-Rust curve crates if
the compatibility target is EMP/OpenSSL point encoding.

Acceptance:

- deterministic primitive vectors match C++ probes;
- randomized interop tests complete base OT and IKNP/COT between Rust and C++ in
  both role directions.

### Phase 4: Fpre and C2PC

Implement:

- `Fpre::new`;
- `Fpre::refill`;
- `function_independent`;
- `function_dependent`;
- `online`.

Acceptance:

- Rust/Rust evaluates tiny circuits correctly;
- Rust/C++ mixed mode evaluates tiny circuits correctly;
- one-AND and small-circuit adversarial tests abort on tampering.

### Phase 5: Full shachain party v1

Wire the circuit crate to the EMP-compatible engine and async protocol.

Acceptance:

- Rust/Rust derives the same values as C++ reference;
- Rust ALICE + C++ BOB works;
- C++ ALICE + Rust BOB works;
- Rust refuses `I = 0` unless `--allow-seed-reveal` is explicitly supplied;
- real-circuit Rust/Rust tests cover `I = 1` and a multi-block `I = 3`;
- worst-case Rust/Rust performance is measured and documented. The current v1
  implementation is correct and compatible, but it is not yet performance
  comparable with the C++ baseline;
- test indices include:
  - `000000000000` compatibility fixture;
  - `000000000001`;
  - `800000000000`;
  - `aaaaaaaaaaaa`;
  - `555555555555`;
  - `ffffffffffff`.

### Phase 6: Verification and regression suite

Add automated tests:

- unit tests for pure circuit/reference code;
- primitive probe tests;
- subprotocol interop tests;
- local Tokio integration tests;
- mixed C++/Rust end-to-end tests;
- transcript/message-order regression tests;
- adversarial/tamper tests;
- latency and peak-RSS benchmark jobs.

The mixed-mode and adversarial tests are mandatory. Honest correctness alone
does not support a malicious-security claim.

### Phase 7: Documentation and human review package

Document:

- the v1 compatibility target;
- crate boundaries;
- command-line contract;
- known local-secret handling limitations, especially `share_hex` in argv;
- the `I == 0` seed-reveal caveat;
- warnings that the project is AI-written, a demo/PoC, and not production-ready;
- what has and has not been proven by tests.

Prepare a review package for a human cryptographer/security engineer before any
use with real funds.

## Rust v2 future plan

Rust v2 is where protocol changes belong.

Possible v2 goals:

- clean framed binary protocol with a versioned handshake;
- typed request/response round functions;
- transcript hash bound into every commitment, OT context, garbling context,
  circuit/relation digest, output opening, and `I`;
- streaming execution that avoids holding the full 48-SHA circuit and all
  garbling state in memory;
- peak memory target near 10MB if practical;
- prepare/reveal split:
  - prepare phase runs almost all expensive MPC for an authorized `I`;
  - reveal phase opens only the final value after final authorization;
- checkpointed authenticated shared state if it can be done without allowing a
  malicious party to steer to `I'`;
- possible future OT/backend changes.

Rust v1 should remain available as a regression oracle while v2 is developed.

## Security notes

- Reimplementing malicious 2PC and OT is high risk. Rust v1 is a new
  cryptographic implementation even if it preserves C++ behavior.
- C++ interop proves compatibility and helps detect porting bugs. It does not by
  itself prove security.
- Honest tests prove correctness, not malicious security. Adversarial tests and
  human review are required.
- Secret shares must not be logged. `zeroize` helps local buffers but does not
  solve command-line argument exposure through `ps`/`/proc`.
- Authorization of `I` remains outside the binary. The binary can ensure both
  parties evaluate the same requested `I`; it cannot prove that Lightning channel
  state allowed that `I`.
- `I == 0` reveals `alice_share XOR bob_share`, i.e. the seed, because no hash
  round runs. Rust v1 refuses it by default and requires the explicit
  `--allow-seed-reveal` test/compatibility override.

## Initial dependency set

Expected Rust dependencies:

- `tokio` for async TCP and timeouts;
- `bytes` for owned byte buffers;
- `thiserror` for errors;
- `rand_core` / `rand_chacha` for testable randomness;
- `zeroize` for local secret cleanup;
- `sha2` for SHA-256 where only the digest function matters;
- RustCrypto `aes` for low-level AES-128 block encryption if it matches EMP
  probes and meets the speed target;
- `openssl` / `openssl-sys` for EMP-compatible P-256 base OT point arithmetic
  and point encoding.

Avoid complete MPC protocol dependencies. The MPC protocol code must live in
this workspace.

### Primitive choice research

For v1 compatibility, `rustls` is not the right primitive dependency. Rustls is
a TLS 1.2/1.3 library. Its crypto provider system controls TLS cipher suites,
key-exchange groups, signature verification, randomness, and key loading. It
does not expose the low-level OpenSSL-compatible P-256 point arithmetic and
point serialization that EMP's base OT uses.

The current EMP path uses:

- OpenSSL P-256 for base OT:
  - `EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)`;
  - `EC_POINT_point2oct(..., POINT_CONVERSION_UNCOMPRESSED, ...)`;
  - `EC_POINT_oct2point`;
  - `EC_POINT_mul`, `EC_POINT_add`, `EC_POINT_invert`;
  - `BN_rand_range`.
- EMP's own AES-NI AES-128 block encryption for `PRP` and `PRG`.
- SHA-256 for hashes/KDFs/transcript checks.

Therefore the lowest-risk v1 choices are:

1. Use Rust OpenSSL bindings for the base OT group and point operations. This is
   the closest match to EMP because EMP itself calls OpenSSL for those objects
   and encodings.
2. Implement the AES dependency behind a tiny internal `Aes128Block` wrapper so
   the backend can be switched without touching MPC logic.
3. Try RustCrypto `aes` first for raw AES-128 block encryption. Use it only if
   C++ probes confirm exact block-byte behavior and benchmarks meet the speed
   gate.
4. If RustCrypto `aes` fails either compatibility or performance, switch the
   wrapper to OpenSSL AES or a small audited compatibility wrapper.
5. Use `sha2` for ordinary SHA-256 digest operations, with C++ probe vectors to
   confirm every call site hashes the same bytes.

Do not use a pure-Rust P-256 crate for v1 unless probes prove exact compatibility
with EMP/OpenSSL point encodings and operations. It may be appropriate for Rust
v2 after the wire/protocol is no longer EMP-compatible.

## Resolved decisions

1. The v1 spec freezes the whole algorithm and wire encoding. Exact probe output
   formats are TOML for the spec and JSON Lines for probe outputs.
2. Rust v1 refuses `I == 0` by default because it reveals the shachain seed.
   Compatibility tests may opt in with `--allow-seed-reveal`; the C++ demo is
   unchanged and accepts `I == 0` silently.
3. Benchmark C++/C++, Rust/Rust, and mixed C++/Rust. The current Rust v1 result
   is correct and compatible but slower than the C++ baseline; performance work
   remains future debt.
4. Prefer OpenSSL bindings for EMP-compatible base OT point behavior; prefer
   vetted Rust crates for standard SHA/AES only after probe confirmation. AES
   backend selection is an empirical implementation gate, not a protocol
   decision.
5. Proxy is not needed for v1.

## Implementation details deferred to Phase 0/3

1. Exact TOML keys and JSONL field lists for the compatibility spec and probes.
2. Exact benchmark harness implementation.
3. Final AES backend, selected by C++ probe compatibility and benchmark results.
