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

## Performance requirement

Rust-Rust v1 is not acceptable if it is materially slower than the current C++
baseline. The current worst-case local run is about **1.2s** on the same machine.

Release-gate benchmark:

- `I = ffffffffffff`;
- same host / loopback;
- same machine used for C++ baseline;
- Rust ALICE + Rust BOB must be no worse than the C++ baseline within agreed
  measurement noise.

Track both:

- wall-clock latency;
- peak RSS.

Rust v1 may not reach the future memory target because it intentionally preserves
the current protocol shape. That is acceptable for v1 if it preserves correctness
and speed. Large memory reductions belong to Rust v2 unless a safe v1-local
optimization is obvious.

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

A future proxy can still be useful as a migration/testing tool, but it should not
be in the main v1 path unless a specific EMP-wire detail proves too invasive to
keep inside the Rust compatibility layer.

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
6. The current input layout must be preserved exactly:
   - BOB's share is placed in wires `[0, n1)`;
   - ALICE's share is placed in wires `[n1, n1+n2)`;
   - the circuit computes `seed = wire[i] XOR wire[256+i]`.

Do not "clean up" role names or wire slices during the v1 port. Mixed mode
depends on matching the current behavior.

## First step

The first step is a **short v1 compatibility spec plus a probe manifest**, not a
large abstract protocol document.

Order:

1. Write down the exact v1 compatibility target:
   - vendored EMP-ag2pc source/commit or hash;
   - compile-time constants such as `SSP = 5` and `fpre_threads = 1`;
   - role behavior;
   - TCP stream schedule;
   - circuit digest format;
   - input/output wire layout;
   - abort behavior.
2. Write the C++ probe manifest:
   - what each probe freezes;
   - expected output format;
   - how Rust tests consume it.
3. Implement the probes.

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

`I = 000000000000` is useful as a compatibility fixture, but it reveals the full
seed because no SHA-256 round runs. It must be documented and should not be a
normal production derivation.

### Subprotocol interop probes

After deterministic probes pass, test live C++/Rust pairs for progressively
larger pieces:

- raw stream open/flush behavior over all three streams;
- base OT;
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
- worst-case Rust/Rust performance is no worse than the C++ baseline;
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
  round runs. Keep it only as a compatibility/test fixture unless production
  policy explicitly authorizes it.

## Initial dependency set

Expected Rust dependencies:

- `tokio` for async TCP and timeouts;
- `bytes` for owned byte buffers;
- `thiserror` for errors;
- `rand_core` / `rand_chacha` for testable randomness;
- `zeroize` for local secret cleanup;
- `sha2` for SHA-256;
- `aes` or `openssl` bindings only if they reproduce EMP AES behavior exactly;
- OpenSSL bindings are likely needed for EMP-compatible base OT point behavior.

Avoid complete MPC protocol dependencies. The MPC protocol code must live in
this workspace.

## Open decisions

1. Exact format of the v1 compatibility spec and probe outputs.
2. Whether Rust v1 should hard-reject `I == 0` in normal CLI mode or preserve it
   exactly for full C++ compatibility. If rejected, keep an explicit compatibility
   test path.
3. Exact benchmark tolerance around the 1.2s C++ baseline.
4. Which OpenSSL/Rust crypto primitives reproduce EMP-visible behavior with the
   least risk.
5. Whether a proxy is needed later for migration tooling. It is not part of the
   default v1 plan.

