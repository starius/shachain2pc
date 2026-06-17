# Rust self-contained party implementation plan

## Goal

Build a self-contained Rust implementation of the current `party` binary:

```text
party <1|2> <port> <I_hex> <share_hex> [peer_ip]
```

It must be a drop-in replacement for the existing C++ binary at the command-line
level and, unless explicitly revised later, at the party-to-party wire level:

- party `1` is ALICE/listener;
- party `2` is BOB/connector;
- `I_hex` is the same 48-bit internal shachain index;
- `share_hex` is the same 32-byte XOR seed share;
- success prints `RESULT <hex>`;
- failure prints `ABORT <reason>` and exits non-zero;
- mixed mode must work: Rust ALICE with C++ BOB, and C++ ALICE with Rust BOB.

The Rust implementation must not depend on an MPC crate. It may use general
Rust packages for async/networking and cryptographic primitives, but the EMP
malicious 2PC pieces used by this project must be implemented in our code.

## Current C++ contract to preserve

The existing binary does more than just one TCP request/response:

1. `demo/party.cpp` parses the CLI, creates an EMP `NetIO`, then calls
   `run::RunDerivation`.
2. `RunDerivation` deterministically builds the circuit from `I`, converts it
   to EMP's Bristol in-memory format, and exchanges a 32-byte circuit digest.
   ALICE sends the digest first; BOB receives first.
3. `emp::C2PC` then runs:
   - `function_independent()`;
   - `function_dependent()`;
   - `online(input, output, alice_output = true)`.
4. EMP `Fpre` opens two additional TCP connections when `fpre_threads = 1`.
   So the wire-compatible Rust implementation must manage three TCP streams:
   the main stream plus `io[0]` and `io2[0]`, in EMP's connection order.
5. EMP sends raw bytes with no outer message framing. Boolean vectors are packed
   by `IOChannel::send_bool`; blocks are 16-byte `__m128i` values in host memory
   order; `send_partial_block<..., 5>` sends the first five bytes of each block.
6. The current input layout must be preserved exactly:
   - BOB's share is placed in wires `[0, n1)`;
   - ALICE's share is placed in wires `[n1, n1+n2)`;
   - the circuit computes `seed = wire[i] XOR wire[256+i]`.

Do not "clean up" role names or wire slices during the port. Cross-mode depends
on matching the current behavior, even where EMP naming is confusing.

## Architecture

Use a Cargo workspace under `rust/`:

```text
rust/
  Cargo.toml
  crates/
    shachain2pc-types/
    shachain2pc-circuit/
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
- typed wire actions used by the pure protocol engine:

```rust
enum StreamId {
    Main,
    Aux0,
    Aux1,
}

enum IoAction {
    Send { stream: StreamId, bytes: bytes::Bytes },
    Recv { stream: StreamId, len: usize, tag: RecvTag },
    Flush { stream: StreamId },
}
```

This is the Rust equivalent of "round types". Because EMP is a raw byte stream,
the correct abstraction is not JSON-like request/response structs. The pure
engine should instead emit typed send/recv actions and consume typed received
buffers. Tests can drive these actions in memory; the async protocol layer can
drive them over TCP.

### `shachain2pc-circuit`

Pure deterministic circuit/reference code:

- port `protocol/bristol.*`;
- port `protocol/circuit_gen.*`;
- port the SHA-256 compression gadget loader/generator currently embedded in
  the C++ path;
- port `reference::GenerateFromSeed`;
- compute the exact same circuit digest as `run::CircuitDigest`.

First milestone must generate the exact same gate order and digest as C++ for
the test indices. Later streaming optimization is a separate protocol version;
it cannot be mixed with the existing C++ binary unless the C++ side is changed
too.

### `shachain2pc-emp-compat`

This crate owns the self-contained Rust implementation of the subset of EMP
used here. It should be written as pure state machines plus explicit randomness
inputs, not direct socket calls.

Needed pieces:

- EMP `block` representation:
  - 16-byte value;
  - `makeBlock(high, low)` compatible with EMP memory layout;
  - XOR, AND masks, `getLSB`, `sigma`;
  - exact partial-block serialization.
- EMP IO encoding:
  - `send_bool` / `recv_bool` packing;
  - EC point serialization used by base OT;
  - raw block serialization.
- EMP hashes/PRG/PRP:
  - SHA-256 digest behavior;
  - fixed-key AES PRP behavior used by EMP;
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
  - EMP-compatible consistency failure detection.

The crate API should look like:

```rust
struct EngineState { /* role, circuit, phase, crypto state */ }

enum EngineEvent {
    Start,
    Received { stream: StreamId, tag: RecvTag, bytes: bytes::Bytes },
    Random { tag: RandomTag, bytes: bytes::Bytes },
}

struct EngineStep {
    state: EngineState,
    actions: Vec<IoAction>,
    result: Option<Value32>,
}
```

The important property is that tests can run ALICE and BOB by repeatedly
matching `Send` actions to peer `Recv` actions without real networking. The
Tokio layer should be only an interpreter for `IoAction`.

### `shachain2pc-protocol`

Async orchestration over real sockets:

- open the main TCP stream using the current role behavior;
- open/accept Aux0 and Aux1 in the same order EMP uses;
- apply socket timeouts equivalent to the C++ tool;
- drive the `shachain2pc-emp-compat` engine until result/abort;
- expose a single async API:

```rust
async fn derive(
    role: Role,
    port: u16,
    peer_ip: Option<IpAddr>,
    index: Index48,
    share: Value32,
) -> Result<Value32, Error>;
```

The protocol layer must not contain MPC math. It only owns scheduling, TCP,
timeouts, and translating IO errors into clean aborts.

### `party` binary

Thin CLI wrapper:

- parse exactly the current positional arguments;
- keep default peer IP as `127.0.0.1`;
- call `shachain2pc-protocol::derive`;
- print `RESULT <hex>` on success;
- print `ABORT <reason>` on error.

For strict command-line drop-in behavior, also decide whether to print
`connected` like EMP `NetIO` currently does. The current demo scripts tolerate
extra lines, but cross-tool users may rely on that output.

## Compatibility strategy

There are two possible strategies:

1. **EMP wire-compatible Rust port.**
   This is the plan above. It is more work, but it satisfies mixed mode.

2. **New Rust-native wire protocol.**
   This is easier and could use clean typed request/response messages, but it
   would not work against the current C++ binary. It would need an explicit
   protocol version and both parties would have to use Rust.

Because the requested requirement says drop-in replacement, same party ABI, and
cross mode, choose strategy 1 first.

## Implementation phases

### Phase 0: Freeze C++ behavior with probes

Add small C++ probe binaries or test hooks that emit deterministic vectors for:

- `makeBlock`, block serialization, `getLSB`, `sigma`;
- `send_bool` packing for aligned and unaligned buffers;
- `send_partial_block<5>`;
- `Hash`, `PRG`, `PRP`;
- circuit digest for representative indices;
- `GenerateFromSeed` reference vectors.

These probes are not the Rust implementation, but they prevent guessing at EMP
ABI details.

### Phase 1: Rust workspace, CLI, reference, circuit

Create the workspace and implement:

- hex parsing;
- `GenerateFromSeed`;
- circuit generation;
- circuit digest;
- `party` argument parsing and output formatting, initially behind a stub
  protocol.

Acceptance:

- Rust reference matches C++ reference for all existing KATs;
- Rust circuit digest matches C++ for `I = 0`, `1`, alternating-bit indices,
  and `0xffffffffffff`.

### Phase 2: EMP wire substrate

Implement the low-level compatibility layer:

- block memory layout;
- bool packing;
- partial blocks;
- raw stream action interpreter;
- main/Aux0/Aux1 TCP connection ordering.

Acceptance:

- Rust encoding tests pass against the C++ probes;
- a Rust mock can exchange bytes with a C++ probe over all three streams.

### Phase 3: Crypto primitives and OT

Port the exact EMP subset:

- AES PRG/PRP behavior;
- SHA-256 wrapper behavior;
- EC point encode/decode for base OT;
- IKNP COT;
- `LeakyDeltaOT`.

Use Rust crypto crates where they can reproduce EMP's externally visible
behavior exactly. If a crate's encoding or arithmetic does not match EMP, wrap
or replace that piece locally.

Acceptance:

- deterministic seeded tests match C++ probes where deterministic seeding is
  possible;
- randomized interop tests complete base OT and IKNP between Rust and C++ in
  both directions.

### Phase 4: Fpre and C2PC

Implement:

- `Fpre::new`;
- `Fpre::refill`;
- `function_independent`;
- `function_dependent`;
- `online`.

Keep this as a state machine emitting `IoAction`s. Do not put Tokio calls inside
the MPC code.

Acceptance:

- Rust/Rust in-memory engine evaluates tiny circuits correctly;
- Rust/C++ mixed mode evaluates tiny circuits correctly;
- malicious/tampered tiny-circuit tests abort rather than return a result.

### Phase 5: Full shachain party

Wire the circuit crate to the EMP-compatible engine and async protocol.

Acceptance:

- Rust/Rust derives the same values as C++ reference;
- Rust ALICE + C++ BOB works;
- C++ ALICE + Rust BOB works;
- test indices include:
  - `000000000000`;
  - `000000000001`;
  - `800000000000`;
  - `aaaaaaaaaaaa`;
  - `555555555555`;
  - `ffffffffffff`.

### Phase 6: Verification and regression suite

Add automated tests:

- unit tests for pure circuit/reference code;
- in-memory protocol tests using pure action drivers;
- local Tokio integration tests;
- cross-mode integration tests using the existing C++ `.build/party`;
- transcript regression tests for byte counts and message ordering;
- negative tests for digest mismatch, wrong role, malformed CLI, peer timeout,
  and known cheat/tamper cases.

The cross-mode tests are mandatory. Without them, "same ABI" is not proven.

### Phase 7: Documentation and security review

Document:

- the Rust crate boundaries;
- the exact command-line contract;
- the exact compatibility target: current EMP-ag2pc source vendored in
  `.deps/emp/include`;
- the warning that this is still a demo/PoC until human-reviewed;
- the `I == 0` caveat: deriving index zero reveals `alice_share XOR bob_share`
  because no SHA-256 round runs. Compatibility mode preserves current behavior,
  but production Lightning policy should reject or tightly gate it.

## Security notes

- Reimplementing malicious 2PC and OT is high risk. The Rust port should be
  treated as a new cryptographic implementation, not as a refactor.
- The first security target is behavioral equivalence with the current
  EMP-backed PoC, not a new proof.
- Cross-mode compatibility does not itself prove security; it proves ABI
  compatibility. Security still depends on the EMP-ag2pc protocol assumptions
  and on faithfully porting every check.
- Secret shares must not be logged. Use `zeroize` for local share buffers where
  possible, but remember that command-line arguments are still visible to the
  local host environment.
- Authorization of `I` remains outside the binary. The binary can prove both
  parties computed the same requested `I`; it cannot prove that this `I` was
  allowed by Lightning channel state.

## Initial dependency set

Expected dependencies:

- `tokio` for async TCP and timeouts;
- `bytes` for owned byte buffers;
- `thiserror` for errors;
- `rand_core` / `rand_chacha` for testable randomness;
- `zeroize` for local secret cleanup;
- `sha2` for SHA-256;
- `aes` or `openssl` bindings only if they reproduce EMP AES behavior exactly;
- `p256` or `openssl` bindings for base OT point arithmetic, subject to
  wire-format compatibility tests.

Avoid dependencies that implement complete MPC protocols. The MPC protocol code
must live in this workspace.

## Open decisions

1. Should Rust strict mode preserve the current `connected` stdout line?
2. Should the default binary preserve `I == 0` for compatibility, or reject it
   for safer Lightning semantics? If rejection is desired, mixed-mode tests for
   `I == 0` should be moved to an explicit compatibility fixture instead of the
   default CLI.
3. Should the Rust source vendor translated EMP code comments/references in a
   dedicated crate, or keep a cleaner reimplementation with line-by-line tests
   against EMP probes?
4. Should a future Rust-native protocol version implement streaming SHA links
   and checkpointed shared state? That is a separate design from EMP wire
   compatibility and should get a version byte/new handshake.

