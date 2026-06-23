# MPC Protocol Refactor Plan

Status: planning document for review before implementation.

The goal is to separate the MPC protocol from its runner and concrete
transport, following the pure-round style used in
`/home/user/mpc/shachain/sha2pc` and `/home/user/mpc/shachain/shachain`.

The current Rust AG2PC implementation is correct and fast enough to keep as the
cryptographic reference, but it is still shaped like an async program over
`EmpStream`. That makes the daemon transport awkward: gRPC is used only for
control/coordination, while MPC bytes still use raw TCP ports. This refactor
turns the MPC into typed state transitions first, then lets `party`, the daemon,
raw TCP, and gRPC call the same protocol library.

## Goals

- Define typed protocol messages and state transitions separately from any
  transport.
- Make protocol steps pure at the public API boundary:
  `state + input -> new_state + output`, with no hidden socket I/O.
- Keep large state moved by value, not cloned. A function may take `mut state`
  internally, but ownership makes mutation explicit and serializable.
- Add a runner crate that sequences pure steps over an abstract async transport.
- Keep the `party` binary CLI-compatible with today.
- Preserve C++ cross-mode compatibility for the legacy `party` path.
- Preserve current Rust/Rust performance within measurement noise before
  replacing daemon worker ports with gRPC JobStream.
- Keep import/relabel frontier crypto parked behind its separate human review
  gate. This refactor is transport/protocol plumbing, not new cryptography.

## Non-Goals

- Do not change AG2PC security parameters, Delta policy, shachain semantics, or
  reveal rules.
- Do not switch the C++-compatible `party` wire format to protobuf.
- Do not require end-to-end byte-identical transcripts under randomized MPC.
  Cross-mode compatibility means C++ and Rust can complete the same job and
  produce the same output or abort on the same tampering.
- Do not optimize the protocol algorithm while refactoring. Any algorithmic
  optimization is a later, separately measured change.
- Do not keep two production MPC implementations after the transition.

## Main Design Decision

Use one typed protocol model with two codecs/transports:

- `EmpCompat` codec/transport for the legacy `party` path. It preserves the
  exact raw EMP-compatible byte encoding and ordering needed for C++ interop.
- `Proto` codec/transport for the Rust-native daemon path. It serializes typed
  messages into gRPC JobStream frames and does not need C++ byte compatibility.

This resolves the apparent conflict between protobuf and C++ compatibility.
Typed messages are the internal protocol surface. Protobuf is only one wire
codec for those messages. The C++ compatibility codec must continue to emit and
consume the legacy byte stream.

## Target Crates

### `shachain2pc-mpc-types`

New crate. Contains protocol message and state type definitions only.

Responsibilities:

- role-independent typed round messages;
- message enums for AG2PC setup, input authentication, program execution,
  COT/checkpoint, reveal, and job framing;
- lightweight domain structs for large values such as blocks, MAC bundles,
  garbled chunks, Boolean-program chunks, and reveal payloads;
- protobuf schema for Rust-native transport frames;
- conversion helpers between protobuf structs and domain structs;
- version numbers and domain separators used in message binding.

Dependencies should stay small: `shachain2pc-types`, `shachain2pc-emp-wire`
for `Block` if needed, `prost`, `bytes`, and `zeroize`. No `tokio`, no `tonic`,
no TCP, no daemon state.

Decision: domain structs remain the main API for pure functions. Protobuf
generated structs are a serialization boundary, not the type every crypto
function manipulates. This avoids forcing large internal arrays through
`Vec<u8>` conversions during local execution.

### `shachain2pc-mpc-core`

New crate. Contains pure protocol transitions and cryptographic state machines.

Responsibilities:

- SoftSpoken/CSW state transitions;
- AG2PC triple-pool transitions;
- input authentication transitions;
- Boolean-program execution transitions;
- COT consistency/checkpoint transitions;
- reveal transitions;
- shachain one-H and precompute-path job state transitions.

Public shape:

```text
fn alice_step(state: AliceState, input: AliceInput)
    -> Result<(AliceState, AliceOutput), ProtocolError>

fn bob_step(state: BobState, input: BobInput)
    -> Result<(BobState, BobOutput), ProtocolError>
```

`State` is owned. Internally the implementation may write `fn step(mut state,
...)` to avoid extra allocations. The public API still makes every state update
explicit and testable.

No async and no transport. Randomness is an explicit argument, for example
`&mut dyn CryptoRngCore` or a crate-local random source trait. This keeps test
vectors deterministic without making production randomness deterministic.

### `shachain2pc-mpc-runner`

New crate. Contains async orchestration over a transport trait.

Responsibilities:

- drive a full job by repeatedly calling `mpc-core` pure transitions;
- hold in-flight session maps for server-side request handlers;
- map role-specific protocol outputs into transport sends/receives;
- provide in-process test transport;
- expose high-level async functions equivalent to today's party helpers:
  `run_seed_root_job`, `run_precompute_path_job`, `reveal_node_job`, and full
  derivation.

Transport trait sketch:

```text
trait MpcTransport {
    async fn send(&mut self, frame: MpcFrame) -> Result<()>;
    async fn recv(&mut self) -> Result<MpcFrame>;
    async fn flush(&mut self) -> Result<()>;
}
```

For AG2PC, the transport must support logical substreams such as `main` and
`sibling`. The trait can model this either as:

- one `MpcFrame { channel_id, payload }` stream with channel IDs; or
- an `MpcTransportSet` that returns one transport handle per logical channel.

Decision: use channel IDs in a single frame type. This maps naturally to gRPC
JobStream, can still be backed by raw TCP, and keeps a single per-job identity.

### Existing Crates After Refactor

- `shachain2pc-emp-wire`: becomes the legacy byte-stream primitives and
  EMP-compatible codec support. It should not own protocol state.
- `shachain2pc-emp-compat`: is gradually emptied of runner/protocol logic.
  Deterministic primitives and C++ fixtures can remain here temporarily, but
  active AG2PC state machines move to `mpc-core`.
- `shachain2pc-party`: becomes a thin CLI plus compatibility runner using
  `mpc-runner` and the `EmpCompat` transport.
- `shachain2pc-daemon`: uses `mpc-runner` with a daemon transport. First it can
  use raw TCP adapters; then it switches to gRPC JobStream.

## Message Boundary Plan

Do not try to split every `send_block` call into a public message on day one.
Use coarse protocol messages first, then refine only where the runner needs
concurrency or observability.

Initial typed messages:

- `SessionStart`
- `SessionStartAck`
- `InputAuthRequest`
- `InputAuthResponse`
- `ProgramRunRequest`
- `ProgramRunResponse`
- `CotCheckRequest`
- `CotCheckResponse`
- `RevealRequest`
- `RevealResponse`
- `Abort`

Nested payloads can initially carry exact legacy byte chunks for C++-compatible
substeps. The invariant is that the runner sees typed phases, while the legacy
codec can still write the same C++ bytes. Later phases replace byte chunks with
fully typed submessages where useful.

This staged approach avoids a rewrite cliff. It also keeps performance stable:
large garbled tables and COT buffers stay batched and are not exploded into
small protobuf messages.

## Phase 0: Inventory And Golden Boundaries

Produce a table of current AG2PC send/receive boundaries:

- function name;
- role;
- logical channel (`main`, `sibling`);
- message length formula;
- flush point;
- state consumed and produced;
- whether C++ byte compatibility depends on exact encoding.

Output: `docs/mpc-message-boundaries.md`.

Review gate: confirm boundaries with Claude before moving code.

## Phase 1: Byte Transport Trait Under Existing Code

Introduce a minimal byte transport trait below `EmpStream`:

```text
trait ByteIo {
    async fn send_data(&mut self, data: &[u8]) -> Result<()>;
    async fn recv_data(&mut self, len: usize) -> Result<Vec<u8>>;
    async fn flush(&mut self) -> Result<()>;
}
```

Then make the existing `EmpStream` implement it and adjust helper functions to
accept the trait where possible.

Purpose:

- create a transport seam without changing protocol behavior;
- keep C++ cross-mode tests green;
- keep performance unchanged;
- prepare for gRPC frame-backed byte streams.

Tests:

- existing Rust/Rust and C++/Rust party tests;
- byte-counter and digest tests;
- no performance regression beyond noise on I=1 and I=3.

## Phase 2: Introduce `mpc-types`

Add the message/state type crate and protobuf schema.

Rules:

- protobuf field numbers are append-only once committed;
- every frame includes protocol version, job id, role, logical channel, and
  sequence number;
- unknown mandatory message versions are rejected;
- large binary fields use contiguous bytes, not repeated scalar fields;
- no `tonic` dependency in this crate.

Tests:

- encode/decode round trips;
- reject trailing bytes and unknown mandatory versions;
- KAT for canonical protobuf bytes of small messages;
- conversion between domain structs and protobuf structs.

## Phase 3: Extract Pure Round Functions Incrementally

Extract pure state transitions in this order:

1. reveal/open checks;
2. input authentication;
3. COT checkpoint;
4. triple-pool draw/check;
5. Boolean-program execution;
6. full session setup/end.

Each extraction must keep the old async wrapper as a thin compatibility layer
until the runner owns orchestration.

State transition rule:

- all consumed state is moved in;
- all produced state is returned;
- random bytes are explicit inputs;
- output messages are explicit return values;
- no socket reads/writes in `mpc-core`.

Tests for each extracted step:

- local pure transition KAT;
- in-process two-party runner test;
- existing C++ cross-mode test still green through the compatibility wrapper;
- tamper returns `Err` and no output.

## Phase 4: Add `mpc-runner`

Implement the transport-agnostic async loop.

The runner owns:

- job descriptor validation;
- role-specific sequencing;
- session map on server side;
- timeout/cancellation mapping;
- conversion between runner frames and pure messages;
- final output/abort semantics.

It does not own:

- daemon DB;
- channel reveal authorization;
- concrete network sockets;
- cryptographic transition logic.

Tests:

- in-process transport for seed-root, one-H, precompute-path, and reveal;
- fake delayed transport for timeout and cancellation;
- two concurrent jobs with independent job IDs;
- replay/gap rejection by sequence number.

## Phase 5: Port `party` To The Runner

Keep the CLI exactly compatible:

```text
party <1|2> <port> <I_hex> <share_hex> [peer_ip]
```

The `party` binary uses:

- `mpc-runner` for sequencing;
- `EmpCompatTransport` for exact legacy raw bytes;
- existing digest exchange and C++ compatibility constraints.

The old direct `Ag2pcSession + EmpStream` orchestration remains only as a test
oracle during this phase. It is deleted after parity is proven.

Required gates:

- Rust/Rust `party` outputs match reference;
- C++ Alice with Rust Bob works;
- Rust Alice with C++ Bob works;
- all existing supported modes still pass;
- tamper tests still abort without `RESULT`;
- release-mode I=1/I=3 performance is statistically no slower than before.

## Phase 6: Add Daemon gRPC JobStream

Add peer service RPC:

```text
rpc JobStream(stream MpcFrame) returns (stream MpcFrame);
```

One JobStream represents one MPC job. `MpcFrame.channel_id` multiplexes logical
AG2PC substreams such as `main` and `sibling` within that job.

The daemon scheduler stops assigning raw worker ports. Instead:

- scheduler allocates a worker/job id;
- control plane negotiates budgets and peer readiness;
- runner sends MPC frames over JobStream;
- HTTP/2 multiplexing handles concurrent jobs over one peer connection.

Tests:

- daemon pair with two concurrent channel precomputes over JobStream;
- no raw worker port use in daemon precompute;
- peer disconnect aborts only the affected job;
- reveal priority can cancel or delay background jobs without corrupting DB.

## Phase 7: Remove Raw-Port Worker Scheme

After JobStream is green:

- remove `mpc_port + 1 + slot` worker ports;
- keep base `mpc_port` only for the legacy standalone `party` binary if needed;
- update docs and CLI help;
- simplify scheduler from slot accounting to worker-count accounting.

The raw-port worker implementation should be treated as a temporary bridge, not
an interface to polish indefinitely.

## Phase 8: Delete Old Runner Paths

Remove or archive:

- direct async protocol orchestration over `EmpStream`;
- duplicate tests that only exercise the old path;
- transport-specific assumptions inside protocol code.

Keep:

- C++ compatibility tests for the `EmpCompat` codec/transport;
- pure transition tests;
- runner integration tests;
- daemon JobStream tests.

## Performance Rules

- Pure functions move state by value but must not deep-clone large buffers.
  Prefer `fn step(mut state, input)` and return `state`.
- Large payloads stay contiguous (`Vec<Block>` or byte buffers), not
  per-gate/per-bit protobuf fields.
- Runners may batch multiple outbound frames before flushing when protocol
  dependencies allow it.
- JobStream frames should use `bytes::Bytes` or contiguous `Vec<u8>` to avoid
  repeated conversions.
- Each phase records I=1 and I=3 release timings before and after.
- Any regression above measurement noise blocks the phase unless explained.

## Security Rules

- Do not make MPC randomness deterministic. Deterministic tests inject fixed
  randomness through explicit test-only inputs.
- Every typed message carries enough context to reject cross-job replay:
  protocol version, job id, role, channel id, sequence, and phase.
- Abort is terminal for a job. A runner must not emit output after any core
  transition returns `Err`.
- `expected_next_index` remains outside the MPC core and inside daemon/channel
  authorization.
- The import/relabel protocol is not part of this refactor and remains blocked
  on human MPC review.

## Review Gates

1. Boundary inventory reviewed.
2. Byte transport trait lands with no behavior or performance regression.
3. `mpc-types` protobuf schema reviewed before use in JobStream.
4. Each extracted pure transition passes pure, in-process, and compatibility
   tests.
5. `party` runner port passes Rust/Rust and C++/Rust cross-mode.
6. JobStream daemon transport passes concurrent precompute integration tests.
7. Old runner paths are removed only after all above gates pass.

## Expected End State

The repository has one MPC protocol implementation:

- typed messages and states in `mpc-types`;
- pure state transitions in `mpc-core`;
- async sequencing in `mpc-runner`;
- `party` using `EmpCompatTransport` for C++ interop;
- daemon using gRPC JobStream for parallel jobs;
- no protocol logic hidden inside concrete socket reads/writes.

This preserves the current correctness and C++ compatibility while giving the
daemon the transport shape it should have had from the start.
