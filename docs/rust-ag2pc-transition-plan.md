# Rust AG2PC backend transition plan

Status: planning note for review. No implementation in this document.

## 1. Goal

Bring Rust into cross-mode compatibility with the current C++ `party`.

Current C++ no longer uses the old single-shot `emp::C2PC`/IKNP/Fpre stack. It
uses the rewritten `emp::AG2PCSession` backend:

- SoftSpoken OT instead of IKNP;
- authenticated garbling with WRK17/KRRW18-style half-gate leaky ANDs;
- cyclic-shift bucketing;
- one lifetime session with carried authenticated wire state;
- `checkpoint(keep...)`;
- `reveal(value, PUBLIC/ALICE/BOB, keep...)`;
- one main `NetIO` plus an internally-created sibling channel.

Rust must implement that current backend. Matching only the shachain circuits,
cache traversal, or recursive tile digest is not enough. We already verified that
Rust/C++ runs now pass the run digest and then fail at the MPC transport layer.

The v1 transition target is **wire-compatible interop**, not full randomized
transcript byte identity. A Rust ALICE must be able to run against a C++ BOB, and
a C++ ALICE must be able to run against a Rust BOB, using normal production
randomness and the current C++ message formats, ordering, and abort behavior.

Full-run byte-identical transcripts are not expected under randomized OT/MPC
unless test-only randomness is fixed. Deterministic byte fixtures remain useful
for local helpers, encodings, message framing, and fixed-seed probes, but they
are not the security goal by themselves.

Semantic/differential testing is also required, but it is an additional gate, not
a replacement for v1 interop. For each supported workload, C++/C++, Rust/Rust,
C++->Rust, and Rust->C++ should produce the same public result, and equivalent
tampering should abort without a `RESULT`. The independent reference
implementation remains the oracle for shachain correctness.

The transition is complete only when:

- Rust/Rust passes all party modes;
- C++/Rust cross-mode passes all party modes;
- C++/C++, Rust/Rust, and both cross-mode directions match the same reference
  outputs for the same inputs;
- equivalent tamper tests abort in Rust/Rust and both cross-mode directions;
- the old Rust WRK17/C2PC backend is removed from the production/test path;
- stale old-EMP compatibility probes are removed or archived as historical docs,
  not kept as active build/test targets.

## 2. Non-goals

- Do not keep a compatibility mode for the old Rust backend.
- Do not reproduce the old emp-ag2pc uninitialized-triple behavior.
- Do not build a proxy translator between old Rust and new C++ protocols.
- Do not change shachain semantics, reveal semantics, `ssp`, or tile fanout while
  doing the backend transition.
- Do not require production runs to be byte-identical end to end under real
  randomness.
- Do not accept semantic output equality alone as the transition gate; live
  C++/Rust wire-compatible interop is required for v1.
- Do not optimize until wire compatibility, correctness, and abort behavior are
  established.

## 3. Current Rust code to retire

The following Rust components are useful as reference material, but should not
survive as active backend code after the transition:

- old `C2pc` API:
  `function_independent`, `function_dependent`, `online`,
  `online_authenticated_clear`, `online_authenticated_carried`,
  `reveal_authenticated_public`;
- old `Fpre`, IKNP, LeakyDeltaOT, OTCO runtime path;
- old EMP wire live-C++ probe harnesses that target removed Makefile probes;
- tests whose only purpose is old backend byte-compatibility.

Keep:

- pure circuit generation and digest code;
- party CLI/range/cache/tree/chunk orchestration;
- reference/KAT tests;
- recursive tile logic;
- security tests that can be rewritten against the new backend.

Implementation rule: the repository should not end with two production MPC
backends. A temporary side-by-side period is acceptable only while the new backend
is being proven; the final phase deletes the old backend.

## 4. Phase 0: freeze the new C++ compatibility surface

Before porting Rust, add deterministic and live probes for the current C++
`AG2PCSession` backend. These probes are the compatibility spec.

Freeze the protocol surface that makes cross-mode possible:

Pin in the spec:

- exact C++ commit and emp-tool/emp-ot/emp-ag2pc commits;
- `ssp`, role numbers, input order, output order;
- main socket and sibling socket creation order;
- message order for session construction;
- SoftSpoken setup transcript;
- input authentication transcript;
- one-AND transcript;
- reveal transcript;
- checkpoint/liveness behavior;
- abort transcript for a tampered MAC/check.

For deterministic subcomponents, freeze exact bytes. For randomized protocol
steps, freeze message ordering, lengths, encodings, role behavior, and invariants;
use live cross-mode tests as the primary oracle. Fixed-seed hooks are acceptable
only as test-only probes and must not weaken production randomness.

Probe cases:

- empty session then reveal/checkpoint behavior where supported;
- one public constant circuit;
- one XOR-only circuit;
- one AND circuit;
- two sequential circuits with `checkpoint(keep)`;
- carried value used twice;
- public reveal to both;
- reveal to ALICE only and BOB only;
- tampered garbling/check/reveal abort.

Outputs should be machine-readable JSONL with hex-encoded wire records where the
bytes are deterministic, plus a short TOML/Markdown spec explaining message
order, length prefixes, encodings, flush points, and role ordering. For
randomized protocols, include live cross-mode invariant probes and record enough
metadata to debug length/order mismatches without pretending that a production
run should be byte-identical.

Review gate: Claude/human review of the probes/spec before Rust implements the
backend.

## 5. Phase 1: Rust transport parity

Implement the current C++ transport shape in Rust:

- one primary full-duplex TCP stream;
- one sibling stream created in the same order as `NetIO::make_sibling`;
- same listen/connect retry behavior;
- same flush boundaries where they affect liveness;
- byte counters and round counters compatible enough for measurement output;
- timeout handling equivalent to `SHACHAIN2PC_TIMEOUT_SECS`.

Tests:

- Rust/Rust transport open/close;
- C++ probe ↔ Rust transport for primary + sibling connection order;
- timeout/stalled-peer test;
- no MPC yet.

## 6. Phase 2: SoftSpoken OT compatibility

Port or reimplement the SoftSpoken OT path used by current C++.

Approach:

- use vetted Rust crypto crates where they exactly match C++ behavior;
- do not hand-roll low-level primitives unless no safe crate exposes the needed
  operation;
- freeze transcript/invariants with C++ probes.

Tests:

- Rust/Rust SoftSpoken setup and COT extension;
- C++ sender ↔ Rust receiver;
- Rust sender ↔ C++ receiver;
- randomized invariant checks over multiple lengths, including boundary sizes;
- C++/C++, Rust/Rust, and cross-mode runs agree on public invariants even though
  randomized wire bytes differ;
- tamper/consistency-check failure returns `Err`, not partial output.

Review gate: no AG2PC garbling until SoftSpoken cross-mode is stable.

## 7. Phase 3: authenticated wire/session core

Implement the Rust equivalent of `AG2PCSession` state:

- party roles;
- global delta/session secrets;
- authenticated input wires;
- carried authenticated wire store;
- liveness/stale-wire checks;
- `checkpoint(keep...)` pruning;
- canonical BooleanProgram ingestion;
- secret zeroize-on-drop.

Rust public API target:

```text
Session::new(transport, role, ssp)
Session::input(owner, bits) -> AuthValue
Session::run_artifact(program, args...) -> AuthValue
Session::checkpoint(keep...)
Session::reveal(value, recipient, keep...) -> Option<bits>
```

Security requirements:

- carried values remain authenticated wires, never clear values;
- stale values fail loudly;
- reveal flushes pending consistency checks before returning output;
- any failed check returns `Err` and the party binary prints no `RESULT`;
- Bob-first public reveal unfairness, if inherited from C++, remains documented.

Tests:

- XOR-only carry and reveal;
- one AND and reveal;
- checkpoint keeps exactly requested values;
- stale carried value errors;
- reveal to non-recipient returns `None`;
- Rust/Rust tamper tests.

## 8. Phase 4: garbling/check/reveal parity

Port the current C++ authenticated garbling backend:

- BooleanProgram canonical wire layout;
- half-gate/leaky-AND computation;
- cyclic-shift bucketing;
- batched equality/check state;
- reveal decode and MAC/hash verification;
- abort paths as typed Rust errors.

Tests:

- deterministic local KATs for pure helper functions;
- C++/Rust one-AND live interop in both role directions;
- C++/Rust multi-AND circuit;
- C++/Rust checkpoint then second circuit;
- C++/Rust reveal to PUBLIC/ALICE/BOB;
- differential C++/C++ vs Rust/Rust behavior tests for the same circuits,
  including matching outputs and matching abort/no-output behavior;
- C++/Rust tamper abort.

Review gate: once this phase passes, the old Rust backend can be disconnected
from `party` behind a feature or branch-local switch.

## 9. Phase 5: reconnect party modes to new backend

Move `shachain2pc-party` from the old `C2pc` API to the new `Session` API.

Modes to wire:

- single index as batch-of-one;
- normal range batch;
- chunked single-index mode;
- shared-trunk tree mode;
- adaptive cache;
- recursive tiled cache with `SHACHAIN2PC_TILE_FANOUT`;
- `SHACHAIN2PC_TAMPER` hooks for tests;
- timing and network counters.

Important invariants:

- seed shares are authenticated once per session where C++ does that;
- chunk/tree/cache intermediate values are carried authenticated wires;
- no intermediate value is revealed and re-input;
- single-index digest stays current C++ single-as-batch digest;
- cache digest binds `tile_fanout`.

Tests:

- Rust/Rust correctness against `ref_cli`/`generate_from_seed`;
- C++/Rust cross-mode for every mode;
- C++/C++, Rust/Rust, C++->Rust, and Rust->C++ differential runs for the same
  inputs, ranges, cache settings, and tamper cases;
- range result order and stdout shape;
- no-socket `I=0` refusal;
- digest mismatch abort before preprocessing;
- tamper abort with no `RESULT`.

## 10. Phase 6: remove old Rust backend

After Phase 5 is green:

- delete old runtime backend code from `shachain2pc-emp-compat`;
- delete or archive old IKNP/Fpre/C2PC tests that no longer describe active
  behavior;
- remove stale old C++ probe build scripts and ignored tests;
- remove old backend feature flags;
- update docs so the only supported Rust backend is the current
  AG2PCSession-compatible backend.

Keep old material only if it is clearly marked historical and cannot be mistaken
for active compatibility coverage.

Acceptance:

- `rg` for old backend names (`C2pc`, `Fpre`, `IKNP`, `LeakyDeltaOT`, `OTCO`) does
  not find active production/runtime paths;
- `cargo test` does not skip stale old-backend compatibility tests;
- CI/build does not reference removed old Makefile probes.

## 11. Phase 7: measurement and security review

Run measurements after backend replacement, not before.

The first optimization pass should preserve the v1 wire protocol. It can still
batch AES, buffer writes, reduce allocations, reuse memory, parallelize local
compute, and improve layout as long as C++/Rust interop and abort behavior remain
green. Protocol-breaking changes such as collapsing sockets, changing message
order, changing reveal fairness, or redesigning batching belong in a later
Rust-only v2 after C++ is retired.

Measure:

- single `I=1`, `I=3`, ignored/manual `ffffffffffff`;
- cache ranges 16, 256, 1024, 8192 where practical;
- local no-latency;
- 50 ms RTT;
- wall time;
- pre-reveal total and per-secret;
- reveal total and per-secret;
- peak RSS;
- rounds/bytes;
- branch instances;
- mismatch count.

Security review checklist:

- deterministic helper/encoding probes match C++;
- live C++/Rust interop succeeds in both role directions;
- differential C++/C++ vs Rust/Rust behavior matches for outputs and aborts;
- all reveal paths are correct-or-abort;
- tampered preprocessing/garbling/reveal returns `Err`;
- no stale wire can be used after checkpoint;
- no cached value is cleartext or re-input;
- all secret-owned buffers zeroize;
- `I=0` guard remains before sockets;
- docs retain the AI-written/demo warning.

## 12. Recommended first implementation slice

Do not start by rewriting `party`.

First slice:

1. Add current C++ `AG2PCSession` probes/spec for:
   transport sibling setup, one input, one XOR, one AND, checkpoint, reveal, and
   tamper abort.
2. Commit that alone.
3. Review with Claude/humans.

Second slice:

1. Implement Rust transport parity.
2. Add C++/Rust transport-only tests.
3. Commit and review.

Only then start SoftSpoken and AG2PC internals. This keeps the transition
debuggable and avoids mixing protocol, language, and application changes in one
opaque step.
