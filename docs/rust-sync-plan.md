# Rust sync plan

Status: planning note. No implementation yet.

This document scopes the work needed to bring the Rust implementation back in
sync with the current C++ implementation. "Current C++" means the rewritten
`emp-ag2pc` session/backend path used by `demo/party.cpp` and `run/derive.h`,
including chunked single-index execution, range execution, the shared-trunk
tree mode, and the adaptive cache with fixed 16-leaf bottom tiles.

The recursive tile fanout plan in `docs/recursive-tile-cache-plan.md` is a later
optimization. Do not fold it into this sync pass.

## 1. Current mismatch

The Rust workspace is not just a little behind the CLI. It is behind the C++
protocol abstraction.

Current Rust:

- `shachain2pc-party` accepts only one `I_hex`.
- It builds one full derivation circuit and runs the older Rust `C2pc` port:
  `function_independent`, `function_dependent`, then `online`.
- `online()` returns clear output bits. It does not return authenticated output
  wires that can be carried into another circuit.
- The circuit crate has only `build_derivation_circuit`; it lacks
  `SplitChainBits`, `BuildChunkCircuit`, and `BuildTileCircuit`.
- It has no range mode, no chunked mode, no shared-trunk/tree mode, no adaptive
  cache mode, and no cache/tile measurement scripts.

Current C++:

- `party` accepts an `I_spec`: one index or an inclusive range.
- Default execution uses one `AG2PCSession` and `run_artifact`.
- Chunked/tree/cache modes carry intermediate values as authenticated wires,
  never as clear values and never as freshly re-input shares.
- `checkpoint()` prunes old authenticated state while preserving selected
  carried values.
- `reveal()` flushes consistency checks before opening output.
- Adaptive cache defaults to trunk chunks of 16 and fixed 16-leaf bottom tiles.

The security-critical mismatch is the carry API. A Rust cache cannot safely be
built by revealing an intermediate and re-inputting it; that would reintroduce
the steering problem the C++ cache was designed to avoid.

## 2. Sync target

The sync target is:

1. Same CLI behavior as C++ `party`.
2. Same pure circuit generation for:
   - full derivation circuit;
   - chunk circuit;
   - fixed 16-leaf tile circuit;
   - cache/tree/chunk digests.
3. Same session semantics:
   - authenticated inputs;
   - `run_artifact` over materialized authenticated arguments;
   - authenticated carried outputs;
   - `checkpoint`;
   - reveal gated by consistency checks.
4. Same operational modes:
   - normal batch over one or more indices;
   - `SHACHAIN2PC_CHUNK_BLOCKS=N` for single-index chunking;
   - `SHACHAIN2PC_TREE=1` for shared-trunk range mode;
   - `SHACHAIN2PC_CACHE=1` for adaptive cache mode;
   - `SHACHAIN2PC_TAMPER` test hook;
   - `SHACHAIN2PC_TIMEOUT_SECS` equivalent where practical.
5. Same output and measurement shape:
   - single index: `RESULT <hex>`;
   - range: `RESULT <I_hex12> <hex>`;
   - timing sections compatible with the C++ scripts.

The initial sync goal is Rust/Rust correctness and security parity with current
C++. Cross-mode C++/Rust wire compatibility is desirable only after the Rust
session/backend matches the current C++ backend. The old Rust `C2pc` wire
compatibility tests are still useful history, but they are no longer the target
for cache parity.

## 3. Non-goals for this pass

- Do not implement recursive tile fanout.
- Do not implement one-time-pad reveal.
- Do not implement persistent authenticated cache across process restarts.
- Do not change `ssp`; keep the current demo/research default aligned with C++.
- Do not optimize before correctness and tamper rejection are back in place.

## 4. Phase plan

### Phase A: Pure circuit parity

Port the pure C++ circuit helpers into `shachain2pc-circuit`:

- `split_chain_bits(index, blocks_per_chunk)`.
- `build_chunk_circuit(sha, chain_bits, first)`.
- `build_tile_circuit(sha, tile_height)` for the current fixed bottom tile.
- Shape checks matching `CheckChunkCircuit` and `CheckTileCircuit`.
- Digest helpers matching C++:
  - full derivation circuit digest;
  - chunk/tree digest;
  - cache digest including range, trunk chunk size, fixed tile height, and SHA
    gadget digest.

Tests:

- Plaintext eval of chunk chains against `generate_from_seed`.
- Plaintext eval of 16-leaf tile outputs against `generate_from_seed`.
- Rust digests matched against C++-generated fixtures.
- `cargo fmt`, `clippy -D warnings`.

This phase is safe to do first because it touches no networking or secrets.

### Phase B: CLI/range surface

Bring the Rust `party` parser and stdout/stderr behavior in line with C++:

- Parse `I_spec` as one index or `lo-hi`.
- Refuse any spec containing `I=0` unless `--allow-seed-reveal` is present.
- Preserve position-independent `--allow-seed-reveal`.
- Print range results as `RESULT <I_hex12> <hex>`.
- Parse the same environment toggles, even if some modes initially return a
  clear "not implemented in Rust sync phase" error.

Tests:

- Parser parity for single index, range, bad range, over-48-bit values, and
  range containing zero.
- No-socket refusal for `I=0`.

This phase can land before protocol cache support, but the unsupported mode
errors must be explicit so callers do not silently get a different mode.

### Phase C: Rust session/carry abstraction

Implement the Rust equivalent of C++ `AG2PCSession` before porting chunk/tree/cache
modes.

Required API shape:

```text
Session::input(owner, bits) -> authenticated value
Session::run_artifact(program, authenticated args...) -> authenticated value
Session::checkpoint(keep...)
Session::reveal(value, PUBLIC/ALICE/BOB) -> clear value or non-recipient None
```

Security requirements:

- Authenticated outputs must remain MAC-bound across `run_artifact` calls.
- A carried value must never be revealed or re-input to simulate carry.
- A stale/unmaterialized wire must be a loud error.
- `reveal` must flush pending consistency checks before producing output.
- Tamper must return an error and no output.

Implementation decision:

- Preferred: port the current C++ session/backend semantics to Rust, not the old
  `C2pc` object model. That gives parity with the code we are actually using in
  C++ and avoids preserving old C2PC assumptions.
- Temporary bridge: if reusing pieces of `shachain2pc-emp-compat`, expose a
  `SecureWires`/carried-state layer only if it preserves authenticated carry
  exactly. Do not build cache on top of clear `online()` outputs.

Tests:

- Small synthetic circuit: input -> run -> checkpoint -> run -> reveal.
- Reuse one authenticated value across two later circuits.
- Tamper in the second circuit aborts before reveal.
- Consecutive reveals with no new gates do not rerun unnecessary checks.

This is the largest phase and the main fork in the road.

### Phase D: Chunked single-index mode

Port `RunDerivationChunked` on top of the Rust session:

- First chunk takes ALICE+BOB share inputs and computes the seed.
- Later chunks take the carried authenticated 256-bit value.
- `SHACHAIN2PC_CHUNK_BLOCKS=N` is single-index only.
- `SHACHAIN2PC_TAMPER=<chunk>` flips a branch constant in that chunk for tests.
- Timing and network counters should match the C++ shape as closely as the Rust
  transport allows.

Tests:

- Rust/Rust chunked output for `I=1`, `I=3`, and `ffffffffffff`.
- Multiple chunk sizes: `1`, `8`, `16`, whole chain.
- Tampered chunk aborts with no `RESULT`.

### Phase E: Batch and shared-trunk tree modes

Bring over:

- default range batch mode;
- `SHACHAIN2PC_TREE=1`;
- tree digest negotiation;
- trunk split and trunk chunking;
- authenticated trunk tip reuse;
- one branch circuit per requested index;
- reveal after all branches are computed.

Tests:

- Range outputs match `ref_cli`.
- Circuit/digest mismatch aborts.
- Tampered branch aborts.
- Range with no shared trunk hash produces the same clear error as C++.

### Phase F: Adaptive cache with fixed 16-leaf tiles

Port the current C++ adaptive cache, not the recursive fanout plan:

- Default trunk chunk size: 16.
- Fixed `tile_height = 4`, `tile_leaves = 16`.
- Full aligned bottom tiles use one multi-output tile circuit.
- Boundary/partial cases fall back to one-SHA branch steps.
- Pre-reveal compute and reveal timing are reported separately.
- `branch_instances`, `new_hashes`, `tile_count`, RSS harness, and correctness
  scripts should have Rust equivalents.

Tests:

- 16-leaf aligned tile range.
- Non-aligned range that exercises fallback steps.
- 256-leaf range.
- Cache tamper test over a reused authenticated trunk/node.
- Result comparison against `ref_cli` and C++ measurement format.

### Phase G: Cross-mode tests after backend parity

Only after Phase C gives Rust the current C++ session/backend semantics:

- Add C++ probes for the new session backend if needed.
- Rust party vs C++ party for:
  - single full derivation;
  - chunked derivation;
  - tree range;
  - cache range.
- Keep tests serialized and use generous timeouts.

If wire compatibility is not feasible without excessive work, document the exact
boundary: Rust/Rust and C++/C++ both implement the same relation and checks, but
their wire transcripts are not guaranteed cross-compatible.

## 5. Measurement parity

Rust measurements should use the same cases as C++:

- single `I=1`, `I=3`, and ignored/manual `ffffffffffff`;
- cache ranges: 16, 256, 1024, 8192 when practical;
- no-latency local run;
- 50 ms RTT emulation for the cache path;
- wall time, pre-reveal time, reveal time, per-secret time, peak RSS, rounds,
  bytes sent/received, branch instances, and mismatch count.

Do not compare old Rust single-circuit speed against C++ cache speed directly.
Compare like-for-like modes only.

## 6. Security checklist

Before calling Rust "in sync":

- `I=0` guard matches C++ for single index and ranges.
- Circuit/mode digest mismatch aborts before preprocessing.
- Intermediate trunk/chunk/tile values are authenticated wires, not clear values.
- Cache reuse never re-inputs a cached share.
- Every reveal is gated by pending consistency checks.
- Tamper tests exist for:
  - chunked mode;
  - shared-trunk branch;
  - cache fallback branch;
  - cache tile;
  - online reveal/output corruption if the new backend exposes that hook.
- Budget accounting reports `compute_inplace`/branch instances, not only revealed
  secrets.
- Secret buffers zeroize on drop where Rust owns them.
- Reveal fairness remains documented as abort-with-output-possible for BOB in
  the current `PUBLIC` reveal shape.

## 7. Recommended next step

Start with Phase A and Phase B in one small reviewable commit:

1. Add pure chunk/tile circuit generation to Rust.
2. Add Rust fixtures/tests against C++ for those circuits and digests.
3. Extend the Rust CLI parser to understand ranges and environment modes, with
   explicit "mode not implemented yet" errors for modes that need Phase C.

Then pause. That gives reviewers a clean, low-risk diff before the session/carry
port, which is the security-critical part.

