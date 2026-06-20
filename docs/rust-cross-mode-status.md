# Rust/C++ cross-mode status

Status: Rust is synced to the current C++ recursive-tile cache shape and now
uses the current AG2PC/SoftSpoken backend. The old Rust WRK17/C2PC backend is no
longer active.

What is synced in Rust:

- `BuildTileCircuit(sha, bit_offset, tile_height)` semantics.
- `PlanTileLevels(depth, tile_height)` semantics.
- Cache digest binding to `tile_fanout`.
- `SHACHAIN2PC_TILE_FANOUT` parsing with `1` as the one-SHA fallback.
- Aligned recursive cache cover for Rust/Rust and cross-mode runs.
- Single-index digest follows current C++ single-as-batch behavior.
- AG2PC main+sibling transport, CSW base OT, SoftSpoken COT, triple-pool draw,
  input authentication, stored-program execution, and reveal.

What was tested locally:

- C++ Alice to Rust Bob and Rust Alice to C++ Bob, single index `1`: passed.
- C++ Alice to Rust Bob and Rust Alice to C++ Bob, multi-block index `3`:
  passed.
- C++ Alice to Rust Bob and Rust Alice to C++ Bob, range `1-3`: passed.
- Both cross-mode directions with `SHACHAIN2PC_CHUNK_BLOCKS=1`, index `3`:
  passed.
- Both cross-mode directions with `SHACHAIN2PC_TREE=1`, range `2-3`: passed.
- Both cross-mode directions with `SHACHAIN2PC_CACHE=1`,
  `SHACHAIN2PC_CHUNK_BLOCKS=16`, and `SHACHAIN2PC_TILE_FANOUT=16`, range
  `10-1f`: passed.
- Active Rust/C++ helper probes for CSW, SoftSpoken, AG2PC triple-pool draw,
  AG2PC input/reveal protocol, and AG2PC compute-in-place: passed.

Remaining validation:

- Run broader benchmark and peak-RSS measurements after the backend transition.
- Re-run larger cache batches and the ignored/manual 48-block worst case.
- Add or run end-to-end cross-mode tamper tests for the party binary modes.
