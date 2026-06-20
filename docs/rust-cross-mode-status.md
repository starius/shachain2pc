# Rust/C++ cross-mode status

Status: Rust is synced to the current C++ recursive-tile cache shape at the
application/circuit layer, but it is not wire-compatible with the current C++
`party` backend.

What is synced in Rust:

- `BuildTileCircuit(sha, bit_offset, tile_height)` semantics.
- `PlanTileLevels(depth, tile_height)` semantics.
- Cache digest binding to `tile_fanout`, not fixed tile height.
- `SHACHAIN2PC_TILE_FANOUT` parsing with `1` as the one-SHA fallback.
- Aligned recursive cache cover for Rust/Rust runs.
- Single-index digest now follows current C++ single-as-batch behavior.

What was tested locally:

- Rust/Rust recursive cache, `tile_fanout=2`, range
  `800000000000-800000000003`: passed.
- Rust/Rust bottom tile cache, `tile_fanout=16`, range
  `800000000000-80000000000f`: passed.
- C++ Alice to Rust Bob, single index `1`: digest passed, then C++ failed with
  `net_recv_data` while Rust timed out.
- C++ Alice to Rust Bob, cache range `800000000000-800000000003` with
  `SHACHAIN2PC_CACHE=1 SHACHAIN2PC_TILE_FANOUT=2`: digest passed, then the same
  backend transport failure occurred.

Interpretation:

The remaining incompatibility is below recursive tiling. Current C++ uses the
rewritten `AG2PCSession` backend with SoftSpoken OT and a different socket/wire
schedule. Rust still uses the older WRK17/C2PC port. Once both sides agree on the
run digest, they enter different MPC protocols and cannot interoperate.

Next required step for real cross-mode:

Port the current C++ `AG2PCSession` backend semantics to Rust, or add a new
compatibility backend shared by both implementations. Recursive tile parity alone
cannot make current C++ and current Rust wire-compatible.
