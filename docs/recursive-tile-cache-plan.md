# Recursive tiled cache plan

Status: planning note. No implementation yet.

This is the next-step design for reducing remote-latency round trips while
keeping the memory spike bounded. It generalizes the current fixed 16-leaf tile
cache into a recursive tree of fixed-fanout MPC nodes.

The current implementation already separates:

- pre-reveal compute: trunk plus branch/tile MPC circuits;
- reveal: one `PUBLIC` reveal per secret, measured separately.

This plan keeps that separation. It does not change reveal semantics.

## 1. Deferred idea: one-time-pad reveal

Record this idea, but do not implement it yet.

Current `PUBLIC` reveal reconstructs at BOB first and then BOB sends clear bits
to ALICE. In the sequential reveal loop this costs roughly one RTT per secret:
at 50 ms RTT, 256 reveals cost about 12.9 s.

A one-time-pad-style reveal could make the two parties exchange output masks
simultaneously and reconstruct locally. This can reduce latency for a single
secret if the protocol accepts abort-after-receive unfairness. Commit/open
variants can authenticate the masks better, but they tend to reintroduce a full
round. Batch reveal is not attractive here because channel updates are
sequential: each secret is opened when the channel state actually advances, not
as one bulk release.

Fairness does not get worse in kind: the current `PUBLIC` reveal is also not fair
because BOB learns before ALICE receives the broadcast. A party can always abort
at the last step. If fair exchange is needed, it has to come from the surrounding
Lightning protocol or a separate penalty/settlement mechanism, not plain 2PC.

For now, reveal remains unchanged and is measured separately.

## 2. Goal

For a known contiguous batch `[lo, hi]`, compute the needed shachain leaves with
fewer MPC instances than the current "single SHA prefix steps plus 16-leaf
tiles" layout.

The new parameter is:

```text
tile_fanout = 1, 2, 4, 8, 16, ...
tile_height = log2(tile_fanout)
```

`tile_fanout` is the number of arms of one MPC tree node. A node computes all
children for one fixed window of index bits, and every child it computes must be
eventually needed by this batch. We should not compute outside the requested
range just to fill a power-of-two shape.

`tile_fanout = 1` is the degenerate compatibility mode: no recursive multi-arm
tiling; use the existing one-step traversal behavior from the original cache.
Implementation-wise this is a special case, not a real tile circuit:
`log2(1) = 0`, so there is no useful `BuildTileCircuit` call. Each branch edge
is computed with the existing one-SHA `BuildChunkCircuit(sha, {bit}, false)`
path.

## 3. High-level shape

Given a contiguous batch `[lo, hi]`:

1. Find the shared high prefix exactly as the cache code does now:
   `split = highest_set_bit(lo ^ hi)`.
2. The trunk is the chain over shared high set bits above `split`.
3. The trunk is computed sequentially in chunks of `trunk_chunk_blocks`, as
   today. Only the authenticated trunk tip survives.
4. The low subtree below `split` is traversed using recursive tile nodes.
5. Leaves are kept as authenticated outputs until their normal sequential
   reveal. Reveal stays one secret at a time.

The trunk chunk size and the tile fanout are separate knobs:

- `trunk_chunk_blocks` controls the one-time refill chain memory/round tradeoff.
- `tile_fanout` controls branch tree arity and remote-latency round count.

## 4. Recursive tile node

The current `BuildTileCircuit(sha, tile_height)` only works for the bottom
window of bits, because it implicitly uses bit positions `0..tile_height-1`.

Recursive tiling needs an offset:

```text
BuildTileCircuit(sha, bit_offset, tile_height)
```

This circuit takes one authenticated 256-bit root and outputs
`2^tile_height` authenticated child roots. Arm `suffix` applies the set bits in:

```text
[bit_offset, bit_offset + tile_height - 1]
```

in normal shachain order, high bit to low bit. For `bit_offset == 0`, the
outputs are final leaves. For `bit_offset > 0`, the outputs are intermediate
authenticated roots that feed the next lower tile level.

Example for 256 leaves with fanout 16:

```text
trunk tip
  -> one tile over bits 7..4       produces 16 intermediate roots
  -> 16 tiles over bits 3..0       produce 256 leaves
```

This uses 17 branch MPC instances instead of the current 31:

```text
current:   15 one-SHA prefix instances + 16 bottom tiles
recursive: 1 upper tile instance      + 16 bottom tiles
```

The number of SHA edges is still 255. The win is fewer protocol instances and
therefore fewer latency-bearing round groups.

## 5. Traversal rule

Represent the requested batch as a set of covered subranges below the trunk tip.
A recursive node may be executed only when all of its arms are needed, meaning
each child root has at least one requested descendant.

If `tile_fanout == 1`, skip this recursive-node logic entirely and use the
current stack-cache traversal: align the authenticated prefix stack for each
requested index and derive missing children one SHA edge at a time.

For a node at `bit_offset` with height `h`, each arm covers a subrange of size:

```text
1 << bit_offset
```

and the whole node covers:

```text
1 << (bit_offset + h)
```

Run the tile node if every arm's subrange intersects `[lo, hi]`. If one or more
arms would have no requested descendant, do not run the full tile: descend only
into the needed arms and use a smaller tile or one-SHA fallback at the boundary.

For `bit_offset == 0`, each arm is a final leaf, so this rule reduces to "run
the bottom tile only when every leaf in the tile is requested." For
`bit_offset > 0`, a child may represent a partial lower subrange; that is still
useful because the child root feeds at least one requested leaf and remains an
authenticated internal value, not a revealed secret.

This means:

- aligned full regions get the low round count;
- some unaligned regions can still use upper tiles when every arm is represented;
- unaligned boundaries do not compute unused secrets;
- every computed arm is eventually used by this batch.

For ranges whose low-depth is not a multiple of `tile_height`, the top level can
use a smaller height `r = depth % tile_height` before full-height levels. Example
with fanout 16 and depth 13:

```text
top height 1, then height 4, 4, 4
```

This avoids expanding to 16 bits and computing unused subtrees.

## 6. Budget accounting

The security budget should continue to count malicious bucketing instances, not
revealed secrets and not the full 2^48 index space.

For `tile_fanout == 1`, the branch-instance budget is just the number of
one-SHA branch edges actually executed by the original stack-cache traversal.

For `tile_fanout > 1` and a perfectly aligned batch of `B = fanout^d` leaves,
branch instances are:

```text
1 + fanout + fanout^2 + ... + fanout^(d-1)
  = (B - 1) / (fanout - 1)
```

plus the trunk chunks.

Examples:

| batch | fanout | branch instances | current fixed bottom-16 shape |
|---:|---:|---:|---:|
| 256 | 16 | 17 | 31 |
| 4096 | 16 | 273 | 511 |
| 8192 | 16 | 547 with top height 1 | about 1023 |

The exact number for unaligned ranges is the number of executed tile/fallback
nodes. The measurement output should keep reporting this as `branch_instances`,
because that is the budget-relevant number.

The per-instance residual remains approximately `< 2^-ssp`, assuming the AG2PC
bucketing proof applies to each larger tile circuit exactly as it does today.
Larger tiles reduce instance count but increase circuit size per instance.

## 7. Memory tradeoff

Recursive tiling reduces round trips. It does not automatically reduce retained
state if we eagerly precompute every leaf and hold all authenticated outputs
until future reveals.

There are two useful modes:

1. Eager precompute:
   compute all leaves before any reveal. This gives the lowest hot-path compute
   latency, but retains `batch_size * 256` authenticated output wires.
2. Frontier precompute:
   compute and keep upper authenticated roots, then expand lower tiles shortly
   before their leaves are needed. This uses much less memory for large batches,
   at the cost of moving some computation closer to the channel update path.

The first implementation can stay eager, matching the current behavior, but the
plan should not assume eager storage is the final answer for 8k+ batches.

## 8. Implementation stages

1. Add the planning/config surface only:
   `tile_fanout`, parsed as a power of two, with `1` as the original-cache
   fallback path.
2. Generalize the tile circuit:
   `BuildTileCircuit(sha, bit_offset, tile_height)`.
3. Add pure tests:
   verify offset tile circuits against `generate_from_seed` for several offsets
   and heights.
4. Implement recursive range covering:
   full covered nodes use tile circuits; boundaries use smaller tiles or
   one-step fallback.
5. Keep cache digest negotiation strict:
   include `tile_fanout`, trunk chunk size, range, and SHA gadget digest.
6. Extend tamper tests:
   tamper an upper tile and a bottom tile; both must abort before reveal.
7. Measure:
   no-latency and 50 ms RTT for 256, 1024, and 8192; report wall,
   pre-reveal, reveal, RSS, total rounds, and branch instances.

## 9. Expected effect

For remote peers, the main win is fewer branch instances, hence fewer
latency-bearing protocol phases. The 256-secret 50 ms RTT case should improve
because branch instances drop from 31 to 17. Reveal will still cost about one RTT
per actually revealed secret, and that is intentional for now.

The main risk is memory growth from retaining many authenticated leaf outputs.
That is a storage policy issue, not a recursive-tiling security issue. If eager
8k batches are too large, switch to frontier precompute while keeping the same
recursive node primitive.
