# Recursive tiled cache plan

Status: implemented and measured (see Section 9, "Measured"). Originally a
planning note; kept as the design record. The aligned recursive cover, the
`tile_fanout` knob, and the offset tile circuit are implemented; unaligned ranges
fall back to the existing bottom-16 + one-SHA scheme.

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

Integrity, however, is a sharper concern than fairness. The current `PUBLIC`
reveal is correct-or-abort: BOB reconstructs from authenticated wires and the MAC
check turns a wrong value into an abort, not a wrong secret. A naive simultaneous
mask exchange that just XORs two locally held masks has no such check, so a
malicious peer can send a bad mask and the other party reconstructs a wrong
secret undetected. For revocation material a wrong secret is eventually caught
on-chain, but it can wedge the channel meanwhile. So any reveal optimization MUST
preserve abort-on-wrong-value -- keep the MAC check in the reconstruction, or use
commit/open -- not merely match the existing fairness level. Commit/open restores
integrity but reintroduces a round, which is the cost we were trying to avoid.

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

### Which latency this actually reduces

Be explicit about the target, because it decides whether this is the right lever.
A cache run has three serial phases at the transport: trunk, branch (precompute),
and reveal. Recursion shrinks only the **branch** phase -- it collapses one-SHA
prefix steps into upper tiles, cutting branch instances roughly in half (31 -> 17
for 256 leaves). It does not touch trunk or reveal.

Reveal is one `PUBLIC` reveal per secret and runs *after* precompute, with no
overlap. At 50 ms RTT, 256 sequential reveals cost about 12.9 s (Section 1). So:

- **End-to-end, back-to-back batch** (all leaves revealed in a burst): the
  round-bearing steps are roughly trunk (~3) + branch + reveal (256). Recursion
  removes ~14 of ~290 -- about 5%. Reveal dominates, and only the deferred reveal
  optimization (Section 1) attacks it.
- **Upfront precompute / cache refill** (reveal amortized at one RTT per channel
  update over time): the cost you wait for is trunk + branch ~= 34 steps, and
  recursion removes ~14 -- about 40%. This is the regime where recursion clearly
  wins.

So recursion is the right lever for refill/precompute latency and for budget
(Section 6), not for steady-state per-update latency. If end-to-end burst latency
is the goal, do the reveal optimization first. This plan assumes the
precompute/refill regime.

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

Implementation note: this boundary handling is the riskiest part of the plan. The
recommended first slice (Section 8) implements only aligned power-of-two coverage
and falls back to the existing bottom-16-tile + one-SHA scheme at boundaries,
deferring variable-height boundary tiles until the aligned path is trusted. Do
not let boundary complexity gate the headline aligned win.

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

This is a first-class benefit, not just accounting. Because the per-seed budget is
`N * 2^-ssp` over instances `N`, halving branch instances (31 -> 17 for 256, a
~45% cut) buys roughly 1.8x more channel updates against one seed before the
budget forces a rotation. At the demo `ssp = 40` ceiling that headroom is worth as
much as the latency change, and unlike the latency win it holds regardless of RTT.

## 7. Memory tradeoff

Recursive tiling reduces round trips. It does not automatically reduce retained
state if we eagerly precompute every leaf and hold all authenticated outputs
until future reveals.

First, set the floor correctly. The dominant memory cost is the per-tile
preprocessing peak of a single tile circuit, not the retained outputs. A height-4
tile is 15 SHA blocks and peaks around 240 MB while it is being garbled; a
retained authenticated output is only a label plus MAC (tens of bytes per wire).
Recursion is RAM-neutral versus the current tiled cache: it reuses the same tile
height, so the per-instance peak is unchanged at ~240 MB. Retained-output growth
is a separate, smaller term that only matters for large batches -- negligible for
256-1024 leaves, but tens of MB for 8k+ (intermediate roots plus leaves), worth
managing there.

Two retention modes address that large-batch term:

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
   verify offset tile circuits against `generate_from_seed` for several
   `(bit_offset, height)` pairs. For `bit_offset > 0` the outputs are intermediate
   roots, so check them against `generate_from_seed(seed, ancestor_index)` with
   the low bits zeroed. Also test the covering *decisions* (which arms run, which
   fall back) for unaligned ranges, not just circuit shapes. `verify_circuit`'s
   `RunTilePlain` today only covers `bit_offset == 0`; extend it.
4. Implement recursive range covering incrementally. Land the aligned
   power-of-two case first -- it is the clean ~2x branch win and is simple to get
   right. For boundaries, fall back to the already-validated bottom-16-tile +
   one-SHA scheme rather than introducing variable-height boundary tiles; defer
   the latter until the aligned path is measured and trusted.
5. Keep cache digest negotiation strict and bind `tile_fanout`. The covering
   decomposition must be deterministic and identical on both sides (derived from
   `(lo, hi, tile_fanout)`, never negotiated) so a mismatch aborts cleanly instead
   of silently building different circuit sequences. The single run-level digest
   must cover `tile_fanout`, trunk chunk size, range, and the SHA gadget digest.
6. Extend tamper tests:
   tamper an upper tile and a bottom tile; both must abort before reveal.
7. Measure:
   no-latency and 50 ms RTT for 256, 1024, and 8192; report wall,
   pre-reveal, reveal, RSS, total rounds, and branch instances.

## 9. Expected effect

For remote peers, recursion cuts branch instances (31 -> 17 for 256 leaves), which
reduces the precompute/refill latency and extends the per-seed budget by ~1.8x.
The budget part is real and RTT-independent.

Be honest about end-to-end burst latency, though. Reveal is unchanged at one RTT
per secret and runs after precompute with no overlap, so for a back-to-back
256-secret batch at 50 ms RTT (~12.9 s of reveal) recursion removes only ~5% of
the round-bearing steps -- the reveal phase, not branches, dominates that case,
and only the deferred reveal optimization (Section 1) attacks it. See Section 2,
"Which latency this actually reduces."

The main implementation risk is the recursive covering for unaligned/boundary
ranges (Section 5); mitigate by landing the aligned case first and falling back to
the existing scheme at boundaries. The main memory risk is retained authenticated
outputs for 8k+ batches (Section 7), addressed by frontier precompute; recursion
itself is RAM-neutral.

### Measured (50 ms emulated RTT)

Aligned ranges, fanout 16, trunk chunk 16, ssp 40, versus the pure
one-SHA-per-secret baseline (fanout 1). Reveal is measured separately. Every run
verified mismatches=0 against the reference.

| leaves | mode | branch instances | branch s/secret | preReveal s/secret | reveal s/secret | peak RSS |
|---:|:--|---:|---:|---:|---:|---:|
| 256  | recursive | 17   | 0.118 | 0.141 | 0.050 | 248 MB |
| 1024 | recursive | 69   | 0.119 | 0.125 | 0.050 | 250 MB |
| 8192 | recursive | 547  | 0.118 | 0.120 | 0.050 | 513 MB |
| 256  | one-SHA   | 255  | 0.639 | 0.661 | 0.050 | 248 MB |
| 1024 | one-SHA   | 1023 | 0.642 | 0.647 | 0.050 | 248 MB |

The marginal precompute cost is ~0.118 s/secret independent of batch size; the
one-time trunk (5.5-8 s) amortizes, so preReveal/secret falls toward it as the
batch grows. Branch instances match the cover formula (256->17, 1024->69,
8192->547, the last with a height-1 top level).

Two corrections to the expectations above, from the measurement:

1. **Recursion vs pure one-SHA is a ~5.4x per-secret precompute win** (0.64 ->
   0.118 s), not ~2x. The ~2x figure was recursion vs the already-tiled hybrid;
   against plain one-SHA the branch phase has ~15x more instances (255 vs 17 for
   256 leaves) and tiling collapses them. Budget headroom vs one-SHA is likewise
   ~15x, not ~1.8x.
2. **Precompute, not reveal, dominates at 50 ms.** Branch is ~0.118 s/secret vs
   reveal ~0.050 s/secret (one RTT). The "reveal dominates" note above
   under-counted per-instance round cost: a 15-edge tile costs ~1.8 s at 50 ms,
   not the ~0.5 s assumed, so the branch phase is large in absolute terms. The
   phase recursion optimizes is therefore the dominant one; the deferred reveal
   optimization (Section 1) addresses the smaller ~0.05 s/secret term.

## 10. Recommended sequencing

1. Generalize the tile circuit to `BuildTileCircuit(sha, bit_offset, tile_height)`
   and pure-test it for `bit_offset > 0`.
2. Implement aligned power-of-two recursive covering; fall back to the current
   bottom-16 + one-SHA scheme at boundaries.
3. Measure the branch/reveal split at 50 ms RTT to confirm which phase to attack
   next.
4. If end-to-end burst latency still matters after the budget and refill wins,
   pick up the reveal optimization (Section 1) with integrity preserved -- that is
   the larger end-to-end lever.

Aligned recursion plus the budget win is the high-value, low-risk first slice. The
reveal optimization is the bigger end-to-end win but carries the integrity caveat
in Section 1 and should not be rushed.
