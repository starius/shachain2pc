# Shared-trunk cache: plan + reuse-security analysis

This documents (1) the plan to generalize the shared **trunk** (`RunDerivationTree`)
into a Go-style **cache**, and (2) a deeper analysis of the one open security
question that gates it: *is reusing a cached authenticated value across many
derivations safe, is there a limit on how many leaves we can derive, and do we
need to reset?*

Status: research/decision note. No persistence is planned now — the cache is
refilled from the seed at the start of each session (accepted trade-off).

---

## 1. Plan — in-session adaptive cache (no persistence)

The trunk is a one-shot, fixed-prefix special case of the BOLT-03 / Go
`shachain/cache.go` idea: a 49-entry array holding the **shared intermediate
element at each chain level**, with derivations resuming from the deepest cached
prefix (Go README "Checkpoints and why reuse is safe"). The Go cache is
semi-honest-only because it **re-inputs** cached shares through fresh OT, which is
steerable under a malicious peer; the new emp's `checkpoint`/liveness lets us
instead **carry the cached value as an authenticated wire** (MAC-bound, never
re-input) — the malicious-secure realization the Go version had to give up.

Design:
- **Cache = the authenticated frontier.** Up to 48 nodes (one per bit level),
  each a 256-bit authenticated intermediate (each party's share ≈
  `AShareBundle` + label + Lambda ≈ ~50 B/bit → **~600 KB** for 48×256). Levels
  are public (like the Go `(index, tag)` tags); each party holds only its shares.
- **Derive on demand.** For `H(I)`, branch from the deepest cached ancestor (a
  few hashes via `BuildChunkCircuit(first=false)` on the carried node), reveal,
  and cache the new intermediates along `I`'s path for the next (lower-index)
  secret — the BOLT-03 insertion logic on authenticated values.
- **No persistence.** The cache + COT mesh live in the in-memory session. On a new
  session (or reconnect) we **refill from the seed** (recompute the trunk once,
  ~one 48-block chain) and re-warm. Cross-restart persistence of authenticated
  state (+ Δ/COT) is deliberately out of scope.
- **The seed (I=0) is never cached.** It is the master secret (gated in the CLI),
  and reusing the raw input breaks emp's checks anyway (the empty-trunk c_gamma
  abort). Every cache node is a hash output.

This is a strict generalization of `RunDerivationTree`; it needs no emp changes.

---

## 2. The reuse-security question

A high cache node `T` may feed **many** branch derivations over a channel's life
(fan-out reuse). Is that safe? Is there a limit on the number of leaves? Reset?

Reuse touches three things; the first two are fine, the third is the real bound.

### 2a. Privacy — does reuse leak `T`? No.

Each branch garbling is **freshly randomized**: the half-gate hash seed is derived
from the running transcript,
`st.mitc.setS(RO(...).absorb(io.digest()).absorb(sib.digest()).squeeze())`
(`backend/engine.h:179`). So even though `T`'s label/mask are reused, every branch
hashes them under a *different* seed → independent, simulatable garbled material.
No "reused garbled circuit" correlation. `T` is an internal wire, never opened
(only branch outputs are revealed), so by standard composition reuse leaks nothing
about `T` beyond the revealed outputs. (This is the Go README's "a fixed shared
value fed into many fresh circuits leaks nothing beyond the outputs" — here with
malicious integrity added.)

### 2b. Integrity — can a malicious peer steer via reuse? No.

`T` is carried as an **authenticated** wire (MAC-bound) and reused directly; it is
**never re-input**. A peer cannot substitute a different `T` — the MAC fails and
the run aborts. Verified: tampering a branch's flip aborts at the leaky-AND F_eq
check *even with the reused trunk* (`demo/tamper_test.sh` extended to tree mode).
This is exactly the steering the Go cache was vulnerable to and could not close.

### 2c. Selective failure — the real accumulation.

emp's authenticated-AND uses leaky-AND + Π_aAND **bucketing**. `get_bucket_size(L)`
picks the smallest bucket `B` with `log2(L)·(B-1) > ssp`, so the residual
leakage/soundness error of **one bucketing instance** (one `compute_inplace` call)
is `< 2^{-ssp}` (`backend/triple_pool.h`). `ssp` is a session parameter
(`AG2PCSession(io, pool, party, ssp = 40)` → `AG2PCProtocol` → `TriplePool`),
default **40**.

The residual is a selective-failure channel: per bucketing instance, a malicious
peer can, with probability `< 2^{-ssp}`, leak one chosen linear predicate on that
instance's wire masks (which include `T`'s bits when `T` feeds the branch) without
being caught; otherwise the run **aborts** (probability `≥ 1 - 2^{-ssp}` — i.e. a
real leak attempt is almost always detected).

Each branch derivation is `≥ 1` `compute_inplace`. By sequential composition /
union bound, over **N** bucketing instances the total statistical error is

>   **error ≤ N · 2^{-ssp}.**

This is the standard "N executions of a `2^{-ssp}`-secure-with-abort protocol cost
`N·2^{-ssp}`," and it is **not specific to the cache** — running N derivations
independently (no cache) does the same N bucketing instances and accumulates the
same `N·2^{-ssp}`.

---

## 3. The answer

### Is it safe? Yes — with a standard, quantifiable accumulation, not a cache-specific flaw.

Reuse adds no new attack: garbling is re-randomized per branch (2a), integrity is
MAC-enforced (2b), and the only accumulation (2c) is the inherent `N·2^{-ssp}` of
doing N malicious-2PC derivations — present with or without the cache.

### Is there a limit on the number of leaves? Yes.

To keep the total statistical error `≤ 2^{-κ}` you need `N · 2^{-ssp} ≤ 2^{-κ}`,
i.e.

>   **N ≤ 2^{ssp − κ}**,  where N ≈ (number of leaves) × (compute_inplace per branch).

With unchunked branches, `N ≈ number of leaves`. At emp's default **ssp = 40**:

| residual target | max leaves (ssp=40) | max leaves (ssp=50) | max leaves (ssp=60) |
|---|---|---|---|
| `2^{-20}` | ~`2^20` (1.0 M) | ~`2^30` (1.1 B) | ~`2^40` (1.1 T) |
| `2^{-30}` | ~`2^10` (1 024) | ~`2^20` (1.0 M) | ~`2^30` (1.1 B) |
| `2^{-40}` | 1 | ~`2^10` (1 024) | ~`2^20` (1.0 M) |

So at the default ssp=40, deriving ~1 000 leaves keeps the residual at `2^{-30}`;
~1 M leaves drops it to `2^{-20}`. For a realistic Lightning channel (say up to
`2^20 ≈ 1 M` commitment updates) you want a comfortable residual (`2^{-40}`),
which needs **ssp ≈ 60**.

### Crucial: `N` is derivations *performed*, NOT the 2^48 index space.

It is tempting to read this as "to support a 48-bit tree we need `ssp ≥ 48 + κ`."
That is **wrong**, for two reasons:

1. **You never derive 2^48 leaves.** That is the *address space* (max commitment
   number), not a workload. 2^48 MPC runs is ~2.8e14 derivations — at an
   optimistic 1000/s that is **~9 000 years**, at the measured ~0.13 s/branch
   ~1 million years. No one runs it.
2. **One derivation costs one `2^{-ssp}`, regardless of its depth.**
   `get_bucket_size(L)` buckets the *whole* batch of `L` ANDs (≈1 M for a 48-deep
   derivation) to `< 2^{-ssp}` in a single instance, so a full-depth derivation
   spends one `2^{-ssp}`, not 48 and not 2^48.

So `N` = secrets actually revealed ≈ commitment updates over the channel's life,
which is `≤ ~2^20`–`2^24` even for an extreme channel — never 2^48. Size `ssp` for
*that*, not the tree. Your "1/1 000 000" target (κ=20) over 1 M derivations is met
by the **default ssp=40**; `ssp=64` gives `2^{-40}` over 2^24 (16 M) derivations,
beyond any real channel. (You *may* set `ssp=68` to nominally cover the full 2^48
at `2^{-20}` — feasible, buckets B≈4→7, ~1.5–2× the triple-gen COTs — but it
guards a workload that cannot physically occur.)

### Do we need to reset from time to time? Per-session no; per-seed yes (and trivial).

- **Restarting the SESSION with the SAME seed does NOT reset the budget.** The
  error is over *total* derivations against that seed's tree (attempts accumulate
  across reconnects; composition already covers abort-and-retry). Re-randomizing a
  cache node does not reclaim it either.
- **The budget is per-SEED.** Rotating to a **new shachain seed** (closing/reopening
  the channel) gives a completely fresh budget — the new tree is independent, and
  old leakage only ever concerned the old (now-closed) channel. So if a channel
  ever approached `2^{ssp-κ}` derivations, it simply rotates the seed. At `ssp≈64`
  this never arises for a real channel.
- **The main lever is `ssp`**, chosen at session start: `ssp ≈ κ + log2(N_max)`.
  For `N_max = 2^24` at `2^{-40}`, `ssp ≈ 64`. Cost: larger buckets (`B` ~4 → ~6-7),
  roughly +50–100% COTs in triple generation — a modest per-session overhead.
  shachain2pc currently uses the **default ssp=40**, so it should be bumped for
  cache / large-batch use and made an explicit parameter.
- **Optional safety:** track the derivation count and abort/warn as it approaches
  `2^{ssp-κ}`, prompting a seed rotation — so a channel can never silently drift
  past its budget.

### What does raising `ssp` cost? (and why not max it "just in case")

`ssp` sets the bucket size `B` via `get_bucket_size(L)`: `B ≈ ssp/log2(L) + 1..2`.
Triple generation scales with `B`:

- **compute** (the dominant COT/leaky-AND): `≈ 3B-2` COTs per AND → ∝ `B`;
- **bandwidth**: ∝ `B`;
- **round-trips / latency**: ∝ `B` (the bucketing runs `B-1` sacrifice layers,
  each with its own exchanges) — so higher ssp also costs proportional wall time
  under non-zero ping;
- **memory**: **unaffected** — the bucketing reuses one sacrifice buffer
  (`~12L` blocks, independent of `B`).

So the price is ~**linear in ssp**, paid on every derivation. Relative to the
default `ssp=40` (`B≈4`), and noting the cache's small branches sit at the higher
end (small `L` ⇒ `B ∝ 1/log2(L)`):

| ssp | B (L≈1M / L≈22k) | triple-gen cost vs 40 | covers @ `2^{-40}` |
|----|----|----|----|
| 40 | 4 / 4 | 1.0× | 1 |
| 64 | 5 / 6 | ~1.3–1.6× | `2^24` (16 M) |
| 88 (nominal full `2^48` @ `2^{-20}`) | 6 / 8 | ~1.6–2.2× | `2^48` |
| 128 | 8 / 10 | ~2.2–2.8× | `2^88` |

**Why not max it out:** it is a *permanent* per-derivation tax (compute +
bandwidth + latency — directly eating the throughput the cache buys) to cover a
workload that cannot physically run (`2^48` derivations ≈ millennia), and the
per-seed rotation backstop means you never have to provision the whole tree
upfront. **`ssp ≈ 64` is the sweet spot**: ~1.3–1.6× for a `2^{-40}` residual over
`2^24` derivations (beyond any real channel). The default 40 is too thin
(`2^{-20}` over 1 M); 88+ buys nothing real at a real cost.

---

## 4. Cache vs no-cache, and the chunking interaction

- **Security parity.** Cache and no-cache both perform ~N bucketing instances →
  same `N·2^{-ssp}`. The cache *concentrates* selective-failure exposure on shared
  ancestor nodes (a rare successful leak on a high `T` is more impactful, since it
  governs a subtree) — but the aggregate probability is unchanged. Conversely, the
  cache exposes the **seed exactly once** (the one-time refill), whereas computing
  every leaf from the seed independently exposes the seed in *every* derivation;
  so for the single most-sensitive value the cache is, if anything, better. Net:
  the cache is a throughput/memory win at no extra security cost (at equal ssp).
- **Chunking spends budget.** Each chunk is its own `compute_inplace` →
  its own `< 2^{-ssp}`. Chunking a branch into `c` chunks multiplies its
  contribution to `c·2^{-ssp}`; the trunk's chunks add likewise. So when the
  security budget is tight, prefer **unchunked branches** and **minimal trunk
  chunking**, raising `ssp` rather than chunking finely. Chunk only as far as
  memory actually demands. (This is the memory↔budget trade behind the chunking
  work, made precise.)

---

## 5. Caveats

- This analysis is from the **protocol structure** (WRK17 / KRRW18, eprint
  2018/578) plus emp's `get_bucket_size` parameterization and the per-run
  transcript-seed — **not** a line-by-line proof of the (AI-assisted, unaudited)
  emp rewrite. Before relying on large-N caching, confirm with upstream / a proof
  pass that (a) each `compute_inplace` bucketing truly achieves `< 2^{-ssp}`, and
  (b) the per-instance errors compose by union bound under heavy reuse (no
  cross-instance amplification beyond the standard sum).
- Descendant-derivability is shachain-inherent: revealing `H(I)` lets anyone
  derive `H(I')` for descendants `I'`. For "reveal a subset later," reveal in
  ancestor-last order or accept derivable descendants (see `run/derive.h` /
  README). The cache does not change this.
- The seed (I=0) is never cached and is CLI-gated.

---

## 6. Recommendation

1. Build the **in-session adaptive cache** (generalize `RunDerivationTree`):
   maintain the authenticated frontier, derive on demand, update the cache in
   decreasing-index order; **refill from the seed at session start** (no
   persistence).
2. Make **`ssp` an explicit session parameter** sized for *derivations actually
   performed* (≈ commitment updates, `≤ ~2^24` for any real channel — never the
   2^48 tree): `ssp ≈ κ + log2(N_max)`, e.g. **`ssp = 64`** for `≤ 2^24` updates
   at `2^{-40}`. Resetting the *session* (same seed) does not reset the budget;
   rotating the *seed* (new channel) does — so a hard cap near `2^{ssp-κ}` that
   triggers a seed rotation is the clean backstop, not session restarts.
3. Prefer **unchunked branches / coarse trunk chunking** when the budget matters;
   chunk only as memory requires, and raise `ssp` to compensate for the extra
   `compute_inplace` instances.
4. Persistence across restarts (to skip the per-session refill) remains the
   separate, harder "stateful authenticated garbling with resume" project
   (serialize authenticated state + Δ/COT) — out of scope for now.
