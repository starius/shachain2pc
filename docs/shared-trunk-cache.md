# Shared-trunk cache: plan + reuse-security analysis

This documents (1) the plan to generalize the shared **trunk** (`RunDerivationTree`)
into a Go-style **cache**, and (2) a deeper analysis of the one open security
question that gates it: *is reusing a cached authenticated value across many
derivations safe, is there a limit on how many leaves we can derive, and do we
need to reset?*

Status: research/decision note. No persistence is planned now — the cache is
refilled from the seed at the start of each session (accepted trade-off).

---

## 0. Current setting & operating limit (TL;DR)

**Code default: `ssp = 40`** (emp's default; the constant `run::kSsp`, passed to
every `AG2PCSession`) — kept for **demo/research performance only**. For
**production funds, raise it to `ssp ≈ 60–64`** ("Production guidance" below):
`2^-20` per channel at ssp=40 is **not** a production-grade target for
theft-adjacent revocation material.

**The budget.** The bucketing error is `< 2^-ssp` per `compute_inplace`, and it
accumulates as `N · 2^-ssp` against **one seed**, where **`N` = the total number of
`compute_inplace` bucketing instances** ever run against that seed — *every*
trunk-refill chunk, branch chunk, precomputed-but-unrevealed output, and *aborted*
attempt, not just revealed secrets. (It is bounded by the computations actually
performed, never the 2^48 index space; see §3.) With the planned design (§1: ~1–2 instances per
update) `N` ≈ 1–2× the channel-update count.

At the **demo/research default `ssp = 40`**:

| residual leak prob | safe instances `N` | ≈ channel updates (~1–2 inst/update) |
|---|---|---|
| `2^-20` (~1 in 1 M) | ~`2^20` | ~500 k – 1 M |
| `2^-30` (~1 in 1 B) | ~`2^10` | ~500 – 1 000 |

The residual is the chance of a *single, undetected, ~1-bit* leak (a real attempt
aborts w.p. `~1-2^-ssp`, and theft needs far more than one bit) — adequate for
demo/research, but **`2^-20` is too thin for production funds**.

**Production guidance:**
1. Use **`ssp ≈ 60–64`** → `2^-40` residual over ~`2^20`–`2^24`
   instances. Cost is
   ~linear (§3); a coordinated change (both parties match).
2. **Count every `compute_inplace` against the seed** (revealed, precomputed,
   aborted, refills, chunks), track the running per-seed budget, and **rotate the
   seed** (open a fresh channel — resets the budget for free) before crossing the
   chosen risk threshold.

The rest of this doc is the analysis behind these numbers.

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
  *(~600 KB is an order-of-magnitude estimate of the raw share material; the actual
  `AG2PCSession::carried_` RSS — map overhead, `AShareBundle` layout — is unmeasured
  until implemented.)*
- **Derive on demand.** For `H(I)`, branch from the deepest cached ancestor. The
  current implementation computes full aligned 16-leaf low-subtree tiles as one
  multi-output `run_artifact` (15 SHA edges in one bucketing instance), while
  partial tile edges fall back to one-SHA steps. Reveal uses the same
  `AG2PCSession::reveal` path as before and is timed separately from pre-reveal
  computation.
- **No persistence.** The cache + COT mesh live in the in-memory session. On a new
  session (or reconnect) we **refill from the seed** (recompute the trunk once,
  ~one 48-block chain) and re-warm. Cross-restart persistence of authenticated
  state (+ Δ/COT) is deliberately out of scope.
- **The seed (I=0) is never cached.** It is the master secret (gated in the CLI),
  and reusing the raw input breaks emp's checks anyway (the empty-trunk c_gamma
  abort). Every cache node is a hash output.

This is a strict generalization of `RunDerivationTree`; it needs no emp changes.

### Chunking in the cache: fixed update-cap trunk + 16-leaf branch tiles

The concrete design, given a committed **maximum of `2^n` updates** for the channel.
(This update cap is a design choice; it relates to the budget `N` of §0/§4 — total
`compute_inplace` instances — by the concrete tiling shape below.)

**Commit to `2^n` updates up front.** Near StartIndex the first `2^n` indices share
their high `(48-n)` bits, so the chain splits cleanly and permanently:

- **Trunk** = the `(48-n)` shared high blocks. Computed **once per session**; only
  its **tip** is cached. *Do not cache inside the trunk* — every update traverses
  the whole trunk, so its internals are never branch points and caching them is
  useless; the trunk chunks exist only for the one-time refill and are discarded
  once they produce the tip.
- **Branches** = the n-bit subtree below the tip.
- **The cap `n` is bounded by the budget.** With 16-leaf branch tiles, aligned
  ranges spend about `2^(n-3)` branch instances plus trunk chunks, not one instance
  per leaf. Choosing `n` is still choosing the operating point on the budget curve
  (and fixes the trunk length), but the tile factor is materially better than the
  earlier 1-SHA-per-step fallback.

**Trunk → chunk at `trunk_chunk_size` (the main refill toggle; default 16).**
The trunk is the single long chain; its chunk size trades the one-time refill cost
(shape illustrated on a 48-block chain — the real trunk is `48 − n`):

| trunk_chunk_size | peak RAM | round-trips | wall @50 ms RTT | budget (instances) |
|---|---|---|---|---|
| 1 (one SHA/step) | **26 MB** | 198 | ~32 s | 48 × 2^{-ssp} |
| 8 | 116 MB | 30 | ~11 s | 6 × 2^{-ssp} |
| 16 | ~hundreds MB | 18 | lower RTT cost | 3 × 2^{-ssp} |
| whole | 468 MB | 10 | ~5 s | 1 × 2^{-ssp} |

Default **16** keeps refill round-trips low for remote peers while still bounding
the circuit below the whole-trunk RSS spike. Drop to 1 only when RAM is the hard
limit; use the whole trunk only when the RSS spike is acceptable. The trunk is
once per session, so this cost amortizes over the `2^n` leaves — it matters most
under frequent restarts.

**Branches → fixed 16-leaf tiles.** Within the subtree, cache tile roots through
the BOLT-03 decreasing-order stack. Every full aligned 16-leaf tile is one
multi-output circuit: 15 internal SHA edges, 16 leaf outputs, one
`compute_inplace` instance. A 256-leaf aligned range therefore spends 15 tile-root
prefix instances plus 16 tile instances for all 256 leaves, instead of 255
one-SHA instances. Partial edges at the boundaries fall back to one-SHA steps.

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
No "reused garbled circuit" correlation. The function-dependent leaky-AND /
`compute_inplace` path has its own hashing and bucketing state (not just this
half-gate seed), so the cache argument also relies on the AG2PC/WRK17/KRRW18
proof that each fresh `compute_inplace` remains secure when its representative
inputs are carried authenticated wires from prior computations. Subject to that
proof obligation, `T` is an internal wire, never opened (only branch outputs are
revealed), so standard composition says reuse leaks nothing about `T` beyond the
revealed outputs. (This is the Go README's "a fixed shared value fed into many
fresh circuits leaks nothing beyond the outputs" — here with malicious integrity
added.)

### 2b. Integrity — can a malicious peer steer via reuse? No.

`T` is carried as an **authenticated** wire (MAC-bound) and reused directly; it is
**never re-input**. A peer cannot substitute a different `T` — the MAC fails and
the run aborts. Verified: tampering a branch's flip aborts at the leaky-AND F_eq
check *even with the reused trunk* (`make test-cache-tamper`, which runs
`demo/cache_tamper_test.sh`).
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

For budget calculations, count instances first. With one unchunked branch per
leaf, instances are approximately leaves; with the current 16-leaf tile cache,
aligned ranges are roughly one branch instance per 8 leaves plus the one-time
trunk chunks. At emp's default **ssp = 40**:

| residual target | max instances (ssp=40) | max instances (ssp=50) | max instances (ssp=60) |
|---|---|---|---|
| `2^{-20}` | ~`2^20` (1.0 M) | ~`2^30` (1.1 B) | ~`2^40` (1.1 T) |
| `2^{-30}` | ~`2^10` (1 024) | ~`2^20` (1.0 M) | ~`2^30` (1.1 B) |
| `2^{-40}` | 1 | ~`2^10` (1 024) | ~`2^20` (1.0 M) |

So at the default ssp=40, ~1 000 instances keep the residual at `2^{-30}`;
~1 M instances drop it to `2^{-20}`. For a realistic Lightning channel (say up to
`2^20 ≈ 1 M` commitment updates, and therefore far fewer branch instances under
tiling), a comfortable residual (`2^{-40}`) still points to **ssp ≈ 60-64** as a
production setting.

### Crucial: `N` is bucketing instances, NOT the 2^48 index space.

It is tempting to read this as "to support a 48-bit tree we need `ssp ≥ 48 + κ`."
That is **wrong**, for two reasons:

1. **You never derive 2^48 leaves.** That is the *address space* (max commitment
   number), not a workload. 2^48 MPC runs is ~2.8e14 derivations — at an
   optimistic 1000/s that is **~9 000 years**, at the measured ~0.13 s/branch
   ~1 million years. No one runs it.
2. **One unchunked `run_artifact` costs one `2^{-ssp}`, regardless of depth.**
   `get_bucket_size(L)` buckets the *whole* batch of `L` ANDs (≈1 M for a 48-deep
   derivation) to `< 2^{-ssp}` in a single instance, so an unchunked full-depth
   derivation spends one `2^{-ssp}`, not 48 and not 2^48. Chunked execution spends
   one term per chunk, and the planned cached branch spends about 1-2 terms per
   channel update.

So `N` = total `compute_inplace` instances over the channel's life, which is
roughly 1-2× actual updates in the planned cache and still nowhere near 2^48. Size
`ssp` for *that*, not the tree. A "1/1 000 000" target (κ=20) over about 1 M
instances is met by the **demo/research default ssp=40**; production funds should
target a stronger residual, e.g. `ssp=64` gives `2^{-40}` over 2^24 (16 M)
instances. The number of updates covered is a function of the cache shape; with
aligned 16-leaf tiles it is higher than the old one-step-per-edge fallback. (You
*may* set `ssp=68` to nominally cover the full 2^48 at `2^{-20}`
— feasible, buckets B≈4→7, ~1.5–2× the triple-gen COTs — but it guards a workload
that cannot physically occur.)

### Do we need to reset from time to time? Per-session no; per-seed yes (and trivial).

- **Restarting the SESSION with the SAME seed does NOT reset the budget.** The
  error is over *total* `compute_inplace` instances against that seed (attempts
  accumulate across reconnects; composition already covers abort-and-retry).
  Re-randomizing a cache node does not reclaim it either.
- **The budget is per-SEED.** Rotating to a **new shachain seed** (closing/reopening
  the channel) gives a completely fresh budget — the new tree is independent, and
  old leakage only ever concerned the old (now-closed) channel. So if a channel
  ever approached `2^{ssp-κ}` instances, it simply rotates the seed. At `ssp≈64`
  this never arises for a real channel.
- **The main lever is `ssp`**, chosen at session start: `ssp ≈ κ + log2(N_max)`
  over the max instance count `N_max`. For `N_max = 2^24` at `2^{-40}`,
  `ssp ≈ 64`.
  Cost: larger buckets (`B` ~4 → ~6-7), roughly +50–100% COTs in triple generation
  — a modest per-session overhead. shachain2pc uses the **demo/research default
  `ssp=40`** (the named constant `run::kSsp`); production should use ~60–64 (§0).
- **Optional safety:** track the instance count and abort/warn as it approaches
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

So the price is ~**linear in ssp**, paid on every `compute_inplace`. Relative to
the default `ssp=40` (`B≈4`), and noting the cache's small branches sit at the
higher end (small `L` ⇒ `B ∝ 1/log2(L)`):

| ssp | B (L≈1M / L≈22k) | triple-gen cost vs 40 | covers @ `2^{-40}` (instances) |
|----|----|----|----|
| 40 | 4 / 4 | 1.0× | 1 |
| 64 | 5 / 6 | ~1.3–1.6× | `2^24` instances (≈8-16 M updates) |
| 88 (nominal full `2^48` @ `2^{-20}`) | 6 / 8 | ~1.6–2.2× | `2^48` |
| 128 | 8 / 10 | ~2.2–2.8× | `2^88` |

**Why not max it out:** it is a *permanent* per-`compute_inplace` tax (compute +
bandwidth + latency — directly eating the throughput the cache buys) to cover a
workload that cannot physically run (`2^48` instances ≈ millennia), and the
per-seed rotation backstop means you never have to provision the whole tree
upfront. For **production**, **`ssp ≈ 60–64`** is the operating point: ~1.3–1.6× for
a `2^{-40}` residual over ~`2^24` instances (≈8-16 M updates, beyond any real
channel). The demo/research default 40 is too thin for funds (`2^{-20}` over
~1 M instances);
88+ buys nothing real at a real cost.

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
- **Chunking spends budget** (the third axis, detailed in §1 "Chunking in the
  cache"). Each chunk/tile is its own `compute_inplace` → its own `< 2^{-ssp}`.
  The current design uses 16-leaf branch tiles to reduce branch instances, and a
  trunk chunk size default of 16 to reduce refill round-trips. Raise `ssp` rather
  than coarsen the cache when the budget is tight.

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
2. **For the current PoC, keep `ssp = 40`** (the documented constant
   `run::kSsp`) to preserve performance while measuring the cache. This is a
   demo/research setting: it gives residual `2^-20` over about 1 M
   `compute_inplace` instances, and is not a production target for funds.
   **For production, use `ssp ≈ 60-64`**
   and track the per-seed instance count. Sizing `ssp` for instances actually
   performed, never the 2^48 tree, is the right mental model:
   `ssp ≈ κ + log2(N_max)`. Resetting the *session* with the same seed does **not**
   reset the budget; rotating the *seed* (new channel) does. A cap near
   `2^{ssp-κ}` that triggers seed rotation is the clean backstop.
3. **Chunking: commit a `2^n`-update cap, chunk the trunk at
   `trunk_chunk_size` (default 16), and run branches as fixed 16-leaf tiles**
   (§1 "Chunking in the cache"). The fixed-cap split gives a `(48-n)`-block trunk
   (chunked, computed once, only its tip cached — nothing cached inside it) and an
   n-bit subtree of cached tile roots. Full aligned tiles use one multi-output
   instance for 16 leaves; partial boundary edges fall back to one-SHA steps. Drop
   `trunk_chunk_size` only when RAM is the hard limit.
4. Persistence across restarts (to skip the per-session refill) remains the
   separate, harder "stateful authenticated garbling with resume" project
   (serialize authenticated state + Δ/COT) — out of scope for now.
