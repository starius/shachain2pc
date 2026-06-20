# emp patches

Patches applied to the pinned emp checkout during vendoring. Each is intended to
be upstreamable; this file records the rationale and upstream status.

## `emp-ag2pc-546d5e4-align-prg-random-data.patch`

**What:** in `emp-ag2pc/backend/triple_pool.h`, `layered_bucket_into_acc` draws
the per-layer cyclic-shift coin with `PRG::random_data(&raw, sizeof(uint32_t))`
into a stack `uint32_t raw`. `PRG::random_data` documents and `assert`s a
16-byte-alignment precondition on its destination
(`"random_data requires 16-byte aligned data; use random_data_unaligned"`), but a
`uint32_t` is only 4-byte aligned. The patch switches to the documented
`PRG::random_data_unaligned`.

**Why it's a genuine emp bug (not a shachain2pc-specific tweak):** the call
violates `random_data`'s own precondition independent of any caller. It aborts in
assert-enabled builds and is alignment-luck-dependent in `NDEBUG` builds (the
value is correct only when the stack slot happens to be 16-aligned). The fix is
behavior-preserving in release: `random_data_unaligned`'s small-buffer path yields
the same first 4 keystream bytes, so it does not change the protocol for
C++↔C++ runs — it only removes the precondition violation.

**Why we need it here:** our pure-Rust AG2PC backend computes this coin with the
natural unaligned 4-byte read, matching `random_data_unaligned`. With the patch,
C++↔Rust cross-mode agrees on the bucket permutation; without it, assert-enabled
C++ probes abort on the bucketing path.

**Upstream status:** not yet submitted. Target: `emp-toolkit/emp-ag2pc`. Suggested
title: *"triple_pool: use PRG::random_data_unaligned for the unaligned bucket-shift
coin"*. Once C++ is retired this patch is irrelevant to shachain2pc, but it remains
a correct fix for emp.
