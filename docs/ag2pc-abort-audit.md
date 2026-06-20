# Rust AG2PC backend — abort-path audit

Scope: a **structural** review of the malicious-security abort paths in the
from-scratch Rust AG2PC/SoftSpoken backend (`rust/crates/shachain2pc-emp-compat`),
asking for each: *what does it check, where, is it logically sound, and is it
faithful to the C++ emp reference it is wire-compatible with?* This is **not** a
formal proof, a constant-time/side-channel audit, or a substitute for an external
review before real funds. It is the "eyes on the checks" pass requested in review.

Method: read each check; confirm it exists, returns `Err` (no `RESULT`) on
failure, and matches emp's construction. Cross-mode byte-equality with C++ emp
(`cross_mode_smoke.sh`, both directions, outputs verified vs `ref_cli`) is strong
corroborating evidence: if the Rust diverged from emp on any honest-path byte it
would fail, and the mode-level tamper smokes (`cross_mode_tamper_smoke.sh`) show
the abort paths fire end-to-end.

## The six abort paths

All line numbers are in `shachain2pc-emp-compat/src/lib.rs`.

1. **Base OT (CSW) consistency** — `csw_send`/`csw_recv`.
   Receiver checks the sender's proof (`CswProofMismatch`, ~L834); sender checks
   the receiver (`CswReceiverMismatch`, ~L772). Guards the Chou-Orlandi-style base
   OT that seeds SoftSpoken. Present and faithful.

2. **SoftSpoken PPRF leaf check** — `pprf_check_send`/`pprf_check_recv` (L1137–1193).
   Sender commits `t = XOR_y H(leaf)` per instance plus a digest of all leaf
   hashes. The receiver, who holds every leaf except its secret punctured index
   `alpha[i]`, *reconstructs* the punctured leaf's contribution as `t XOR
   (sum of known)`, hashes the full reconstructed set, and compares to the
   sender's digest → `FeqMismatch` (L1190). Because `alpha` is the receiver's
   secret, a sender cannot cheat only the punctured leaf; any inconsistent leaf
   changes the hash. **Sound.**

3. **SoftSpoken COT correlation check** — `combine_send_chunk`/`combine_recv_chunk`
   (gated on `self.malicious`), `FeqMismatch` ~L1061. The standard COT consistency
   check on the extended outputs. Present and faithful.

4. **Bucketed leaky-AND (triple integrity)** — `get_bucket_size` (L2571),
   `compute_inplace` (L2594), `leaky_and_halfgate` (L2715), `layered_bucket_into_acc`
   (L2792), `ag2pc_feq_check` (L3056).
   - `get_bucket_size(L)` returns the smallest `B` with `log2(max(L,1024))·(B-1) >
     ssp`, i.e. residual `< 2^-ssp` — matches C++ `triple_pool.h`.
   - Each layer's leaky-AND folds its output into a running SHA-256 (`hashes.feq`);
     `B-1` sacrificial layers are combined into the accumulator with a **cyclic
     shift `r = PRG(S) mod L`**, where `S = RO("AG2PC RO") ∘ io.digest ∘ sib.digest`
     is a transcript-derived public coin (unpredictable before the layer is
     committed). The shift prevents an adversary from steering which triples bucket
     together.
   - `ag2pc_feq_check` is a **commit-then-open equality check**: Alice commits
     `H(digest, nonce)` *before* seeing Bob's digest, then both open; mismatch →
     `FeqMismatch` (L3075/L3093). Neither side can adapt, so a cheating party whose
     leaky-AND/bucketing diverged is caught. **Sound**, and the cyclic-shift +
     equality-check structure is KRRW18 as emp implements it.

5. **Garbling c_gamma / gamma check** — `ag2pc_gamma_check_pass` (L2145),
   `ag2pc_garbler_and_gate` / `ag2pc_evaluator_and_gate`, comparison at L2087–2098.
   Each party computes a per-AND consistency block `m1_t[i]`; after the circuit
   both hash their `m1_t` vectors and compare → `FeqMismatch` (L2097). The values
   are pre-committed by the already-sent garbled tables, so a plain digest equality
   (no commit-open) is adequate; a cheating garbler whose tables are inconsistent
   produces a divergent evaluator `m1_t`. **Sound.**

6. **Reveal (output integrity)** — `decode` (L2392) / `decode_to_party` (L2420).
   The recipient receives the peer's masked-bit shares plus a digest of the peer's
   wire MACs, recomputes `key XOR share·Δ` for each wire, and aborts unless its
   hash equals the peer's digest (`FeqMismatch`, L2454) — an IT-MAC check that
   makes any wrong revealed bit abort rather than pass. The output is then
   `my_share XOR lambda XOR peer_share`. **Correct-or-abort.**
   PUBLIC reveal = Bob decodes/verifies, then broadcasts to Alice (Alice trusts the
   broadcast). This is the documented Bob-favored unfairness, faithful to emp's
   `reveal(PUBLIC)`; for the deterministic shachain output Alice can re-check
   against the agreed value if desired.

Supporting: `check_secure_wires` (L2490) rejects stale/wrong-length carried wires
before reveal; secrets zeroize on drop; `I=0` is refused before any socket.

## Assessment

Every malicious-security check emp relies on is present in the Rust port, returns
a typed `Err` with no `RESULT` on failure, and matches emp's construction
(corroborated by byte-level cross-mode equality). The leaky-AND/bucketing,
equality check, c_gamma check, OT consistency checks, and authenticated reveal are
each individually sound on read.

## Residual risk / recommendations

- **Structural, not formal.** "Faithful to emp + cross-mode byte-equal + aborts on
  the tested tampers" is strong but not a proof that *every* adversarial deviation
  aborts. Before backing real funds, get an external review and consider porting
  emp-ag2pc's own KAT/adversarial vectors.
- **Per-primitive adversarial coverage is thinner than the old backend's.** Today
  the adversarial tests are mode-level (`SHACHAIN2PC_TAMPER` on chunk/tree/cache)
  plus cross-mode tamper smoke. Add targeted unit tamper tests that corrupt each
  check's inputs (a garbled-table row, a bucket triple, a PPRF leaf, a reveal MAC)
  and assert the specific `Err`.
- **Not constant-time-audited.** `select_block`/`block_lsb` branching and the
  AES/PRP paths were not reviewed for timing side channels.
- **`ssp = 40` is the demo/research budget** (inherited from C++): residual
  `N·2^-40`. Production needs `ssp ≈ 60–64` and per-seed rotation; unchanged here.
- **No proof obligation is discharged for the constant triple-pool `pair_seed`** —
  it is copied faithfully from emp (`triple_pool.h:424`), so any caveat is emp's,
  not the port's.

Conclusion: the abort paths are present and sound on structural review; this raises
confidence materially but does not replace a formal external audit.
