# Notes on the rewritten emp-ag2pc (session/backend API)

Captured while porting the C++ side from the old single-shot `emp::C2PC` to the
rewritten upstream emp-ag2pc (`546d5e4`, "session/backend, byte-bool contract").
These are things worth knowing for future work — especially the resumability /
async features that the old API did not have.

## Why we moved

The old pin (emp-ag2pc `356cfd82`, `fpre.h == 2f079f0`) has a latent
uninitialized-memory bug: at `fpre_threads=1` its single-shot `C2PC`/`Fpre`
`combine` fills only `min(batch_size, permute_batch_size)` triples per refill, but
`function_independent` does one `refill()` and reads all `num_ands` triples from a
`new block[batch_size*3]` that is never `memset`. So every circuit with
`num_ands > permute_batch_size` (3100) — i.e. every real SHA circuit — reads
uninitialized heap. It is correct only because fresh pages are zero and `(0,0,0)`
is a degenerate-valid AND triple; `MALLOC_PERTURB_=170` flips the output. It is
also insecure (those gates get no masking). emp's own `sha256.cpp` test hits the
same path. The rewrite removes this entirely: it sizes to `num_ands` with
zero-initialized `std::vector`s and drops `permute_batch_size`. We verified the
new C++ stack is `MALLOC_PERTURB_`-robust (output unchanged under heap poisoning).

## API shape

Header-only **C++20**. The whole 2PC is one object, `emp::AG2PCSession`:

```cpp
NetIO *io = ...;                         // single full-duplex socket; the session
ThreadPool pool(4);                      //   spawns its own sibling channel
AG2PCSession sess(io, &pool, party, /*ssp=*/40);
using Ctx = AG2PCSession::DirectCtx;     // == AG2PCCtx, a pure BooleanContext recorder
auto a = sess.input<UInt_T<Ctx,32>>(ALICE, x);   // each party owns its input; PUBLIC = constant
auto c = a + b;                          // operators record gates into the current chunk
uint32_t out = sess.reveal(c, PUBLIC).value();   // reveal returns std::optional<clear_t>
```

- `ThreadPool` lives in the **global** namespace (emp-tool `third_party/ThreadPool.h`), not `emp::`.
- Value types are emp-tool's context-bound `*_T<Ctx,N>`: `Bit_T`, `UInt_T`, `Int_T`,
  `Float_T`, and `BitVec_T<Ctx,N>` (fixed-width crypto blocks — what we use for the
  256-bit shares/output). `clear_t` for `BitVec_T<Ctx,N>` is `std::array<bool,N>`.
- `reveal(v, recipient, keep...)` → `std::optional<clear_t>`; `recipient ∈ {PUBLIC, ALICE, BOB}`.
  Returns the value at the recipient (or PUBLIC), `nullopt` elsewhere. There is **no**
  XOR-share reveal.

## Protocol (what changed under the hood)

- Authenticated garbling **WRK17 + KRRW18 (eprint 2018/578)**: a function-dependent
  **half-gate leaky-AND** run in place on each AND gate's own input masks, a single
  **batched `F_eq`** check, and **cyclic-shift bucketing**.
- Correlated OT is a single lifetime-open **SoftSpoken⟨4⟩** session from emp-ot —
  **replacing IKNP**. Its consistency check runs **before every reveal**, so it gates
  output: a deviating party makes `reveal` abort (`emp::error`) rather than return a
  steered value. **No more stdout-scraping CheatGuard** — the abort is structural.
- Party 1 = garbler, party 2 = evaluator (same role split as before).

## Resumability / liveness (new, and useful)

- **Explicit wire liveness** — no refcount, no global `emp::Backend` singleton. The
  session owns `carried_` (materialized authenticated wire state).
- **`checkpoint(keep...)`** prunes carried state down to the named values (drops the
  rest); `checkpoint()` with no args drops everything pending + all carried. This is
  the resumability primitive: keep a handful of authenticated wires alive across an
  arbitrary amount of further computation without paying for the whole history.
- **`reveal(v, recipient, keep...)`** flushes keeping `v` + `keep...` alive.
- Memory is **linear in (#AND gates + live width)**, not #wires — a slot-reused
  per-wire layout. Stale wires error loudly (a value whose ids were pruned).

## Async / parallelism

- The session takes a `ThreadPool*`; the engine uses it for local-compute
  parallelism (passes, bucketing, hashing). Unlike the old `fpre_threads` (which
  changed the **stream schedule** and thus the wire), this is compute-only.
- The transport is a single full-duplex `NetIO` plus an internal **sibling channel**
  (`NetIO::make_sibling`, a second socket re-established on the same port after the
  primary accept). The session sets this up itself; callers create one `NetIO`.

## Circuits — three ways in, plus the raw escape hatch

A circuit reaches the protocol three ways, all byte-identical transcript:
1. **Direct / chunked** — operators record into the current chunk, flushed at `reveal`/`checkpoint`.
2. **Compiled replay** — `sess.run(circuit, args...)` replays a stored typed `Circuit` (`frontend::compile<rec::…>` once, replay many; same circuit runs on plaintext / this protocol / ZK).
3. **Live body replay** — `sess.run(body, args...)` replays a pure body live per pass, no stored IR.

For a hand-built / loaded untyped circuit (an AES/SHA builtin, or our Bristol
derivation), use **`sess.run_artifact<RetV>(prog, args...)`** with an explicit
return value type. `prog` is a `circuit::BooleanProgram`
(`{num_inputs, num_wires, vector<Gate>, vector<uint32_t> outputs}`, `Op ∈
{And,Xor,Not,Const0,Const1}`). **It must be RecordContext-canonical**: gate `i`'s
output wire is exactly `num_inputs + i` (dense, single-def, topological, ≤1 Const0
and ≤1 Const1). `run_artifact`/the engine assert this (`backend/canonical.h`); a
non-canonical (e.g. Bristol-numbered) program is rejected. We renumber our
derivation circuit into this form in `run/derive.h::ToBooleanProgram`.
Args to `run_artifact` are concatenated in wire order (our order: BOB share → wires
`[0,256)`, ALICE share → `[256,512)`).

- The new emp-tool ships SHA/AES as compiled `.empbc` programs
  (`emp-tool/ir/files/sha256_256.empbc`) + a C++ SHA gadget
  (`emp-tool/circuits/crypto/sha256.h`); `circuit::builtin_circuit("sha256_256")`
  loads the builtin. (We keep using our own Bristol-derived circuit for an exact,
  already-validated match to the BOLT-03 reference, rather than re-expressing the
  derivation on the new SHA.)

## Build gotchas (for the bootstrap)

- emp-tool / emp-ot are external `find_package` deps that emp-ag2pc tracks as
  **`main`** (a moving target). emp-tool main has since renamed the `Session`
  concept (`DirectCtx`/`direct_ctx()` → `ctx_t`/`ctx()`), which fails emp-ag2pc
  `546d5e4`'s `static_assert`s. Pin emp-tool/emp-ot to their main commits **as of
  emp-ag2pc's commit date**, not bleeding HEAD.
- Disable tests with the real toggles `EMP_TOOL_BUILD_TESTS` / `EMP_OT_BUILD_TESTS`
  / `EMP_AG2PC_BUILD_TESTS` (default ON for a top-level configure — `BUILD_TESTING`
  is ignored).
- Set `EMP_TOOL_NATIVE_ARCH=OFF` under nix (it strips `-march=native`, which would
  otherwise leave SSE4.2 off and break emp-ot svole's `_mm_cmpgt_epi64`). Pass the
  portable baseline `-msse4.2 -maes -mpclmul` explicitly. (Native would be faster;
  this is a portable lower bound.)
- The emp-ag2pc INTERFACE target's headers do not install under our prefix layout —
  copy them. The new emp-tool dropped the legacy Bristol files — restore the
  standard `sha-256.txt` from an older emp-tool commit (our `circuit_gen` needs it).
- Libs install under `lib64/` on this system; force `CMAKE_INSTALL_LIBDIR=lib` (and
  the Makefile searches both). Link `-lemp-ot -lemp-tool` (emp-ot depends on emp-tool).

## Caveat

README: "AI-assisted rewrite, not yet audited. Do not deploy without your own
audit." So it fixes the old bug and is faster, but it is itself not yet audited.
