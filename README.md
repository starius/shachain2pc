# shachain2pc

A self-contained, **maliciously-secure** two-party computation of the
[BOLT-03](https://github.com/lightning/bolts/blob/master/03-transactions.md)
shachain per-commitment-secret derivation (`generate_from_seed`).

Two parties hold XOR shares of the seed and jointly compute
`H(I) = generate_from_seed(seed, I)` for an agreed index `I` without either
party learning the seed — and, crucially, **without either party being able to
derive a secret for an index that was not authorized**, in particular not a
*future* secret, even if it deviates arbitrarily from the protocol.

## How it works

For each index `I` there is **one fixed boolean circuit**, agreed by both
parties, that computes `seed = aliceShare ⊕ bobShare` and then
`generate_from_seed(seed, I)` with `I`'s per-link bit-flips baked in as **public
constants** (not a controllable input). That circuit is evaluated under
**authenticated garbling** (EMP [`emp-ag2pc`](https://github.com/emp-toolkit/emp-ag2pc),
the WRK17 protocol): the parties evaluate exactly the agreed circuit, or the
protocol **aborts**. So the only reachable output is `H(I)` for the agreed `I` —
there is no steering to another index, and no intermediate hash leaks.

## Security: the attack this stops, and how

A naive garbled-circuit derivation feeds the per-link bit-flip as the garbler's
*private* circuit input (`gIn = gShare ⊕ flip(B)`) and re-inputs the carried
shares between links. Under a malicious adversary that is broken: a cheating
party can (a) garble a different circuit, or (b) XOR an arbitrary mask in place
of the agreed flip, steering the chain to `generate_from_seed(seed, I′)` for an
`I′` it chose and learning that (e.g. future) secret. This is the property a
semi-honest garbled-circuit protocol cannot give.

shachain2pc removes both freedoms:

1. **One fixed, agreed circuit per index.** A derivation of index `I` is a single
   boolean circuit that, from the two seed-share inputs, recomputes
   `seed = gShare ⊕ eShare` and then `generate_from_seed(seed, I)` with `I`'s
   bit-flips baked in as **public constants**. The flips are no longer an input
   anyone controls; they are part of the circuit both parties agree on.
2. **Maliciously-secure evaluation.** The circuit is evaluated with authenticated
   garbling (`emp-ag2pc`). This guarantees the parties evaluate exactly the
   agreed circuit on authenticated inputs, or the protocol **aborts** — a
   cheating garbler cannot substitute a different circuit, and neither party can
   feed an input inconsistent with its authenticated share. So the only reachable
   output is `H(I)` for the agreed `I`; there is no steering to `I′`, and no
   intermediate hash is revealed.

The soundness check is per-AND-gate: the garbler is information-theoretically
MAC-committed (via the WRK17 authenticated AND triples) to each gate's truth
table, so garbling a different function is caught (`emp-ag2pc` reports
`no match GT!`). Failures in the preprocessing phase already terminate the
process (emp's `error()` calls `exit(1)`), so no value is produced. The online
phase is the nuance: this `emp-ag2pc` build *reports* a detected inconsistency on
`std::cout` and then continues with a corrupted value rather than hard-aborting,
and `2pc.h` exposes no status to query. `run/` closes that gap with a
`CheatGuard` that captures the engine's consistency-check output and turns any
detection into a hard abort, so the untrusted value is discarded and never
returned. The malicious demo (`demo/run_cheat.sh`) exercises exactly this: the
honest evaluator aborts and learns nothing.

The agreed index `I` is chosen out of band; each party only runs the protocol
for an `I` it is willing to authorize, so neither party can unilaterally drive a
derivation of a future index. As a fast first-line check, the two parties also
exchange a digest of the circuit before any preprocessing and abort immediately
on a mismatch (this is *not* the security boundary — authenticated garbling
still catches a party that commits to one circuit and garbles another).

## Why this stack

- **Engine: EMP `emp-ag2pc`** — the canonical, purpose-built malicious 2PC of
  boolean circuits (authenticated garbling). Reusing a vetted engine avoids
  rolling our own malicious crypto, which would not be reliable or secure.
- **Language: C++** — required to use `emp-ag2pc`. We are 2-party only and do
  **not** need post-quantum or threshold security, so we use just the
  malicious-2PC-of-SHA-256 core.
- **Build: nix** — a flake dev shell (`nix develop`) pins the toolchain and
  OpenSSL; `tools/bootstrap-emp.sh` fetches and builds the pinned emp stack into
  `.deps/emp`.

The cryptographic rounds live inside the vetted `emp-ag2pc` engine; the "pure
protocol" this project owns is the circuit/relation definition and the share/IO
layout.

## Layout

| Dir | Role |
| --- | --- |
| `reference/` | single-party `generate_from_seed` oracle + KATs (no MPC), and `ref_cli` |
| `protocol/` | the pure, deterministic part: build the Bristol circuit for index `I` (`bristol.*`, `circuit_gen.*`, `wire_layout.h`) — public flips + a SHA-256 chain over the XOR of the two seed shares — and the input/output wire layout |
| `run/` | drive the two `emp-ag2pc` parties over a socket: feed shares, evaluate, obtain `H(I)`, abort on any cheat (`derive.h`) |
| `demo/` | two-party binary (`party`), circuit generator (`gen_circuit`), and the honest / malicious demo scripts |
| `tools/` | offline checks: bit-convention probe, circuit verifier, circuit tamperer, bandwidth meter |

## Build

Requires nix (for the toolchain and OpenSSL) on an x86-64 host.

```sh
nix develop -c ./tools/bootstrap-emp.sh   # once: fetch + build emp into .deps/emp
nix develop -c make                        # build everything
```

## Run

```sh
nix develop -c ./demo/run_demo.sh    # honest: both derive H(I) == reference
nix develop -c ./demo/run_cheat.sh   # malicious garbler: evaluator aborts, no value
```

`run_demo.sh` defaults to `I = ffffffffffff` (StartIndex `2^48−1`, the first
revealed secret: a 48-block chain, ~5.6M gates). Override with env vars, e.g.
`I=1 PORT=12345 nix develop -c ./demo/run_demo.sh`.

To run the parties by hand, **first generate the agreed circuit** for the index
(both parties must load the *same* circuit file for the *same* index — running
`party` on a path that does not exist fails fast with a clear error). Then start
party `1` (ALICE, the listener) and party `2` (BOB) pointed at ALICE's IP:

```sh
# once, on each host (or generate once and copy the file to both):
./.build/gen_circuit ffffffffffff circuit.txt          # I = StartIndex (hex)

# ALICE (listener) and BOB (connects to ALICE's IP):
./.build/party 1 12345 circuit.txt <aliceShareHex>
./.build/party 2 12345 circuit.txt <bobShareHex> <alice_ip>
```

The two share hexes are each 64 hex chars (32 bytes); the seed is their XOR. On
the same machine, BOB connects to `127.0.0.1` (the default if `<alice_ip>` is
omitted).

## Tests

```sh
nix develop -c make test     # reference KATs + plaintext circuit verification
```

`make test` runs, with no network:
- `ref_kat` — the reference vs the five published BOLT-03 generation vectors.
- `verify_circuit` — the generated circuit, plaintext-evaluated against the
  reference across those vectors, popcount 0 and 48, three share splits, and a
  serializer round-trip.

The MPC layer itself is exercised by the demo scripts above.

## Scope and trade-offs

- **2 parties, asymmetric roles** (party 1 = garbler/ALICE, party 2 =
  evaluator/BOB). Not threshold, not post-quantum.
- **The cache optimization is dropped.** A semi-honest implementation can resume
  a derivation from a *secret-shared* intermediate checkpoint; doing that
  maliciously requires carrying **authenticated** shared state across circuits
  (a "stateful authenticated garbling" extension), which is left as future work.
  Each derivation here recomputes from the seed in one circuit
  (`popcount(I) ≤ 48` SHA-256 blocks). Security is preferred over the
  optimization.
- Both parties derive the circuit independently from the agreed `I`, so they
  evaluate byte-identical circuits; a party that garbles a *different function*
  within that structure is caught by authenticated garbling (clean abort), and a
  malformed or differently-sized circuit is caught by the circuit-digest
  handshake (also a clean abort, before any preprocessing).

## Known limitations

- **Connection setup is an unbounded wait.** A party blocks until its peer
  appears: the evaluator in emp's client `while(1){ connect() }` retry loop and
  the garbler in `accept()`, both inside `emp::NetIO`'s constructor. If the peer
  never starts, the party hangs indefinitely. The post-connect read/write
  timeout (`SHACHAIN2PC_TIMEOUT_SECS`, set on the socket *after* construction)
  does **not** cover this phase. A clean bounded fix isn't a local one-liner — it
  needs patching emp's `NetIO` (cap retries / `accept` timeout) or a custom
  `IOChannel` over a pre-connected socket (emp's `NetIO` has no fd-adopting
  constructor) — so it is deferred. The connect retry is partly intentional
  (start-order independence). Operationally: start the garbler (listener) first,
  and/or run the parties under an external timeout/supervisor. Note `party` does
  not validate the role argument, so a value other than `1`/`2` takes the client
  path and can hang here.
