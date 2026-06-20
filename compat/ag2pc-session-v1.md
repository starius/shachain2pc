# AG2PC session compatibility surface

Status: Phase-0 compatibility probe for the current C++ `emp::AG2PCSession`
backend.

This document defines the v1 transition target for the Rust AG2PC port:
wire-compatible interop with the current C++ `party`, plus semantic/differential
checks. It does not require full production transcript byte identity, because the
protocol uses fresh randomized OT/MPC material.

## Scope

The probe binary is `.build/ag2pc_session_probe`, built from
`tools/ag2pc_session_probe.cpp`.

Run a live pair with:

```sh
make test-ag2pc-probe
```

The target backend is the rewritten C++ `emp::AG2PCSession` stack:

- one primary `NetIO`;
- one `NetIO::make_sibling()` channel created by `AG2PCProtocol`;
- SoftSpoken<4> COT sessions;
- one long-lived `TriplePool`;
- authenticated input batching through `process_inputs`;
- half-gate leaky-AND with cyclic-shift bucketing;
- `checkpoint(keep...)` carried authenticated wires;
- `reveal(value, PUBLIC/ALICE/BOB, keep...)`.

## Compatibility Target

The Rust port must match:

- role semantics: party 1 is ALICE/garbler/listener, party 2 is
  BOB/evaluator/connector;
- primary and sibling connection order;
- `ssp = 40` unless both sides deliberately change it together;
- message order and flush boundaries required for liveness;
- encodings of bool vectors, blocks, digests, and reveal payloads;
- typed abort behavior: a failed check returns an error and prints no `RESULT`;
- recipient behavior: PUBLIC reveals to both parties, ALICE/BOB reveals only to
  the requested party.

The Rust port does not need to reproduce randomized production bytes exactly.
For randomized steps, the cross-mode oracle is: the run completes, both sides
observe the same public result, non-recipients observe no value, and tampering
aborts before output.

## Probe Cases

`ag2pc_session_probe` executes these cases under one live session:

1. `session_setup`
   Constructs `AG2PCSession`, which opens the sibling channel and starts the
   SoftSpoken COT sessions.
2. `input_batch_two_bits`
   Authenticates one ALICE bit and one BOB bit in one `input_batch().finish()`.
3. `public_true_reveal`
   Reveals a public constant to PUBLIC.
4. `xor_reveal`
   Reveals `alice_bit XOR bob_bit` to PUBLIC.
5. `and_reveal`
   Reveals `alice_bit AND bob_bit` to PUBLIC.
6. `checkpoint_keep_carry_inputs`
   Flushes and keeps the XOR result plus both original inputs as carried
   authenticated state.
7. `carried_and_reveal`
   Uses the carried XOR in a later AND and reveals it to PUBLIC.
8. `reveal_to_alice`
   Reveals a bit only to ALICE; BOB must receive `null`.
9. `reveal_to_bob`
   Reveals a bit only to BOB; ALICE must receive `null`.

## Probe Output

Each party prints JSONL records with schema
`shachain2pc.ag2pc_probe.v1`. Each record contains:

- `case`, `seq`, and `party`;
- `process_input_calls`;
- cumulative `num_and`;
- per-case and cumulative sent/received byte counters;
- per-case and cumulative communication-round counters;
- per-case and cumulative flush counters;
- primary and sibling Fiat-Shamir transcript digests;
- a case-specific `result` field where the case reveals a value.

The counter/digest fields are a debugging aid for Rust/C++ interop. They are not
a deterministic transcript fixture under production randomness.

## Required Follow-Up Probes

Before replacing the Rust backend, add or extend probes for:

- fixed-byte helper encodings where the bytes are deterministic;
- SoftSpoken setup/extension invariants in both role directions;
- a multi-AND circuit;
- checkpoint then second circuit with wider values;
- tampered garbling/reveal aborts.

Those probes should reuse this document as the compatibility surface instead of
reviving the old EMP `C2PC`/IKNP/Fpre fixtures as active targets.
