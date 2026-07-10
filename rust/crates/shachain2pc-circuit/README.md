# shachain2pc-circuit

## Role

This crate owns Bristol circuit parsing, plaintext circuit evaluation, and the
reference shachain circuit builders used by the Rust implementation.

## Place In The Stack

`shachain2pc-circuit` sits above `shachain2pc-types` and below the MPC crates.
It builds and checks the circuits that `shachain2pc-emp-compat` turns into
AG2PC programs. It contains no transport or daemon logic.

## Public Interface

- `Circuit`, `Gate`, and `GateType`: the in-memory Bristol circuit model.
- `sha256_compress_gadget()`: parses the embedded SHA-256 compression gadget.
- `build_circuit_for_index`, `build_chunk_circuit`, and `build_tile_circuit`:
  construct shachain derivation circuits.
- `eval_bristol`: plaintext evaluator used by tests and reference checks.
- Digest helpers such as `batch_digest`, `tree_digest`, and `cache_digest`:
  bind both parties to the same circuit shape.

## Internal Layout

- `src/lib.rs`: circuit model, parser, builders, digests, and reference logic.
- `src/tests.rs`: parser, digest, plaintext evaluation, and fixture tests.

## Invariants

- Circuit digests are protocol bindings. Do not change them casually.
- Bit ordering must stay compatible with `Value32` and the C++ fixtures.
- The embedded SHA-256 gadget is read at build time and should not require a
  runtime file dependency.

