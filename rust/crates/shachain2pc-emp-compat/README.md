# shachain2pc-emp-compat

## Role

This crate owns the EMP-compatible AG2PC implementation. It keeps the legacy
byte behavior needed by the standalone party path while delegating pure crypto
state transitions to `shachain2pc-mpc-core`.

## Place In The Stack

`shachain2pc-emp-compat` sits above `shachain2pc-mpc-core` and
`shachain2pc-emp-wire`. It turns circuits into compact AG2PC programs and runs
them over any `TranscriptIo` transport, including EMP/TCP and daemon gRPC
JobStream byte adapters.

## Public Interface

- `Ag2pcSession`: setup, input authentication, program execution, reveal, end.
- `Ag2pcProgram`: compact direct-program representation built from circuits.
- `Ag2pcSecureWires`: authenticated wires with optional session-local labels.
- `SoftSpoken4` and `Ag2pcTriplePool`: EMP-compatible wrappers around core
  state machines.
- `normalize_ag2pc_delta` and share-relation helpers.

## Internal Layout

- `src/lib.rs`: public error type, constants, imports, and section includes.
- `src/base_ot.rs`: EMP random oracle, P-256, and base OT helpers.
- `src/softspoken.rs`: async SoftSpoken wrapper over pure state.
- `src/wires.rs`: authenticated wire containers and protocol shell types.
- `src/program.rs`: AG2PC direct-program representation and builders.
- `src/session.rs`: session execution, input opening, and garbling paths.
- `src/triple_pool.rs`: triple-pool I/O, checks, delta helpers, utilities.
- `src/tests.rs`: compatibility fixtures, tamper tests, and roundtrips.

## Invariants

- The C++/EMP-compatible byte path must remain compatible where tested.
- Labels are session-local one-time material; do not persist or reuse them.
- Authenticated wire MAC material is what makes cached reveals correct-or-abort.
- Large buffers are on the hot path; avoid clones unless they are intentional.

