# shachain2pc-party

## Role

This crate provides the standalone `party` binary path and reusable job helpers
for seed-root, one-H, precompute, and reveal operations. It is the compatibility
bridge between command-line experiments and the daemon.

## Place In The Stack

`shachain2pc-party` composes circuits, EMP-compatible AG2PC sessions, and EMP
streams into complete shachain derivation jobs. The daemon calls selected
helpers from this crate while keeping service orchestration elsewhere.

## Public Interface

- `run_party` and `parse_args`: standalone CLI entry points.
- `run_seed_root_job`, `run_one_hash_job`, and `run_precompute_path_job`.
- `PrecomputeSession`: live per-channel incremental precompute session.
- `reveal_node_local_share` and `reveal_node_from_peer_share`: fast MAC-open
  reveal helpers.
- `MpcTcpEndpoint`, `IndexSpec`, `PartyOutput`, and `PartyError`.

## Internal Layout

- `src/lib.rs`: public types, standalone entry point, and section includes.
- `src/jobs.rs`: embeddable seed, one-H, precompute, and reveal jobs.
- `src/standalone_modes.rs`: batch, tree, cache, and chunked CLI modes.
- `src/helpers.rs`: shared helpers, CLI parsing, and EMP stream setup.
- `src/main.rs`: thin `party` binary wrapper.
- `src/tests.rs`: CLI parsing, compatibility, cache, and reference tests.

## Invariants

- The standalone path remains the byte-compatibility oracle for C++/EMP tests.
- Live precompute sessions may reuse in-memory labels only within one session.
- Restart persistence belongs to the daemon; this crate should not persist
  session-local one-time material.
- Reveals must preserve expected-index and seed-reveal safety checks.

