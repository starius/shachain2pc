# shachain2pc-daemon

## Role

This crate implements the daemon, local CLI API, peer gRPC API, encrypted
persistence, background precompute scheduler, and integration-test harness for
the two-party shachain service.

## Place In The Stack

`shachain2pc-daemon` is the top application layer. It derives per-channel shares
and fixed per-channel Delta values from the master secret, stores recovery
state, coordinates peers over gRPC, and delegates MPC execution to
`shachain2pc-party`, `shachain2pc-mpc-runner`, and the lower protocol crates.

## Public Interface

- `run_daemon`: starts the control and peer gRPC services.
- `init_daemon_state`: builds an in-process daemon state for tests/tools.
- `DaemonConfig`, `PeerTlsConfig`, `ControlFile`, and `DaemonHandle`.
- `channel_seed_share`, `channel_delta`, and `reference_for_channel`.
- `parse_master_secret_hex`, `parse_role`, `parse_addr`, and `read_control_file`.

The binaries are:

- `shachain-daemon`: daemon process.
- `shachain-cli`: local control client.

## Internal Layout

- `proto/daemon.proto`: control and peer gRPC API.
- `build.rs`: protobuf generation.
- `src/lib.rs`: public types, daemon startup, state construction, includes.
- `src/db.rs`: encrypted redb persistence, legacy migration, writer task.
- `src/services.rs`: gRPC control/peer service adapters and JobStream glue.
- `src/precompute_driver.rs`: live per-channel precompute session commands.
- `src/state.rs`: daemon state machine, scheduler, reveal, reconciliation.
- `src/helpers.rs`: bindings, TLS, derivation, parsing, small helpers.
- `src/bin/`: daemon and CLI binaries.
- `tests/daemon_pair.rs`: end-to-end daemon-pair tests and benchmarks.

## Invariants

- The DB is a recovery cache, not the reveal authority. The caller supplies
  `expected_next_index`.
- Persist only channel config, revealed compact shachain secrets, and target
  frontier leaves. Do not persist trunk nodes or session labels.
- Peer mTLS, cookie auth, security parameter binding, and MAC checks are
  security boundaries; failures must fail closed.
- Disabled channels must drop live sessions and in-memory cache state.

