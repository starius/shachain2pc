# shachain2pc-mpc-runner

## Role

This crate adapts typed MPC frames to concrete async transports. It is the thin
runner layer between pure protocol handlers and byte streams.

## Place In The Stack

`shachain2pc-mpc-runner` uses `shachain2pc-mpc-core` for the typed handshake
and `shachain2pc-mpc-types` for frame encoding. The daemon uses it to run the
JobStream handshake before handing the same byte streams to AG2PC.

## Public Interface

- `MpcTransport`: async send/receive/flush interface for typed `MpcFrame`s.
- `MpcTransportSet`: exposes independent main and sibling transports.
- `TransportPair`: simple main/sibling transport holder.
- `ByteFrameTransport`: length-prefixed `MpcFrame` transport over `ByteIo`.
- `run_session_handshake`: validates both peers agree on session parameters.
- `memory_transport_pair`: in-process transport for tests.

## Internal Layout

- `src/lib.rs`: transport traits, adapters, runner handshake, errors.
- `src/tests.rs`: in-memory transport, ByteFrameTransport, and handshake tests.

## Invariants

- Main and sibling transports are independent to avoid AG2PC deadlocks.
- Session handshakes bind public parameters before raw AG2PC bytes run.
- Transport errors should fail closed; callers decide how to tear down jobs.

