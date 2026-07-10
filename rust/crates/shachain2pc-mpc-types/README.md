# shachain2pc-mpc-types

## Role

This crate owns typed MPC frame definitions and their canonical protobuf
encoding. It is the wire-message type layer, not a transport or protocol
runner.

## Place In The Stack

`shachain2pc-mpc-types` sits between pure protocol handlers and transports.
`shachain2pc-mpc-core` creates and validates these messages, while
`shachain2pc-mpc-runner` sends them over a concrete transport.

## Public Interface

- `MpcFrame`: canonical typed frame with job id, role, logical channel,
  sequence, kind, payload, and flags.
- `SessionStart` and `SessionStartAck`: typed session handshake messages.
- `LogicalChannel`: `Main` and `Sibling`.
- `MessageKind`: mandatory and optional message kinds.
- `PROTOCOL_VERSION`: frame encoding version.

## Internal Layout

- `proto/mpc.proto`: protobuf schema.
- `build.rs`: generates Rust protobuf bindings.
- `src/lib.rs`: safe wrappers, validation, canonical encode/decode.
- `src/tests.rs`: canonical encoding and malformed-frame tests.

## Invariants

- Encoding is canonical: decoding then re-encoding must reproduce the input.
- Unknown mandatory message kinds must fail closed.
- Optional unknown kinds must be explicitly flagged.
- Payloads are zeroized on frame drop.

