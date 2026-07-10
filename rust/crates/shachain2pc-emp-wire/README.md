# shachain2pc-emp-wire

## Role

This crate owns EMP-compatible byte transport primitives and transcript I/O.
It is deliberately low level: it moves bytes and blocks, but does not know the
AG2PC protocol state machine.

## Place In The Stack

`shachain2pc-emp-wire` is used by both legacy EMP/TCP paths and newer gRPC
JobStream adapters. Higher layers implement protocol logic on top of the
`ByteIo` and `TranscriptIo` traits.

## Public Interface

- `Block`: the 128-bit block type used throughout the MPC implementation.
- `ByteIo`: framed byte/block send and receive operations.
- `TranscriptIo`: `ByteIo` plus transcript hashing and Fiat-Shamir support.
- `EmpStream`: EMP/TCP-compatible stream implementation.
- `Ag2pcStreams`: the main/sibling stream pair used by AG2PC.
- `ChannelByteStream`: mpsc-backed adapter used by daemon gRPC JobStream.

## Internal Layout

- `src/lib.rs`: block operations, byte framing, transcript hashing, streams,
  and adapters.
- `src/tests.rs`: EMP fixture checks and in-memory transport tests.

## Invariants

- EMP/TCP byte compatibility is part of the external contract.
- Main and sibling channels must remain independently drivable; multiplexing
  them onto one blocking ordered stream can deadlock AG2PC.
- Transcript digest ordering is security relevant and covered by tests.

