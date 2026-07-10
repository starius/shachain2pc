# shachain2pc-mpc-core

## Role

This crate contains pure protocol kernels and state machines. "Pure" here
means no sockets, no async transport, and no daemon state: callers pass state
and messages in, and receive updated state or errors back.

## Place In The Stack

`shachain2pc-mpc-core` sits below `shachain2pc-emp-compat` and
`shachain2pc-mpc-runner`. It owns reusable crypto/state-machine logic that must
not be tied to EMP/TCP, gRPC, or any runner implementation.

## Public Interface

- `ChannelFlow`: typed frame sequencing and session-handshake state.
- `SessionParams` plus `send_session_start`,
  `receive_session_start_and_ack`, and `receive_session_start_ack`.
- `AShareBundle`, `Ag2pcTriplePoolState`, and `Ag2pcComputeBuffer`.
- `SoftSpoken4State`, `Prp`, `Prg`, `Mitccrh8`, and helper kernels.
- `reveal_local_share`, `reveal_recipient_bits`, and `finalize_input_open`.

## Internal Layout

- `src/lib.rs`: crate imports, constants, and section includes.
- `src/triple_pool.rs`: pure AG2PC triple-pool state and buffers.
- `src/softspoken.rs`: PRP/PRG, SoftSpoken, CGGM/SFVOLE, MITCCRH, transpose.
- `src/reveal.rs`: authenticated reveal and input-open checks.
- `src/channel_flow.rs`: typed handshake and frame sequencing state.
- `src/tests.rs`: pure state-machine and crypto-check tests.

## Invariants

- This crate must stay transport-independent.
- Frame mismatches and parameter mismatches poison the channel flow.
- All non-Delta MPC randomness is owned by callers/sessions and must not be
  made deterministic across executions.
- Hot kernels are performance sensitive; avoid hidden clones of large buffers.

