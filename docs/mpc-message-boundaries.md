# MPC Message Boundary Inventory

Status: Phase 0 inventory for the pure protocol refactor.

This document records the current Rust AG2PC transport boundaries before moving
protocol logic away from concrete `EmpStream` sockets. It is intentionally
behavior-preserving: the old C++-compatible byte order remains the reference for
the `EmpCompat` codec.

## Logical Channels

Current AG2PC uses two full-duplex logical channels:

- `main`;
- `sibling`.

They are not merely tags on one sequential stream. The current implementation
uses both channels concurrently in multiple places:

- `Ag2pcProtocol::process_inputs` uses `tokio::try_join!` to send the local
  input-open message on one channel while receiving the peer input-open message
  on the other. Alice sends on `main` and receives on `sibling`; Bob mirrors
  that.
- `Ag2pcTriplePool::draw` and `flush_cot_check` use paired SoftSpoken/COT
  operations on `abit1` and `abit2`, mapped across `main` and `sibling`.
- Several helper paths in tests exchange verification bundles on `main` while
  the protocol state has pending consistency data tied to both channels.

Conclusion: the runner API must expose independent logical channels. A naive
single ordered `MpcFrame` stream can deadlock if the receiver waits for one
channel while unread frames for another channel are blocking progress. A single
gRPC stream is acceptable only if it has a background dispatcher and bounded
per-channel queues. The simpler and safer daemon mapping is one gRPC bidi stream
per logical AG2PC channel per job, with a shared job id.

## Stream Open And Digest Gate

| Boundary | Role behavior | Channel | Bytes | Flush | Notes |
| --- | --- | --- | --- | --- | --- |
| `Ag2pcStreams::open` | Alice listens, accepts `main`, then accepts `sibling`; Bob connects `main`, then `sibling` | both | TCP connection setup | n/a | C++ compatibility depends on this order. |
| `open_ag2pc_streams_after_digest` | Alice sends digest first, flushes, then receives; Bob receives then sends and flushes | `main` | 32 bytes each direction | yes | Refuses mismatched job/circuit/security digest before AG2PC setup. |

The digest gate belongs to the runner/job layer, not the cryptographic core. It
is still part of the legacy `party` compatibility transcript.

## CSW Base OT

| Boundary | Sender bytes | Receiver bytes | Flush | State consumed/produced |
| --- | --- | --- | --- | --- |
| `csw_send` / `csw_recv` setup | Sender later sends `Z`, `chi`, `proof`, `c0`, `c1`; receiver first sends seed and one point per choice | Both sides flush after their send batch | yes | Produces base OT seeds for SoftSpoken. |

The P-256 point encoding and block order are C++ compatibility surfaces. Keep
them in `EmpCompat` fixtures.

## SoftSpoken

| Boundary | Channel | Bytes | Flush | Notes |
| --- | --- | --- | --- | --- |
| `SoftSpoken4::begin` | whichever logical channel owns that instance | base-OT transcript, once | yes through helpers | Initializes sender/receiver leaves. |
| `SoftSpoken4::next_n` | per instance channel | batched COT chunks | yes through `ag2pc_next_n_flush` | Length is caller-controlled. |
| `SoftSpoken4::end` | per instance channel | final consistency/check blocks if needed | yes | Ends/checks the COT stream. |

The AG2PC triple pool keeps two SoftSpoken instances (`abit1`, `abit2`) and maps
them to opposite logical channels depending on role and phase.

## AG2PC Setup And Triple Pool

| Boundary | Function | Channel use | State produced |
| --- | --- | --- | --- |
| session setup | `Ag2pcProtocol::setup_with_delta` | `main` and `sibling` | global Delta, triple pool, transcript digests |
| draw triples | `Ag2pcTriplePool::draw` | paired operations across both channels | authenticated shares for `rep_a`, `rep_b`, `sigma` |
| COT flush | `Ag2pcTriplePool::flush_cot_check` | paired operations across both channels | abort-or-checked COT state |

This phase is one of the reasons an `MpcTransportSet` is the safer runner
abstraction than a single blocking stream.

## Input Authentication

| Boundary | Role behavior | Channel | Bytes | Flush |
| --- | --- | --- | --- | --- |
| Alice label transfer | Alice sends evaluator labels, Bob receives | `main` | `n_total` blocks | yes |
| Owner local mask open | Owner sends local mask/open digest | `main` or `sibling` depending on role | share bytes, digest, optional packed x bits | yes |
| Peer local mask receive | Peer receives mask/open digest | opposite logical channel | same as above | no explicit send |

`process_inputs` intentionally sends on one channel and receives on the other
with `try_join!`. This must remain non-blocking in any gRPC mapping.

## Program Execution

| Boundary | Role | Channel | Bytes | Flush | Notes |
| --- | --- | --- | --- | --- | --- |
| garbled chunk send | Alice | `main` | `2 * n` blocks + `n` bytes | yes per chunk | Chunk size currently `AG2PC_GARBLE_CHUNK_ANDS`. |
| garbled chunk receive | Bob | `main` | same | paired with compute | no send |
| lambda-and send | Bob | `main` | packed bool vector | yes | Sent after Bob evaluates AND gates. |
| lambda-and receive | Alice | `main` | packed bool vector | no send |
| gamma digest send | Alice | `main` | 32 bytes | yes | Alice sends after receiving lambda-and. |
| gamma digest receive | Bob | `main` | 32 bytes | no send | Mismatch aborts. |

Program execution uses only `main` for garbling/evaluation bytes, but its seed is
derived from both `main` and `sibling` transcript digests.

## Reveal / Decode

| Boundary | Recipient | Channel | Bytes | Flush | Notes |
| --- | --- | --- | --- | --- | --- |
| public reveal share | both | `main` | share bytes + digest | yes | Each party sends then receives, role ordered internally. |
| private reveal | Alice or Bob only | `main` | same shape, recipient-specific output | yes | Non-recipient should not learn opened bits. |

Reveal must flush pending COT consistency checks before returning output. Abort
is terminal and must not produce `RESULT`.

## Compatibility Notes

- `EmpCompat` must preserve the existing byte order, flush points, bool packing,
  block order, and P-256 point encodings.
- `Proto`/gRPC can use typed frames, but it must preserve protocol dependency
  order and independent progress of `main` and `sibling`.
- Large payloads should remain contiguous buffers. Do not split garbled tables
  or COT chunks into per-gate/per-bit protobuf fields.
- Message/frame sequence numbers belong to the runner/transport layer and must
  reject replay/gaps before passing messages to `mpc-core`.

## Runner Mapping Decision

Use an `MpcTransportSet` in the runner:

```text
main:    ByteIo
sibling: ByteIo
```

The legacy `party` maps this to two EMP-compatible TCP streams exactly as today.
The daemon JobStream mapping should use either:

- two gRPC bidi streams per job, one for `main` and one for `sibling`; or
- one gRPC bidi stream plus a background dispatcher that demultiplexes frames
  into per-channel queues.

Default decision for implementation: start with two gRPC bidi streams per job.
It is simpler to reason about, preserves independent progress, and avoids
head-of-line mistakes. It still uses one peer gRPC service and one job id; HTTP/2
multiplexes the underlying connection.
