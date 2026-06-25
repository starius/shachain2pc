# Daemon Implementation Report

This report records the implementation state of the daemon and CLI work.

## Implemented

- `shachain2pc-party` is split into a reusable library plus the original
  `party` binary wrapper.
- The AG2PC stack can initialize with a caller-provided, normalized Delta.
- The party library exposes embeddable helpers for seed-root authentication,
  one-H jobs, public reveal of authenticated nodes, and full derivation.
- `shachain2pc-daemon` provides:
  - a local gRPC control API and `shachain-cli`;
  - a peer gRPC API for hello/config/frontier discovery;
  - cookie-authenticated local control over loopback TCP;
  - encrypted redb persistence using subkeys derived from the daemon master
    secret;
  - deterministic per-channel seed shares and fixed per-channel Delta;
  - enable/disable, status/config, list, and reveal commands;
  - mandatory `expected_next_index` gating for non-local reveals;
  - `I=0` seed reveal refusal unless `allow_seed_reveal` is requested;
- persisted revealed shachain leaves and local derivation from later leaves.
- explicit and background path precompute for authenticated frontier nodes.
- one shared tonic peer channel, cloned per RPC so control calls and each
  JobStream pair multiplex over one HTTP/2 connection.
- optional peer mTLS for the daemon-to-daemon API. When configured, both the
  peer server and client present the configured identity and validate the peer
  against the configured CA and expected DNS name.
- one live precompute AG2PC session per active channel. Target indices are sent
  as authenticated in-band JobStream commands, so adjacent precomputes reuse the
  labeled in-memory shachain frontier instead of re-authenticating the seed and
  re-deriving shared prefixes while both parties remain up.
- RAM-authoritative persistence: daemon state is reconstructed into memory at
  startup, and later mutations enqueue logical redb deltas through one
  background writer instead of rewriting a full encrypted JSON blob.

## Integration Coverage

The daemon integration test starts two real daemon processes and drives both
with the real CLI. It verifies:

- paired seed reveal with `allow_seed_reveal`;
- encrypted DB persistence across daemon restart;
- nonzero reveal through the full MPC path;
- precompute of a nonzero frontier node, daemon restart, and reveal from the
  persisted authenticated node without storing the clear secret;
- matching outputs against the reference derivation;
- local cache reuse for already revealed values;
- refusal when `expected_next_index` does not match.
- automatic background precompute to the shared local/peer target;
- cap refusal without consuming the monitoring counters;
- failed precompute attempts being recorded for monitoring.
- rollback repair, where one peer loses its DB and a later precompute jointly
  recomputes the missing frontier state.
- target-only precompute persistence for a multi-bit path, proving trunk and
  intermediate authenticated nodes are not written as durable frontier state.
- live-session reuse across adjacent targets (`2` then `3`), proving the second
  target costs one H rather than re-deriving the two-H path.
- peer mTLS JobStream precompute and cached reveal.
- cached reveal rejection for missing local authorization, binding mismatch, and
  tampered peer shares.
- encrypted redb round-trip, wrong-master rejection, tamper rejection, key
  opacity/addressability, and one-time migration from the legacy encrypted JSON
  blob.

## Persistence

The daemon persists state in one redb table with opaque HMAC-SHA256 keys and
AEAD-encrypted values. The HMAC key subkey and value-AEAD subkey are derived
from the daemon master secret with separate HKDF labels. Values use fresh
AES-256-GCM nonces and bind the ciphertext to the opaque stored key as AAD, so
records cannot be relocated between logical keys.

Each encrypted value includes its logical record type, channel index, sub-id,
and payload. Startup verifies the encrypted meta record, scans every value, and
reconstructs the in-memory channel map. Wrong master secrets, value tampering,
or per-record parse failures abort startup instead of silently wiping state.

Writes are logical deltas sent to one background writer. Reveals and precompute
enqueue eventual-durability batches; channel enable/disable requests use an
immediate flush because they are rare registry changes. The writer also issues
a periodic immediate checkpoint when eventual writes are dirty, and clean
process shutdown drains and flushes the writer before exit. A power loss may
still lose the latest uncheckpointed cache tail, but redb preserves an older
consistent snapshot, and the daemon can recompute lost cache state through MPC.
The externally supplied `expected_next_index` remains the authority for reveal
safety; the DB is never trusted as the channel-state frontier.

## Frontier State

Persisted authenticated frontier nodes contain only `lambda` and the IT-MAC
`mac/key` bundles. Labels are deliberately not serialized because garbled labels
are session-local randomness.

Path precompute opens or reuses one live AG2PC session for the channel,
authenticates the seed once for that session, computes requested targets inside
that same session, strips labels from the exact requested target node, and
stores that authenticated leaf encrypted in the DB.

The live session keeps a compact labeled RAM cache with at most one node per
shachain layer. Those labels and intermediate trunk nodes are not durable
frontier state because they are session-local randomness and are not reusable
after restart. The DB stores only exact requested leaves that can be revealed
later.

The daemon shares one parsed SHA-256 compression `Circuit` across all live
sessions with `Arc<Circuit>`. Live-session cache retention follows the
shachain future-storage closure and prunes obsolete one-shot intermediates
after each target. Successful precompute also trims unused SoftSpoken leftover
COT chunks while keeping setup state, PPRF leaves, authenticated labels, and
the live frontier intact.

A later daemon process can reveal an exact persisted node because public reveal
checks only the MAC/lambda authenticated value and does not need session-local
labels.

Cached daemon reveal for nonzero persisted leaves now uses a peer gRPC
`RevealCached` RPC. Alice sends her local MAC-open share; Bob's peer handler
waits for Bob's matching local reveal authorization, verifies Alice's share
against Bob's persisted `lambda + wire_bundle` material and fixed channel
Delta, returns Bob's MAC-open share, and both daemons store the same opened
secret. This keeps the two-sided reveal rendezvous and makes both parties
verify the persisted authenticated material. The explicit `I=0` seed-reveal
path remains on the legacy one-shot reveal transport.

After a secret is revealed and inserted into the durable shachain store, the
exact persisted frontier node for that index is removed. The authenticated node
is no longer needed once its clear secret is known, and dropping it keeps the DB
and future encrypted rewrites compact.

Precompute reserves checked-unit budget before starting MPC. A request that
would exceed the configured fixed-Delta lifetime cap is refused before the
precompute job is opened, and a repeated precompute for an already stored exact
node is a no-op.

The daemon also records attempted checked units and failed precompute jobs as
monitoring data. These counters are not safety-critical, because the DB can be
deleted or rolled back, but they make crash loops and repeated failed
precompute attempts visible.

If an exact persisted node is unavailable, nonzero reveal still falls back to
the already verified full derivation path. This keeps the tool correct and
fund-safe. The current fallback uses a fresh one-shot AG2PC Delta, not the fixed
per-channel Delta, so it does not consume the fixed-Delta lifetime cap. If the
fallback is later changed to reuse the fixed channel Delta, it must reserve and
account for the same checked-unit budget as precompute.

## Restart Boundary

A direct experiment that computed the seed root in one session, persisted the
authenticated wires, then loaded them as the parent for a fresh one-H session
failed the AG2PC equality check. This is expected: the persisted node has a
Delta-bound MAC representation but no fresh-session garbled labels.

Therefore persisted nodes are revealable after restart, but they are not used as
parents for further H applications after restart. Extending the frontier after a
restart starts a fresh live session and re-warms from the seed. This preserves
fresh OT, garbling, leaky-AND, preprocessing, and label randomness and avoids
the import/re-label protocol on the daemon's critical path.

A future import/re-label protocol could avoid restart re-warm by assigning
fresh labels to a persisted authenticated value while binding them to the
carried MAC without revealing the cleartext intermediate. That remains a
separate cryptographic optimization that needs human MPC review before
implementation.

Reconciliation uses the common subset of peer-visible frontier nodes. A local
node whose peer-visible binding is absent or different on the peer is dropped
before a new precompute job starts, so asymmetric frontier halves are regenerated
jointly. The reveal MAC check remains the final correct-or-abort backstop if a
mismatched authenticated value ever reaches reveal.

## Security Notes

- The DB stores encrypted daemon state. Future unrevealed cleartext secrets are
  not stored.
- Determinism is Delta-only. OT, garbling, leaky-AND, preprocessing, and per-job
  randomness must stay fresh for every computation.
- The Delta lifetime budget counter is monitoring-only. Safety must come from a
  conservatively sized static cap and matching security parameters on both
  parties. The daemon enforces the configured cap for precompute requests, but
  the cap itself must still be chosen conservatively because DB rollback can
  erase the local monitor.
- Background precompute runs over peer gRPC `JobStream`. Each MPC job uses two
  bidirectional streams, one for AG2PC `main` and one for `sibling`, so the two
  logical channels can make independent progress without raw worker ports.
- JobStream frames bind the channel, target index, digest, `ssp_target`, and
  Delta lifetime cap. Receivers reject descriptor or security-parameter
  mismatches and enforce their own worker budget before accepting incoming work.
- Before AG2PC bytes are exchanged, daemon precompute runs the shared
  `mpc-runner` session handshake over a length-prefixed typed frame on the
  `main` JobStream. This binds the effective SSP, circuit/job digest, and
  immutable job context at the runner layer, then returns the same byte streams
  to the existing AG2PC implementation.
- The daemon no longer uses `mpc_port + 1 + n` worker ports. The configured
  `mpc_port` remains for the explicit seed reveal path, full-derivation
  fallback, and the legacy C++-compatible `party` transport.
- The local API currently uses loopback TCP plus a cookie. Peer API mTLS is
  available for daemon-to-daemon gRPC and is covered by integration tests.
