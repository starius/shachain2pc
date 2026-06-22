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
  - encrypted JSON state using a key derived from the daemon master secret;
  - deterministic per-channel seed shares and fixed per-channel Delta;
  - enable/disable, status/config, list, and reveal commands;
  - mandatory `expected_next_index` gating for non-local reveals;
  - `I=0` seed reveal refusal unless `allow_seed_reveal` is requested;
  - persisted revealed shachain leaves and local derivation from later leaves.
  - explicit path precompute for authenticated frontier nodes.

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

## Frontier State

Persisted authenticated frontier nodes contain only `lambda` and the IT-MAC
`mac/key` bundles. Labels are deliberately not serialized because garbled labels
are session-local randomness.

Path precompute opens one AG2PC session, authenticates the seed, computes the
requested shachain path inside that same session, strips labels from each
durable node, and stores the authenticated nodes encrypted in the DB. A later
daemon process can reveal an exact persisted node because public reveal checks
only the MAC/lambda authenticated value and does not need session-local labels.

Precompute reserves checked-unit budget before starting MPC. A request that
would exceed the configured fixed-Delta lifetime cap is refused before the
precompute job is opened, and a repeated precompute for an already stored exact
node is a no-op.

If an exact persisted node is unavailable, nonzero reveal still falls back to
the already verified full derivation path. This keeps the tool correct and
fund-safe while the background scheduler is not implemented.

## Remaining Limitation

A direct experiment that computed the seed root in one session, persisted the
authenticated wires, then loaded them as the parent for a fresh one-H session
failed the AG2PC equality check. This is expected: the persisted node has a
Delta-bound MAC representation but no fresh-session garbled labels.

Therefore persisted nodes are revealable after restart, but they are not yet
usable as parents for further H applications after restart. Extending the
frontier after a restart must re-warm from the seed root inside a new live
session, or use a future import/re-label protocol that assigns fresh labels
while binding them to the carried MAC without revealing the cleartext
intermediate.

Before enabling restart-resumed frontier extension, add a dedicated
protocol/test that proves a persisted authenticated node can be consumed by a
later job without equality-check failure and without revealing or re-inputting
cleartext intermediates.

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
- The local API currently uses loopback TCP plus a cookie. Peer API TLS/mTLS is
  still a production hardening item from the plan.
- Peer gRPC is not yet the raw MPC transport. The daemon still coordinates jobs
  that use the existing EMP-compatible TCP transport.
