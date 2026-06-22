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

## Integration Coverage

The daemon integration test starts two real daemon processes and drives both
with the real CLI. It verifies:

- paired seed reveal with `allow_seed_reveal`;
- encrypted DB persistence across daemon restart;
- nonzero reveal through the full MPC path;
- matching outputs against the reference derivation;
- local cache reuse for already revealed values;
- refusal when `expected_next_index` does not match.

## Current Limitation

Persisted authenticated frontier nodes are implemented as encrypted DB records,
but they are not used for nonzero reveal yet. A direct experiment that computed
the seed root in one session, persisted the authenticated wires, then loaded
them as the parent for a fresh one-H session failed the AG2PC equality check.

This means that "same fixed Delta plus serialized authenticated wires" is not
yet enough to safely resume the one-H frontier across fresh sessions. There is
likely another session-local invariant in the current AG2PC representation, or
the resumed node needs an explicit refresh/translation protocol before it can be
used as a parent for new authenticated computation.

The daemon therefore uses the already verified full derivation path for nonzero
reveals. This keeps the tool correct and fund-safe while preserving the DB
format and API shape needed for the future frontier work. Seed-root persistence
works and is covered by the restart integration test.

Before enabling persistent one-H frontier use, add a dedicated protocol/test
that proves a persisted authenticated node can be consumed by a later job
without equality-check failure and without revealing or re-inputting cleartext
intermediates.

## Security Notes

- The DB stores encrypted daemon state. Future unrevealed cleartext secrets are
  not stored.
- Determinism is Delta-only. OT, garbling, leaky-AND, preprocessing, and per-job
  randomness must stay fresh for every computation.
- The Delta lifetime budget counter is monitoring-only. Safety must come from a
  conservatively sized static cap and matching security parameters on both
  parties.
- The local API currently uses loopback TCP plus a cookie. Peer API TLS/mTLS is
  still a production hardening item from the plan.
- Peer gRPC is not yet the raw MPC transport. The daemon still coordinates jobs
  that use the existing EMP-compatible TCP transport.
