# Daemon Integration Test Plan

This document plans the next daemon integration-test expansion. The tests are
meant to exercise the daemon as a two-party service: real daemon processes, real
CLI control, real encrypted DBs, real peer gRPC/JobStream, and the existing
AG2PC implementation.

The plan intentionally does not introduce new protocol features. Where a test
needs malicious behavior, use either a direct gRPC client that sends invalid
public control frames or a narrow test-only fault hook that corrupts one byte at
a named boundary. The production daemon must not grow a general "malicious
mode."

## Existing Coverage

The current `daemon_pair` integration suite already covers:

- seed reveal across restart and local known-secret cache;
- nonzero reveal through the full MPC fallback;
- precomputed frontier reveal after daemon restart;
- target-only durable frontier persistence;
- live in-memory session reuse for adjacent targets (`2 -> 3`);
- peer mTLS JobStream happy path;
- one peer DB loss followed by joint frontier recompute;
- background precompute to the shared target;
- two concurrent channels over JobStream;
- Delta lifetime cap refusal;
- failed security-parameter negotiation monitoring;
- expected-index reveal refusal.

The additions below should preserve that structure and keep tests serialized
with the existing daemon-pair lock/port allocation style.

## Test Harness Additions

Add reusable harness helpers before adding many scenarios:

- `kill_alice`, `kill_bob`, `restart_alice`, `restart_bob`, and
  `restart_both`, preserving the shared temp directory and port assignments.
- `snapshot_db(role, name)` and `restore_db(role, name)` for rollback tests.
- `remove_db(role)` for total local DB loss.
- `wait_daemon_down(role)` and `wait_daemon_ready(role)` to avoid race-prone
  sleeps after kills/restarts.
- `wait_channel_absent_or_contains` for rollback/reconcile assertions.
- `start_mtls_with(mode)` for positive and negative mTLS variants.
- Direct peer-gRPC helper for descriptor-level invalid `JobStream` cases,
  separate from the normal CLI path.
- Test-only daemon fault hooks behind `#[cfg(test)]` or a test-only feature:
  - corrupt next outgoing JobStream payload after the runner handshake;
  - corrupt next persisted frontier record before save;
  - close the process after accepting a JobStream but before committing output.

Fault hooks must be explicit, single-purpose, and disabled in normal builds.
They should produce deterministic aborts and must never emit a `RESULT` or
commit a forged frontier node.

## Restart And Liveness Tests

### `daemon_pair_peer_restart_reconnects_shared_channel`

Goal: prove the long-lived tonic `Channel` reconnects after a peer process
bounce.

Scenario:

1. Start both daemons and enable a channel.
2. Precompute `I=1` from Alice.
3. Kill and restart Bob only.
4. Without restarting Alice, precompute `I=2` from Alice.
5. Reveal both `I=1` and `I=2` from cache/reference as appropriate.

Expected:

- Alice's existing shared `Channel` reconnects on the next RPC.
- The old live precompute session is not reused after Bob restarts.
- The next precompute succeeds through a fresh session.
- No stale active job remains on either side.

### `daemon_pair_alice_restart_rewarms_without_label_persistence`

Goal: prove local restart discards labels/session state but keeps revealable
target leaves.

Scenario:

1. Precompute `I=2`.
2. Restart Alice only.
3. Reveal `I=2` from the persisted target leaf.
4. Precompute `I=3`.

Expected:

- `I=2` reveal returns `CACHE true`.
- `I=3` succeeds, but it is a fresh-session re-warm rather than a one-H
  extension from persisted `I=2`.
- No trunk/intermediate labels appear in the DB.

### `daemon_pair_bob_restart_rewarms_without_label_persistence`

Same as the Alice restart test, with Bob restarted and Alice kept alive. This
exercises peer-side incoming session cleanup.

### `daemon_pair_both_restart_reveals_common_frontier`

Goal: prove both-daemon restart keeps durable target leaves and never resumes
one-time session material.

Scenario:

1. Precompute `I=1` and `I=3`.
2. Restart both daemons.
3. Reveal `I=1` and `I=3` from cache.
4. Precompute `I=7`.

Expected:

- Reveals use persisted target leaves.
- Further precompute starts a new session with fresh randomness.
- Results match `reference_for_channel`.

### `daemon_pair_kill_initiator_mid_precompute_cleans_peer`

Goal: kill Alice during an active precompute and prove Bob cleans up.

Implementation note: use a test-only hook to exit Alice after JobStream setup
or after the first AG2PC payload.

Expected:

- Bob eventually has no active jobs.
- No frontier node is committed for the interrupted target.
- Restart Alice and retry; the precompute succeeds.

### `daemon_pair_kill_receiver_mid_precompute_cleans_initiator`

Same as above with Bob killed during an incoming precompute.

Expected:

- Alice returns an error or times out cleanly.
- Alice removes the active job reservation and records the failed attempt.
- Restart Bob and retry; the precompute succeeds.

## DB Rollback And Persistence Tests

### `daemon_pair_peer_db_rollback_drops_asymmetric_leaf`

Goal: cover rollback to a valid older DB, not only deletion.

Scenario:

1. Enable a channel and snapshot Bob DB.
2. Precompute `I=1`.
3. Restore Bob DB snapshot.
4. Precompute `I=1` again.

Expected:

- Alice sees Bob lacks the matching leaf and drops its local half.
- Both parties recompute and end with matching frontier.
- The recompute increments checked-unit accounting.

### `daemon_pair_local_db_rollback_drops_asymmetric_leaf`

Same as peer rollback, but rollback Alice while Bob keeps the newer leaf.

Expected:

- Reconciliation converges on the common subset.
- No reveal can produce a wrong secret from mismatched halves.

### `daemon_pair_revealed_secret_compaction_survives_restart`

Goal: prove durable revealed secrets use normal shachain compaction and survive
restart.

Scenario:

1. Reveal a later index that can derive an older index.
2. Request the older derivable index with a nonmatching expected index.
3. Restart both daemons and repeat the older request.

Expected:

- The older request is served locally from the durable known-secret store before
  and after restart.
- The DB does not accumulate redundant known secrets when a later secret covers
  an older one.

### `daemon_pair_rollback_loses_known_secret_and_expected_index_still_blocks`

Goal: prove DB rollback cannot make the daemon an authority for the channel
reveal frontier.

Scenario:

1. Snapshot DBs.
2. Reveal a later secret and verify an older secret is locally derivable.
3. Restore one daemon's old DB.
4. Ask that daemon for the older secret with an expected index that only would
   be allowed if the later secret were still known.

Expected:

- The daemon refuses because local derivation is gone and the request does not
  match `expected_next_index`.
- No MPC starts and no `RESULT` is printed.

### `daemon_pair_corrupt_encrypted_db_refuses_start`

Goal: prove encrypted DB AEAD failure is fail-closed.

Scenario:

1. Start, enable a channel, and stop.
2. Flip a byte in one DB file.
3. Try to restart that daemon.

Expected:

- The daemon exits with an encrypted-DB error.
- It does not write a control file or accept local/peer requests.

## Session Cache And Scheduler Tests

### `daemon_pair_live_cache_replaces_one_node_per_layer`

Goal: black-box the one-node-per-layer in-memory cache rule.

Scenario:

1. Precompute a target whose terminal layer is later replaced by another target
   on the same layer.
2. Request a target that would have been one H from the older same-layer node
   but is not derivable from the replacement.

Expected:

- The checked-unit count shows the older same-layer node was not retained.
- Reveals still match the reference.

### `daemon_pair_disable_channel_stops_background_fill`

Goal: disabling a channel should prevent new background work and clean active
background state.

Scenario:

1. Configure nonzero background precompute.
2. Enable a channel and wait for at least one target.
3. Disable the channel.
4. Wait and verify no additional frontier growth.
5. Re-enable and verify precompute resumes.

Expected:

- Disabled channel does not start new jobs.
- Re-enabled channel resumes from the durable common subset and live-session
  state is re-created if needed.

### `daemon_pair_worker_budget_limits_live_sessions`

Goal: cap active live sessions by the shared worker budget.

Scenario:

1. Set workers to `1`.
2. Enable two channels.
3. Start two manual precomputes concurrently.

Expected:

- One precompute succeeds and one is refused or waits according to the chosen
  scheduler policy.
- The peer also enforces its own worker budget.
- No over-cap active jobs appear in `jobs`.

### `daemon_pair_peer_budget_shrink_stops_new_background_work`

Goal: min(local, peer) budget is enforced dynamically.

Scenario:

1. Start with precompute target `2` on both peers.
2. Let one target fill.
3. Set peer precompute target to `0`.
4. Verify no further background targets are scheduled.

Expected:

- Already committed leaves remain.
- New background work stops until both peers advertise a positive target.

## Peer TLS And Auth Tests

### `daemon_pair_mtls_rejects_wrong_domain`

Goal: hostname validation is active.

Scenario:

1. Start peer servers with a certificate valid for `localhost`.
2. Configure one client with `--peer-tls-domain wrong.local`.
3. Attempt peer frontier or precompute.

Expected:

- RPC fails during TLS verification.
- No active job or frontier node is committed.

### `daemon_pair_mtls_rejects_untrusted_client_ca`

Goal: mutual client authentication is active, not just server TLS.

Scenario:

1. Start Alice and Bob with different CA roots or a bad client identity on one
   side.
2. Attempt precompute.

Expected:

- The server rejects the client certificate.
- The CLI reports failure and no frontier changes.

### `daemon_pair_mtls_rejects_plaintext_peer`

Goal: a TLS peer server must not accept plaintext JobStream/control traffic.

Scenario:

1. Start one daemon with peer mTLS.
2. Configure the other side with `http://...` and no TLS.
3. Attempt peer frontier or precompute.

Expected:

- Connection fails.
- No work is committed.

### `daemon_pair_local_cookie_rejects_bad_cli`

Goal: local loopback control auth remains enforced.

Scenario:

1. Start a daemon normally.
2. Invoke the control API with a wrong cookie.

Expected:

- The request is unauthenticated.
- Reveal/precompute/config actions are not executed.

## Malicious Peer And Tamper Tests

These tests model malicious behavior at daemon boundaries. They are not a
cryptographic proof; the AG2PC core already has lower-level tamper tests. The
daemon-level assertion is operational: abort, no wrong output, no forged
frontier commit, and cleanup/retry works.

### `daemon_pair_rejects_jobstream_security_param_tamper`

Goal: receiver rejects public descriptor tampering.

Scenario:

1. Use a direct peer-gRPC helper to open a JobStream with a valid channel but a
   weaker `ssp_target`, wrong Delta cap, wrong effective SSP, or wrong digest.

Expected:

- Receiver rejects before AG2PC setup.
- No active job remains and no frontier node is stored.

### `daemon_pair_rejects_jobstream_context_replay`

Goal: frames cannot be replayed across channel/job context.

Scenario:

1. Start a valid JobStream.
2. Send a non-start frame with a different `job_id`, channel index, target, SSP,
   or digest.

Expected:

- The stream is closed/rejected.
- The receiver does not commit output.

### `daemon_pair_rejects_duplicate_or_missing_jobstream_channel`

Goal: the two-stream pairing logic is fail-closed.

Scenario:

1. Send duplicate `main` streams for one job id.
2. Send only `main` and never send `sibling`.
3. Send `sibling` with a mismatched descriptor.

Expected:

- Duplicate and mismatch are rejected immediately.
- Missing sibling does not create an active precompute job and is cleaned up by
  timeout/stale-pending cleanup if that cleanup is implemented.

### `daemon_pair_tampered_precompute_payload_aborts_without_frontier`

Goal: corrupted AG2PC bytes during background precompute fail closed.

Implementation note: use a test-only fault hook that flips one byte on the next
JobStream payload after the runner handshake and before target commit.

Expected:

- The CLI precompute fails.
- Both daemons have no frontier node for the target.
- Failed-attempt monitoring increments where appropriate.
- A later honest retry succeeds and matches the reference.

### `daemon_pair_tampered_reveal_payload_aborts_without_result`

Goal: corrupted reveal/full-derivation bytes fail closed at daemon level.

Implementation note: reuse or expose the existing AG2PC tamper hooks through the
daemon path, or add a test-only EMP/TCP byte-flip proxy around the reveal
transport.

Expected:

- Both CLI reveal processes exit failure or one fails while the other sees
  abort.
- No `RESULT` line is printed.
- No known secret is stored.

### `daemon_pair_tampered_persisted_frontier_aborts_or_recomputes`

Goal: an invalid authenticated node at rest cannot reveal a wrong secret.

Implementation note: because DB records are encrypted, use a test-only helper
that loads a valid DB, corrupts one serialized MAC/key byte before re-encrypting,
and then restarts the daemon.

Expected:

- Reconcile drops mismatched peer-visible bindings if public binding changes; or
  reveal reaches MAC verification and aborts if the binding still matches.
- No wrong `RESULT` is printed.
- Honest recompute repairs the node.

### `daemon_pair_malicious_peer_frontier_binding_is_dropped`

Goal: bogus peer frontier data cannot make a local node trusted.

Scenario:

1. Use a direct fake peer service or test hook to return a frontier node with
   the right mask and wrong public binding.
2. Run reconcile/precompute.

Expected:

- Local node is dropped rather than used.
- Subsequent precompute recomputes jointly with a real peer.

## Suggested Implementation Order

1. Add harness helpers for per-side restart, DB snapshots, and direct peer gRPC.
2. Land restart/reconnect tests:
   - `daemon_pair_peer_restart_reconnects_shared_channel`;
   - `daemon_pair_alice_restart_rewarms_without_label_persistence`;
   - `daemon_pair_bob_restart_rewarms_without_label_persistence`.
3. Land DB rollback/compaction tests.
4. Land mTLS negative tests.
5. Land scheduler/session lifecycle tests.
6. Add test-only fault hooks and land malicious/tamper tests.

This order keeps the first several commits free of fault-injection machinery and
lets reviewers validate ordinary restart/rollback behavior before adversarial
tests add more harness complexity.

## Done Criteria

- Each new integration test starts real daemon processes unless it is explicitly
  a direct peer-gRPC negative test.
- Every abort-path test asserts no `RESULT`, no forged frontier node, and no
  stale active job.
- Restart/rollback tests assert both final correctness and the intended cache
  behavior (`CACHE true`, checked-unit count, or re-warm count).
- mTLS negative tests prove failure before MPC bytes are exchanged.
- The full daemon integration suite remains serialized and deterministic enough
  for CI.
