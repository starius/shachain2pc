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

## Benchmark Harness

Add a separate daemon benchmark harness, not a default unit test. It should be
easy to run in CI or by hand, but it must not make normal `cargo test`
unpredictable. Prefer one of:

- an ignored integration test:
  `cargo test -p shachain2pc-daemon --test daemon_bench -- --ignored`;
- or a small benchmark binary:
  `cargo run -p shachain2pc-daemon --bin daemon-bench -- ...`.

The benchmark should emit machine-readable JSON plus a concise text summary.
Do not hardcode pass/fail timing thresholds unless an environment variable asks
for regression gating.

### Metrics

Record per daemon and for the pair:

- wall-clock setup time;
- precompute fill time;
- good-case throughput:
  `precompute_wall_seconds / committed_secret_count`;
- reveal latency for cached persisted leaves:
  p50, p95, p99, max, and per-secret average;
- reveal latency after restart, proving durable leaves are still fast;
- fallback reveal latency for one non-precomputed secret;
- peak RSS per node using `/proc/<pid>/status` `VmHWM` where available;
- sampled current RSS over time using `/proc/<pid>/status` `VmRSS`;
- optional process CPU time from `/proc/<pid>/stat`, reported separately from
  wall time;
- number of active jobs, live sessions, frontier nodes, known secrets, and
  checked units at the start and end.

Memory reporting should include:

```text
idle_rss_mb
peak_rss_mb
peak_minus_idle_mb
peak_per_active_worker_mb = (peak - idle) / max(observed_active_jobs, 1)
peak_per_live_channel_mb = (peak - idle) / enabled_channel_count
```

The benchmark must sample both daemons and report the max and sum. A one-node
peak can hide asymmetric behavior, especially during reveal/fallback.

### Main 100-Channel Scenario

`daemon_bench_100_channels_good_case`:

1. Start two real daemons in release mode.
2. Configure peer mTLS.
3. Set a chosen worker count, for example `workers=4`.
4. Enable 100 channels on both peers.
5. Set a precompute target, initially `1` for all channels.
6. Wait for all 100 target leaves to be committed on both peers.
7. Reveal all 100 precomputed secrets sequentially, using the required
   `expected_next_index` value for each channel.
8. Restart both daemons.
9. Reveal the same or locally derivable older secrets again, proving durable
   known-secret/cache behavior.
10. Print JSON and text summary.

Primary headline numbers:

```text
precompute_seconds_per_secret
cached_reveal_latency_p50_ms
cached_reveal_latency_p95_ms
cached_reveal_latency_p99_ms
peak_rss_mb_per_node
peak_rss_mb_pair_sum
```

The first target on each channel pays session setup and seed authentication. A
second benchmark should precompute `I=2` then `I=3` across the same 100
channels to measure warm in-session incremental throughput separately:

```text
cold_precompute_seconds_per_secret = I=2 fill / 100
warm_precompute_seconds_per_secret = I=3 fill / 100
```

The warm number is the one that best reflects the current live-session
optimization.

### Budget Stress Scenarios

`daemon_bench_100_channels_workers_1`:

- Same as the main scenario with `workers=1`.
- Confirms bounded concurrency and establishes the low-memory baseline.

`daemon_bench_100_channels_workers_8`:

- Same as the main scenario with higher workers.
- Shows scaling, RSS growth, and whether gRPC/CPU becomes the bottleneck.

`daemon_bench_1000_channels_idle_floor`:

- Enable 1000 channels.
- Precompute one target per channel with a small worker count.
- Wait until all active jobs are idle and the live per-channel sessions are
  resident.
- Report the idle-session RSS floor:
  `idle_sessions_rss / live_session_count`.
- Disable half the channels and prove live-session count and RSS drop
  accordingly.

This benchmark exposes the scaling floor that a 100-channel run may hide:
enabled live sessions consume RAM independently of active worker count.

`daemon_bench_deep_target_peak`:

- Precompute a StartIndex-region target with many set bits.
- Confirm peak RSS remains approximately one active H worker plus the live
  session cache, because H applications are sequential within the session.
- Report wall time separately from shallow I=2/I=3 cases.

`daemon_bench_100_channels_low_ram_refusal`:

- Configure `max_ram_mb` below the estimated need.
- Expected behavior after RAM admission control lands: precompute queues or
  runs with only the RAM-derived effective worker count.
- Until RAM admission control lands, this test should be marked
  `expected_fail` or documented as pending because `max_ram_bytes` is currently
  not enforced.

If the idle-session-aware formula leaves room for zero workers, the daemon
should still expose one effective worker and print/return a clear warning that
the configured RAM budget is too low and may be exceeded. This preserves
liveness for emergency reveal/precompute paths while making the operator-facing
over-budget condition explicit.

### Reveal Benchmarks

`daemon_bench_reveal_cached_vs_fallback`:

- Precompute and reveal one cached target.
- Reveal one non-precomputed target through the full fallback.
- Report both latencies separately.

Cached reveal should be the operational fast path. Fallback reveal remains
correct but is not the expected steady-state path.

### Output Format

Example JSON shape:

```json
{
  "channels": 100,
  "workers": 4,
  "precompute_target": 1,
  "precompute": {
    "committed": 100,
    "wall_ms": 12345,
    "ms_per_secret": 123.45
  },
  "cached_reveal": {
    "count": 100,
    "p50_ms": 12.3,
    "p95_ms": 18.9,
    "p99_ms": 21.0,
    "max_ms": 22.4
  },
  "rss": {
    "alice_peak_mb": 0,
    "bob_peak_mb": 0,
    "pair_peak_sum_mb": 0
  }
}
```

## Resource Budget Status

Current implementation status:

- Worker budget: implemented for precompute. Outgoing jobs use
  `min(local_workers, peer_workers)`, incoming jobs enforce the receiver's local
  `workers`, and active jobs are tracked so concurrent precompute cannot exceed
  the shared worker limit.
- Delta lifetime checked-unit cap: implemented for precompute reservation and
  accounting.
- Precompute target budget: implemented as `min(local channel target, local
  daemon target, peer daemon target)`.
- CPU budget: approximated only by the `workers` concurrency limit. There is no
  OS-level CPU quota or CPU-time admission control.
- RAM budget: not implemented yet. `max_ram_bytes` is parsed, configurable, and
  reported by status/config, but it is not used to reserve memory or refuse
  precompute. This is the main resource-control gap for 100-channel testing.

Before treating the daemon as resource-safe under large channel counts, RAM
must reduce worker concurrency. The daemon already has a measured or configured
peak RAM cost per active one-H worker, so the first implementation should turn
RAM into a worker cap and then reuse the existing worker-budget machinery.

The model is intentionally idle-session aware:

```text
rss_floor =
    baseline_daemon_rss +
    live_idle_sessions * idle_session_rss_estimate

worker_ram_budget = max(max_ram_bytes - rss_floor, 0)

ram_limited_workers_raw =
    floor(worker_ram_budget / one_h_worker_peak_rss_estimate)

ram_limited_workers = max(ram_limited_workers_raw, 1)

ram_overcommit_warning =
    ram_limited_workers_raw == 0
```

Then compute locally:

```text
effective_local_workers = min(configured_workers, ram_limited_workers)
```

If `ram_overcommit_warning` is true, the daemon should still allow one worker
but must make the over-budget condition visible in logs, status, and benchmark
output. This is a deliberate liveness choice: a badly undersized RAM budget
should not make the daemon permanently unable to run the one job needed to catch
up or serve an urgent operation, but the operator must be told that the host may
exceed `max_ram_bytes`.

The equivalent expanded formula is:

```text
ram_available_for_jobs =
    max_ram_bytes -
    baseline_daemon_rss -
    live_idle_sessions * idle_session_rss_estimate

ram_limited_workers =
    max(floor(max(ram_available_for_jobs, 0) / one_h_worker_peak_rss_estimate), 1)

effective_local_workers = min(configured_workers, ram_limited_workers)
```

Then use:

```text
effective_shared_workers =
    min(local_effective_workers, peer_advertised_effective_workers)
```

Outgoing precompute must start only if `active_jobs < effective_shared_workers`.
Incoming JobStream work must start only if
`active_jobs < effective_local_workers`. If the effective worker count was
forced to one from a raw zero, the job may run but must carry the warning
described above.

The peer config exchange should advertise both the configured `workers` and the
derived `effective_workers`, plus the RAM inputs used to derive it. The
scheduler should make decisions from `effective_workers`; configured `workers`
is retained as the user-requested CPU/concurrency ceiling.

The RAM estimate should reserve for active jobs and account for live sessions:

```text
estimated_job_rss = configured_or_measured_one_h_rss
estimated_idle_session_rss = configured_or_measured_live_session_rss
reserved_ram =
    active_jobs * estimated_job_rss +
    live_idle_sessions * estimated_idle_session_rss
```

The worker cap above is the main admission check. As a defensive backstop, a job
should also warn when:

```text
reserved_ram + estimated_job_rss > local_max_ram
```

That backstop should not refuse the last effective worker unless an explicit
strict mode is later added. The default policy is fail-loud and warn-loud, not
deadlock on an undersized RAM setting.

The first implementation can be conservative and static. Initial values should
come from the measured one-H peak with a safety margin, for example:

```text
one_h_rss_estimate_mb = 32
idle_session_rss_estimate_mb = 1
```

Then the benchmark should replace guesses with observed p95/peak values. The
daemon should expose `effective_workers`, reserved RAM, and observed peak RSS in
`status` or a metrics endpoint before the benchmark becomes a regression gate.

The policy should not normally tear down idle per-channel sessions just to admit
more work. Idle sessions are the optimization that prevents re-deriving the
trunk while both daemons remain alive, and their expected footprint is small.
The RAM cap should primarily reduce active worker count. If a deployment sets
`max_ram_bytes` too low to hold idle sessions plus one worker, the daemon should
surface the condition explicitly instead of silently dropping reusable session
state.

Disabled channels are different: they must consume no live RAM. Disabling a
channel must:

- stop scheduling new work for the channel;
- cancel or finish-and-drop any active precompute job for that channel according
  to the chosen cancellation semantics;
- drop the live `PrecomputeSession` handle and its in-memory one-node-per-layer
  cache;
- remove the channel from live-session accounting immediately;
- keep only durable DB state needed for later re-enable and revealed-secret
  lookup.

Re-enabling a channel creates a fresh live session on demand and re-warms from
the seed as needed. This is safe because no session-local labels or COT state
are persisted.

The strict resource invariant is no disabled-channel live RAM: no active job,
no session task, no gRPC streams, no labeled cache, and no scheduler entry. A
disabled channel may still have encrypted durable state on disk. If future
measurements show that loading disabled `ChannelRecord`s into the daemon's
in-memory DB is material at large scale, split enabled-channel state from
disabled durable records or lazy-load disabled records so disabled channels have
no meaningful per-channel resident footprint.

## Empirical RAM Calibration

The RAM constants must come from real daemon runs, not from library-only party
benchmarks. The daemon has extra fixed costs from tokio, tonic, rustls,
encrypted DB state, local control service, peer service, mTLS certificates, and
the live-session maps. The benchmark harness should provide a repeatable command
that emits the calibrated numbers and the raw samples used to derive them.

Use release builds and the same feature set as production measurements. Sample
both daemon PIDs periodically from `/proc/<pid>/status`:

```text
VmRSS  = current resident set
VmHWM  = high-water resident set
```

Optional profiler runs should use heap tools only as diagnostics, not as the
primary benchmark output. Useful commands include:

```text
/usr/bin/time -v <daemon-or-benchmark-command>
heaptrack <daemon-or-benchmark-command>
valgrind --tool=massif <daemon-or-benchmark-command>
```

Suggested calibration sequence:

1. **Baseline daemon RSS**
   - Start both daemons with mTLS, DB, local control, and peer services
     initialized.
   - Enable no channels.
   - Wait for steady state.
   - Record `baseline_daemon_rss = max(VmRSS_alice, VmRSS_bob)`.

2. **Channel metadata RSS**
   - Enable 100, then 1000 channels, but set precompute target to zero.
   - Record RSS deltas.
   - This catches DB/channel-record overhead that is not part of the live
     precompute session.

3. **Idle live-session RSS**
   - Enable N channels.
   - Precompute one target per channel with a small worker count.
   - Wait until `active_jobs == 0`.
   - Record:

     ```text
     idle_session_rss_estimate =
         (steady_rss_after_precompute -
          baseline_daemon_rss -
          channel_metadata_rss) / live_session_count
     ```

   - Repeat after disabling half the channels. Disabled channels must disappear
     from `live_session_count`, and RSS should drop by roughly the corresponding
     idle-session amount after allocator noise is accounted for.

4. **One-H worker peak RSS**
   - Run with `workers=1`, one enabled channel, and one precompute target that
     performs exactly one H beyond the cached parent.
   - Sample RSS during the job and record `VmHWM`.
   - Compute:

     ```text
     one_h_worker_peak_rss_estimate =
         peak_rss_during_job -
         steady_rss_before_job
     ```

   - Repeat with `workers=2`, `workers=4`, and enough channels to keep workers
     busy. The slope of peak RSS against observed active jobs should match the
     one-worker estimate. If it does not, record the higher p95/peak value and
     use that for admission control.

5. **Deep target peak check**
   - Run a StartIndex-region target with many set bits.
   - Peak RSS should stay near one active H worker plus idle session state. If
     it grows with depth, investigate retained per-H temporaries before trusting
     the RAM formula.

6. **Other-consumer audit**
   - Compare the formula-predicted RSS against observed RSS for 100 and 1000
     channels.
   - Any persistent unexplained delta should be broken down before enabling the
     RAM gate. Candidates include gRPC buffers, HTTP/2 flow-control windows,
     DB serialization buffers, TLS state, pending fault-test channels, and
     retained known-secret/frontier vectors.

The benchmark JSON should include both configured estimates and measured values:

```json
{
  "memory_model": {
    "baseline_daemon_rss_mb": 0,
    "channel_metadata_rss_mb": 0,
    "idle_session_rss_estimate_mb": 0,
    "one_h_worker_peak_rss_estimate_mb": 0,
    "configured_max_ram_mb": 0,
    "configured_workers": 0,
    "ram_limited_workers_raw": 0,
    "effective_workers": 0,
    "ram_overcommit_warning": false
  }
}
```

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
3. Confirm the channel has a live session or active precompute state.
4. Disable the channel.
5. Wait and verify no additional frontier growth.
6. Verify live-session count and active-job count for the channel drop to zero.
7. Re-enable and verify precompute resumes through a fresh session.

Expected:

- Disabled channel does not start new jobs.
- Disabled channel holds no live `PrecomputeSession`, in-memory
  one-node-per-layer cache, gRPC JobStream task, or active job reservation.
- Re-enabled channel resumes from the durable common subset and live-session
  state is re-created if needed.
- Any active job that was in flight at disable time is cancelled or allowed to
  finish only if the disable RPC does not return until the live state is gone.
  After disable returns, the channel must consume no live RAM.

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

### `daemon_pair_ram_budget_derives_effective_workers`

Goal: prove `max_ram_bytes` reduces active worker concurrency using the
idle-session-aware formula.

Scenario:

1. Configure `workers=8`.
2. Configure static test estimates for baseline RSS, idle-session RSS, and
   one-H worker peak RSS.
3. Enable enough channels to create live idle sessions.
4. Set `max_ram_bytes` so the formula yields `ram_limited_workers_raw=2`.
5. Start several manual or background precomputes.

Expected:

- Status reports `configured_workers=8`, `effective_workers=2`, and no
  overcommit warning.
- At most two active precompute jobs run locally.
- The peer sees and uses the advertised effective worker count.

### `daemon_pair_ram_budget_warns_but_allows_one_worker`

Goal: preserve liveness when RAM is configured below the idle-session floor.

Scenario:

1. Configure `workers=4`.
2. Create enough live idle sessions that
   `max_ram_bytes - rss_floor < one_h_worker_peak_rss_estimate`.
3. Request one precompute.

Expected:

- Status reports `ram_limited_workers_raw=0`, `effective_workers=1`, and a
  RAM overcommit warning.
- Exactly one precompute may run.
- No second concurrent precompute starts while the warning condition remains.

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
