# Daemon Integration Test Plan

This document tracks remaining daemon integration tests, benchmarks, and RAM
optimization work. The tests exercise the daemon as a two-party service: real
daemon processes, real CLI control, real encrypted DBs, real peer
gRPC/JobStream, and the existing AG2PC implementation.

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
- peer mTLS cached reveal happy path;
- cached reveal rejection for missing local authorization, binding mismatch, and
  tampered peer shares;
- one peer DB loss followed by joint frontier recompute;
- background precompute to the shared target;
- two concurrent channels over JobStream;
- Delta lifetime cap refusal;
- failed security-parameter negotiation monitoring;
- expected-index reveal refusal.
- panic-safe daemon child cleanup through `Drop`;
- RAM-derived `effective_workers`, low-RAM warning, and precompute admission;
- disable behavior that refuses active precompute and frees live session state;
- an ignored 100-channel benchmark that uses persistent local control gRPC
  clients and reports throughput, cached reveal latency, and per-node peak RSS.
- encrypted redb persistence unit coverage for round-trip/reopen,
  wrong-master rejection, tampered-value rejection, opaque deterministic keys,
  and migration from the legacy encrypted JSON blob.

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

The harness must be panic-safe. `DaemonPair` and every per-side process handle
must own child processes through a `Drop` guard that kills and reaps them on any
exit path, including failed assertions and test panics. Restart helpers should
replace the guarded child handle atomically only after the old child is dead.
This is required before adding restart, rollback, benchmark, or fault-injection
tests: leaked daemons consume ports, skew CPU/RSS measurements, and make later
tests nondeterministic.

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

## Persistence Status

The full-file encrypted JSON store has been replaced by an encrypted redb store.
Daemon state is authoritative in RAM; writes enqueue logical mutation batches to
one background writer. Stored keys are deterministic HMAC-SHA256 PRFs over
canonical logical keys, and stored values are AEAD encrypted with fresh nonces
and the opaque stored key as AAD. This removes the per-reveal full-DB rewrite and
uses redb transactions for crash-consistent snapshots.

Lazy durability is intentional for reveal/precompute cache updates: losing the
most recent tail after a crash costs recomputation, not an unsafe reveal.
Channel enable/disable uses immediate flush because registry changes are rare.
The writer periodically checkpoints dirty eventual commits and clean shutdown
drains and flushes the writer. Legacy encrypted JSON blobs are migrated once
through a durable temporary redb and renamed to `*.migrated`; startup recovers
an interrupted migration before opening the store.

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
7. Reveal all 100 precomputed secrets sequentially through persistent local
   control gRPC clients, using the required `expected_next_index` value for
   each channel.
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
- Expected behavior: precompute queues or runs with only the RAM-derived
  effective worker count.
- If the RAM formula leaves no room for a worker, the daemon still allows one
  worker and reports `ram_overcommit_warning`.

If the idle-session-aware formula leaves room for zero workers, the daemon
should still expose one effective worker and print/return a clear warning that
the configured RAM budget is too low and may be exceeded. This preserves
liveness for emergency reveal/precompute paths while making the operator-facing
over-budget condition explicit.

## RAM Optimization Findings And Plan

Recent 100-channel daemon measurements showed two separate memory numbers:

- a fill-time peak around 720-776 MB per daemon;
- a lower steady idle floor after precompute finishes.

The peak includes active one-H workers, AG2PC working buffers, gRPC/TLS state,
and allocator high-water effects. The largest avoidable idle-session cost found
in review is simpler: every live `PrecomputeSession` owns a fresh parsed copy of
the SHA-256 compression circuit.

The embedded SHA circuit has about 116k gates and occupies roughly 1.77 MiB as
a `Circuit`. With 100 live channels, the current owned field duplicates about
177 MiB of immutable gate data. With 1000 live channels, that would grow to
about 1.77 GiB. This is not inherent to the protocol; it is a data-layout bug.
The circuit should be a singleton.

### 1. Share The SHA Circuit

Priority: high. This is the largest confirmed retained-RAM win and does not
change protocol bytes or cryptography.

Status: implemented. The daemon parses the SHA-256 compression circuit once at
startup, stores it as `Arc<Circuit>`, and threads the same allocation through
incoming and outgoing live precompute sessions. Daemon callers use
circuit-aware party helpers; standalone compatibility paths keep their existing
public API.

Implementation plan:

- parse `sha256_compress_gadget()` once when the daemon initializes;
- store it in daemon shared state as `Arc<Circuit>`;
- pass `Arc::clone` into `PrecomputeSession::setup_with_streams`, so outgoing
  and incoming live session maps both share the same allocation;
- update precompute, reveal, and fallback helpers to take `&Circuit` or
  `Arc<Circuit>` instead of reparsing or owning a `Circuit`;
- convert standalone per-operation helpers, including
  `run_precompute_path_with_streams` and reveal/fallback paths, so they do not
  parse a fresh circuit per call;
- preserve the existing circuit digest and C++/Rust compatibility tests;
- add a daemon unit/integration assertion that two live precompute sessions
  share the same circuit allocation, for example with `Arc::ptr_eq` behind a
  test-only accessor;
- add a grep guard or unit test that rejects `sha256_compress_gadget()` call
  sites outside one-time initialization and tests;
- update RAM calibration after the change.

Expected result:

```text
current circuit RAM  ~= 1.77 MiB * live_channel_count
target circuit RAM   ~= 1.77 MiB total
```

The worker-count benefit is indirect. Removing duplicate circuits lowers the
idle RSS floor, which leaves more `max_ram` headroom for active one-H workers.
The circuit itself must not be counted as a per-worker cost after this change.
`Circuit` is immutable plain gate data and can be shared as `Arc<Circuit>`
across tokio tasks without a lock or gate-data clone.

### 2. Prune Live Session Cache Retention

Priority: medium. The current cache is bounded, so this is not the hundred-MB
issue, but it is the next cleanup.

Status: implemented for the live session cache. Retention follows the
shachain future-storage closure, keeps at most one labeled node per
trailing-zero bucket, and prunes obsolete one-shot intermediates after each
target. Durable DB persistence remains exact-target-only.

The live session should keep at most one labeled node per shachain layer, and
only nodes that can still be selected as a future parent by the shachain
derivability rules. "Future parent" means the full shachain-storage closure for
the remaining count-down sequence, not only the immediate next target. The live
cache should be sufficient to keep several consecutive future targets warm while
still bounded to at most one node per trailing-zero bucket.

The live session must not cache in-trunc intermediates: the sequential
trunk/truncation path used only to reach the current batch/target region is
one-shot work and is known not to be selected as a later parent. Those nodes
should flow through the current computation and then be dropped instead of being
cloned into the live cache.

Implementation plan:

- make the parent-selection and retention rule one shared helper;
- define that helper in terms of the shachain-storage closure needed to derive
  all remaining lower future indices, not only the next target;
- test it against the reference shachain derivability rules, including cases
  where trunk/trunc intermediates are produced but are not retained;
- after every target commit, prune cached labeled nodes not in that closure;
- assert that a deep target leaves only reusable frontier/cache parents in RAM,
  not every intermediate H along the path;
- assert that warm reuse survives several consecutive count-down targets, for
  example 5-10 steps with roughly one checked unit per step where the shachain
  closure predicts reuse;
- keep the durable DB policy unchanged: only exact requested revealable target
  leaves are persisted.

Expected result: kilobytes per channel rather than hundreds of MiB, fewer
clones, no retained one-shot trunk material, and clearer invariants.

### 3. Trim Idle AG2PC Buffers

Priority: medium after measuring.

Status: implemented for the safe leftover class found in this pass.
`trim_idle_allocations()` drops unused SoftSpoken leftover COT chunks after a
successful live-session precompute, but keeps setup state, PPRF leaves, session
counters, authenticated labels, and the live frontier intact.

Review found retained SoftSpoken/triple-pool buffers on the order of hundreds
of KiB per live channel. Some state is required for a live session, but large
spent COT/PPRF buffers and compute temporaries should not remain resident when
the channel is idle.

Implementation plan:

- instrument `Ag2pcSession` and `Ag2pcTriplePool` idle sizes after one target;
- add an explicit `trim_idle_allocations()` method if buffers can be safely
  cleared without changing protocol state or reusing one-time material;
- call it after a target commit when no H is active for that channel;
- prove a later in-session precompute still reuses the labeled shachain parent
  and only regenerates safe fresh preprocessing as needed;
- benchmark idle RSS and warm precompute latency before and after.

Do not clear data merely to save RAM if that causes a protocol restart or
requires deterministic reuse of one-time material. Labels for the current live
frontier remain RAM-only and must be fresh-session state.

### 4. Avoid Fresh Setup For Cached Reveal

Priority: high for throughput, medium for RAM.

Status: implemented for nonzero persisted cached leaves. The daemon
cached-reveal path now uses peer gRPC `RevealCached`, a lightweight two-party
MAC-open over persisted `lambda + wire_bundle` material and the re-derived fixed
channel Delta. Alice sends her local share; Bob's peer handler waits for Bob's
matching local reveal authorization, verifies Alice's share, returns Bob's
share, and both daemons store the same opened value. This keeps the two-sided
reveal rendezvous and IT-MAC correct-or-abort check, but skips base OT,
SoftSpoken bootstrap, COT, and garbling setup.

The explicit `I=0` seed-reveal path and the full-derivation fallback remain on
the legacy one-shot transport. The persisted `lambda` plus `wire_bundle`
MAC/key material is still required DB material for restart reveal;
`strip_labels_for_reveal` must continue to remove only session-local labels.

The latest 100-channel good-case release runs show that setup was not the only
remaining latency source. With peer gRPC cached reveal, persistent local control
clients, and revealed-node DB compaction, sequential cached reveals still landed
in the same broad range as the earlier CLI/EMP path once background refill and
DB writes were included. The final drained run averaged 443.52 ms (p50 429 ms,
p95 691 ms, p99 794 ms). Treat this as a mixed consume/refill measurement, not
as isolated reveal latency.

Remaining work:

- add an isolated reveal-only benchmark that disables background refill after
  the initial fill;
- add a parallel cached-reveal benchmark across channels;
- add a fallback reveal benchmark for comparison.

This is a latency/throughput optimization, not a new crypto protocol. It must
not reveal a value without the same IT-MAC correct-or-abort check already used
by public reveal.

### 5. Recalibrate RAM Constants After Fixes

Priority: required before treating benchmarks as capacity numbers.

Status: partially measured. The ignored benchmark harnesses report steady
`VmRSS` as well as `VmHWM`, so calibration can separate fill-time peak from
idle floor. Defaults remain conservative until the full calibration sequence is
run and reviewed.

The latest drained 100-channel good-case release run with 4 configured workers
and a 1 GiB RAM cap reported:

```text
precompute: 27.474 s total, 274.74 ms/secret
cached reveal with refill: avg 443.52 ms, p50 429 ms, p95 691 ms, p99 794 ms
Alice RSS: idle-after-precompute 425 MB, peak 482 MB
Bob RSS:   idle-after-precompute 456 MB, peak 528 MB
pair peak sum: 1011 MB
effective workers at end: Alice 4, Bob 2
```

The benchmark leaves precompute target enabled during reveal, so it measures a
mixed consume/refill path. Run the isolated reveal-only benchmark before using
these reveal numbers as a capacity limit.

After the circuit sharing and any idle-buffer trimming land, rerun the
calibration sequence in this document and update the configured estimates:

- baseline daemon RSS;
- channel metadata RSS;
- idle live-session RSS;
- one-H worker peak RSS;
- fill-time peak versus steady idle floor;
- before/after 100-channel idle RSS for the `Arc<Circuit>` change, with the
  expected direction roughly from the old duplicated-circuit floor toward the
  singleton-circuit floor;
- 100-channel and 1000-channel scaling;
- disabled-channel RSS drop.

The 1000-channel idle-floor run is implemented as
`daemon_bench_1000_channels_idle_floor`; it fills one target per channel,
records steady RSS, disables all channels, and records the post-disable RSS
floor.

The current `one_h_worker_peak_rss_estimate` is deliberately conservative. If
the measured p95 daemon worker peak is materially below the configured value,
lower the default only after the slope check across `workers=1/2/4` confirms
that peak RSS grows linearly with active jobs.

### 6. Benchmark The Real Steady State

The current 100-channel benchmark measured serial cached reveal and cold-ish
precompute behavior. Add follow-up benchmark modes:

- parallel cached reveals across channels;
- warm incremental precompute loop, for example fill `I=2` then `I=3`
  (implemented as `daemon_bench_100_channels_warm_refill`);
- mixed steady state that consumes one cached reveal and refills one future
  target per channel;
- optional 50 ms RTT run for remote-cosigner sensitivity.

Report:

```text
cached_reveal_ms_per_secret
warm_precompute_ms_per_secret
steady_update_ms_per_secret
steady_updates_per_second
idle_rss_mb
peak_rss_mb
effective_workers
ram_overcommit_warning
```

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
- RAM budget: implemented for precompute admission. `max_ram_bytes` is parsed,
  configurable, reported by status/config, and converted into
  `effective_workers` using the idle-session-aware/current-RSS-aware formula
  below. If the raw RAM-derived worker count is zero, the daemon still exposes
  one effective worker and reports a RAM warning.

The daemon has a measured or configured peak RAM cost per active one-H worker.
It turns RAM into a worker cap and reuses the existing worker-budget machinery.

The model is intentionally idle-session aware:

```text
rss_floor =
    baseline_daemon_rss +
    live_idle_sessions * idle_session_rss_estimate

observed_floor =
    max(current_rss_bytes -
        active_jobs * one_h_worker_peak_rss_estimate, 0)

admission_floor = max(rss_floor, observed_floor)

worker_ram_budget = max(max_ram_bytes - admission_floor, 0)

ram_limited_workers_raw =
    floor(worker_ram_budget / one_h_worker_peak_rss_estimate)

ram_limited_workers = max(ram_limited_workers_raw, 1)

ram_overcommit_warning =
    ram_limited_workers_raw == 0
```

`admission_floor` uses the greater of the modeled floor and observed current RSS
after subtracting currently active worker reservations. This catches memory
consumers the simple formula missed, including allocator
retention after previous H jobs, gRPC/HTTP2 buffers, TLS state, and DB buffers.
The 100-channel benchmark showed this matters: after precompute completed, RSS
remained much higher than the small live-session estimate alone.

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
one_h_rss_estimate_mb = 192
idle_session_rss_estimate_mb = 1
```

The initial worker estimate is intentionally conservative for the daemon, not
the library-only party path. A 100-channel daemon benchmark with 4 workers
observed per-node peak RSS in the 718-760 MB range, which includes tonic/tokio,
mTLS, live sessions, worker allocation, and allocator-retained memory. The RAM
gate should therefore treat the real daemon as the calibration source and
continue refining this value from benchmark p95/peak data.

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

This is a deliberate "all enabled sessions resident" policy:

```text
ram_floor ~= baseline_daemon_rss +
             enabled_live_channels * idle_session_rss_estimate
```

Operators must size `max_ram_bytes` for the enabled-channel set, not only for
currently active jobs. A future LRU policy could evict enabled-but-idle sessions
and re-warm them on use, but that is not the current target because it trades
predictable low-latency extension for extra re-warm churn. The explicit operator
control for freeing this RAM is `channel disable`.

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
   - The daemon should also self-measure its own `VmRSS` after startup
     initialization and expose it as the default runtime
     `baseline_daemon_rss`. Benchmarks then validate the self-measured value
     instead of hardcoding a stale baseline across builds or deployments.

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

### `daemon_pair_live_cache_drops_in_trunc_intermediates`

Goal: prove one-shot trunk/trunc intermediates are not retained in the live
session cache.

Scenario:

1. Precompute a deep target with several sequential H applications before the
   reusable branch point.
2. Inspect test-only live-cache metadata after the target commits.
3. Request a nearby target that should reuse only the retained frontier parent,
   not any in-trunc intermediate.

Expected:

- Live cache metadata contains only reusable shachain parents, at most one per
  level.
- In-trunc intermediate masks are absent.
- Checked-unit counts show the nearby target reuses the intended frontier
  parent and does not depend on a hidden retained trunk node.
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
