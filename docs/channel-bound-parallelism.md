# Channel-Bound Parallelism Investigation

Status: design and measurement plan. No implementation has landed yet.

The current daemon parallelizes across channels. A hot single channel is still
bounded by one live `PrecomputeSession`: one command loop owns one AG2PC session,
one labeled shachain cache, and one pair of JobStream transports. That is the
right default for correctness and memory, but it means abundant CPU cannot help
one channel once that single session is the bottleneck.

This note records two candidate ways to increase throughput for a single hot
channel without adding the cross-session import/relabel protocol.

## Current Boundary

Current daemon behavior:

- one outgoing live precompute session per enabled active channel;
- one incoming live precompute session per peer-initiated active channel;
- scheduler admission is keyed by channel, so at most one background precompute
  job is active for a channel;
- `PrecomputeSession` serializes `Plan` and `Precompute` commands through one
  `mpsc` loop;
- the live session keeps a RAM-only labeled shachain cache with at most one
  reusable parent per level;
- durable DB state stores only exact revealable leaves, never trunk/internal
  labels.

This is safe and simple, but it cannot fill a single channel's frontier faster
than one AG2PC session can execute sequential H applications.

## Idea 1: Multiple Independent Sessions Per Channel

Run several live AG2PC sessions for one channel, each owning a disjoint segment
of the future secret stream. For example:

```text
lane 0: next 128 outputs
lane 1: following 128 outputs
lane 2: following 128 outputs
...
```

Each lane authenticates the same channel seed share under the same fixed
per-channel Delta, but every session uses fresh OT, garbling, leaky-AND,
preprocessing, and labels. Lanes never exchange authenticated wires. They only
persist exact revealable leaves into the shared encrypted DB.

### Why It Is Plausible

- It uses existing AG2PC session semantics. There is no cross-session reuse of
  labels, so there is no import/relabel protocol.
- The sequential reveal gate is unchanged. A daemon may precompute far-ahead
  authenticated leaves, but it still opens clear secrets only when the caller
  supplies the exact `expected_next_index`.
- Parallelism is real if the channel has enough frontier demand. The worker
  budget can admit multiple lanes for the same channel, and each lane rides its
  own JobStream pair over the shared HTTP/2 peer channels.

### Costs And Risks

- Every lane pays its own session setup and seed authentication.
- Every lane loses labeled-cache reuse across lane boundaries. The lane span
  must be large enough to amortize its setup and trunk warm-up cost.
- The scheduler and state maps must move from `channel_index` keys to
  `(channel_index, lane_id)` or an equivalent lane descriptor.
- Peer descriptors must bind the lane id, lane range, security parameters, and
  circuit digest so both parties agree which session owns which targets.
- Disable/restart/rollback cleanup must drop all lanes for the channel.
- Delta lifetime accounting must count checked units across all lanes, including
  failed and repeated attempts.

### Implementation Shape

Add a per-channel config, initially off by default:

```text
channel_parallel_lanes: u32
lane_span: u64
```

Define deterministic lane ownership from public channel state and target index:

```text
lane_window = target_ordinal / lane_span
lane_id     = lane_window % channel_parallel_lanes
lane_range  = [lane_window * lane_span, (lane_window + 1) * lane_span)
```

The exact mapping must use the production reveal ordinal/index convention, not
mutable DB contents. Both parties must derive the same owner without a separate
coordination round. The JobStream descriptor then includes:

```text
channel_index
target_index
lane_id
lane_range_start
lane_range_len
ssp_target
delta_lifetime_checked_units_cap
circuit_digest
```

The daemon stores durable leaves exactly as it does today, keyed by target
index. Only live RAM state becomes lane-scoped.

### First Verdict

This is a good candidate when one channel needs high sustained precompute
throughput and the frontier target is large enough to keep multiple lanes warm.
It is probably not helpful for small frontiers because repeated session setup
can dominate.

The first benchmark should answer the amortization question:

- one channel, frontier 128 and 512;
- lanes 1, 2, 4, 8;
- lane spans 32, 64, 128;
- RTT 0 ms and 50 ms;
- report persisted secrets/sec, time to first 16 leaves, peak RSS, idle RSS,
  checked units, and failed/aborted jobs.

## Idea 2: Multi-Output Branch Circuits In One Session

Compute both sides of a branch, or a larger fixed subtree, inside one AG2PC
program. Instead of running one `H` application per target edge, a live session
runs a circuit that expands one authenticated parent into multiple authenticated
leaf outputs. The daemon then strips labels and persists the exact leaves needed
for future reveals.

The standalone party cache mode already contains the main primitive:
`build_tile_program` computes a `2^height` leaf tile from one parent inside one
session. The daemon does not yet use that shape for background precompute.

### Why It Is Plausible

- It stays inside one live session, so carried labels remain session-local and
  no import/relabel protocol is needed.
- It can collapse many protocol flights into one larger AG2PC program. This is
  especially attractive at 50 ms RTT, where the current one-H path costs many
  RTT-equivalent turns.
- It may reduce statistical-budget consumption because one larger
  `compute_inplace` instance covers a whole multi-output program instead of one
  instance per one-H step. The exact accounting must use the actual number of
  AG2PC `run_program` / `compute_inplace` calls.
- It keeps a single per-channel cache and avoids lane-boundary duplicate setup.

### Costs And Risks

- Peak RAM and bandwidth grow with tile size. A height-4 tile contains 15 SHA
  edges and 16 outputs, so it is much larger than one H.
- One large job can increase latency to the first leaf in the tile. This is good
  for throughput only if the channel actually needs the whole tile soon.
- It may not use abundant CPU by itself if the heavy AG2PC work remains mostly
  single-task inside one session. It primarily reduces protocol overhead and
  repeated setup, not necessarily CPU-core underuse.
- The scheduler must avoid computing leaves that cannot be revealed before they
  become derivable/obsolete under normal shachain rules.
- Persisted state remains exact target leaves only. Internal tile roots/trunks
  must stay RAM-only and be dropped when no longer useful.

### Implementation Shape

Add a new session command:

```text
PrecomputeTile {
    base_index: Index48,
    height: u8,
}
```

The command chooses a cached parent, runs a tile circuit in the same
`Ag2pcSession`, slices the `2^height` authenticated outputs, label-strips only
the leaves selected for durable frontier fill, and returns them as a batch.

The JobStream descriptor must bind the tile base and height. The writer commits
all returned leaves as one logical DB batch. If any peer validation or MAC check
fails, the whole tile is discarded.

Start with small heights:

```text
height=1: 2 leaves, 1 branch point
height=2: 4 leaves, 3 SHA edges
height=3: 8 leaves, 7 SHA edges
height=4: 16 leaves, 15 SHA edges
```

Existing party cache tests should be used as the oracle before daemon wiring.

### First Verdict

This is the most direct way to improve one-channel throughput under RTT. It
also has a smaller scheduler surface than multi-lane sessions. The main unknown
is the RAM/latency curve as tile height grows.

The first benchmark should answer the tile-size question:

- one channel, one live session;
- frontier 64, 128, and 512;
- tile heights 1, 2, 3, 4;
- RTT 0 ms, 10 ms, and 50 ms;
- report persisted secrets/sec, p50/p95 time per persisted leaf, peak RSS,
  idle RSS after fill, bytes sent, checked units, and time to first revealable
  leaf.

## Comparison

| Question | Multiple sessions | Multi-output circuit |
| --- | --- | --- |
| New crypto? | No, if lanes do not share wires. | No, if all outputs stay in one live session. |
| Uses many CPU cores for one channel? | Yes, through independent sessions. | Maybe; mainly reduces rounds/overhead. |
| RTT benefit | Moderate; sessions still run one-H steps. | High if many H steps collapse into one program. |
| RAM cost | Session setup/cache per lane plus active jobs. | Larger active circuit/job buffers. |
| Scheduler complexity | Higher: lane ownership, cleanup, accounting. | Moderate: range/tile planning and batch commit. |
| Setup amortization | Needs large lane spans. | Amortized inside each tile/range. |
| Restart behavior | Re-warm every lane from seed. | Re-warm one session from seed. |

The likely sequence is:

1. Measure the existing party cache tile mode under release and RTT to get the
   multi-output curve without daemon changes.
2. If tile height 2-4 gives a clear per-secret win at acceptable RSS, wire tile
   precompute into the daemon first.
3. If one tile-enabled session still cannot keep up for a hot channel, add
   multiple lane sessions so several tile-enabled sessions can fill disjoint
   future windows.

The two ideas compose: each lane can eventually use multi-output tile circuits.

## Initial Investigation Log

Code inspection confirms the current single-channel bottleneck:

- `PrecomputeSessionHandle` sends `Plan` and `Precompute` commands into one
  per-session `mpsc` loop;
- `run_outgoing_precompute_session` processes those commands serially because
  one `Ag2pcSession` owns the carried labels and cache;
- scheduler admission is keyed by `channel_index`, so a channel cannot have two
  active background precompute jobs today.

The existing standalone party cache path was used as a sanity check for idea 2
before daemon changes. The command shape is:

```text
SHACHAIN2PC_CACHE=1 SHACHAIN2PC_TILE_FANOUT=<1|16> \
  target/release/party <role> <port> <lo>-<hi> <share>
```

Release-mode, no emulated RTT, aligned range, both parties on loopback:

| leaves | fanout | wall | per secret | notes |
| ---: | ---: | ---: | ---: | --- |
| 16 | 1 | 3.78 s | 236 ms | trunk dominates |
| 16 | 16 | 3.85 s | 241 ms | one tile, trunk dominates |
| 256 | 1 | 18.62 s | 72.7 ms | one-SHA cache steps |
| 256 | 16 | 16.34 s | 63.8 ms | recursive tile path |

This measurement is deliberately narrow. It proves the current tile path works
and gives a modest low-RTT win, but it does not prove the daemon optimization.
At low RTT the run is mostly local compute and setup; the expected value of
multi-output circuits is larger under nonzero RTT because they reduce
latency-bearing AG2PC program instances. The next measurement must repeat the
same comparison at 50 ms RTT and include peak RSS.

## Security And Accounting Rules

Both ideas must preserve these invariants:

- reveal remains sequential and authorized by externally supplied
  `expected_next_index`;
- precomputed future leaves are authenticated, not cleartext;
- no session-local labels, COT state, or internal trunk nodes are persisted;
- all non-Delta randomness stays fresh per session/job;
- Delta lifetime accounting counts every checked unit across all lanes and
  multi-output jobs;
- peer descriptors bind lane/tile shape, target range, security parameters,
  and circuit digest;
- disabled channels drop all live lane/session state and schedule no more work.

These are protocol-shape changes, not new cryptographic primitives. They should
still be included in the funds-path security review, but they do not require
the parked import/relabel protocol.

## Investigation Tasks

1. Add release benchmark modes for the existing party cache tile path:
   `tile_height`, `frontier`, `RTT`, and RSS/bytes metrics.
2. Add a daemon-only model benchmark that simulates lane assignment without
   changing persistence, to estimate setup duplication for lane spans 32/64/128.
3. Prototype daemon tile precompute behind a feature flag and compare against
   current one-H precompute for one channel at 0 ms and 50 ms RTT.
4. Only after tile data is known, prototype lane-scoped sessions behind a
   feature flag.
5. Keep both prototypes off by default until the benchmark report shows a
   throughput/RSS win and integration tests cover restart, disable, rollback,
   tamper, and expected-index reveal safety.
