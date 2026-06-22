# Daemon Service Plan

Status: planning document for the next large implementation phase. This plan is
for review before coding. The goal is to turn the optimized Rust implementation
into a long-running two-party service with local control APIs, durable cache
state, background precomputation, and sequential reveal.

This document intentionally starts from the current optimized Rust/AG2PC code and
does not include the abandoned experimental windowing work.

## Goals

- Run one daemon per party.
- Provide daemon-to-daemon gRPC for MPC coordination and data transport.
- Provide a local CLI-to-daemon gRPC API for operator control.
- Accept one local master secret at daemon startup.
- Derive the encrypted database key from the local master secret.
- Derive every local channel shachain seed share from the local master secret and
  a channel index.
- Persist only durable, droppable state. Losing or rolling back the DB must cause
  recomputation, not permanent protocol failure or unsafe reveal.
- Treat unrevealed authenticated precompute as epoch-scoped MPC state. The first
  daemon version keeps this frontier in memory and rewarms it after restart.
- Support background precomputation under RAM and worker budgets negotiated as
  the minimum of both parties' current settings.
- Prioritize requested reveals over background precomputation.
- Keep reveal sequential: a channel reveal must be the next unrevealed secret, or
  an older secret derivable locally from already revealed later shachain entries.
- Start with the simple cache strategy: each MPC job computes one shachain
  `H` application, and the daemon caches authenticated intermediates.

## Non-Goals

- Do not implement recursive tiled cache, streaming preprocessing, or a new MPC
  protocol in this phase.
- Do not persist raw master secrets.
- Do not persist peer configuration as authoritative truth. Peer config is a
  live input to scheduling and may change.
- Do not make the DB required for correctness. The system must tolerate DB
  deletion or rollback by recomputing.
- Do not reveal batches. Channel updates are sequential, so reveal stays one
  secret at a time.
- Do not persist unrevealed authenticated frontier nodes in the first daemon
  version. Encrypted persistence for such nodes is a later extension with
  stricter epoch handling.

## Security Model

The current MPC protocol remains the cryptographic core. The daemon adds durable
state, scheduling, and control surfaces, so it must preserve these invariants:

- The local master secret is process memory only. It is provided at startup and
  zeroized on shutdown where possible.
- Compromising one daemon's master secret gives the attacker only that party's
  shares. Revealing full shachain secrets still requires the peer's MPC
  participation, unless the attacker also compromises the peer or a revealed
  secret.
- The encrypted DB key is derived from the master secret with domain separation.
- Channel seed shares are derived from the master secret with separate domain
  separation and do not depend on DB salt or mutable config.
- Cached state is split into two classes:
  - revealed shachain secrets, which are durable DB state and are governed by
    normal shachain rules;
  - unrevealed authenticated frontier nodes, which are tied to an MPC Delta epoch
    and are in-memory only in the first version.
- Unrevealed authenticated nodes are never converted into cleartext and re-input
  through normal private input.
- Revealed secrets are inserted into the local shachain store using standard
  shachain rules: at most one known value per level, and older derivable secrets
  can be answered locally.
- If a peer lacks an intermediate that we have, we must be able to discard ours
  and jointly recompute from a common ancestor. Local cache asymmetry is not an
  error, but unilateral catch-up is not possible for authenticated nodes because
  fresh randomness will not recreate the same node.
- A reveal request must include the caller's expected next reveal index. The
  daemon DB is not the authority for the channel's reveal frontier.
- A failed MPC job aborts that job and drops in-flight state. It must not reveal
  a wrong secret or commit a derived node as valid.
- A disabled channel cannot start new background jobs. Already-running jobs for
  that channel are cancelled unless they are serving an active reveal request.

For funds-facing use, this still needs a human security review. This plan makes
the service shape reviewable; it is not a production-security sign-off.

## Key Hierarchy

Input at daemon startup:

```text
master_secret: 32 bytes or higher-entropy secret material
party_role:    local identity/role for peer relationships
db_path:       encrypted persistent store path
```

Derived keys:

```text
db_key = HKDF-SHA256(
    ikm  = master_secret,
    salt = db_salt,
    info = "shachain2pc daemon db key v1"
)

channel_seed_share(channel_index) = HKDF-SHA256(
    ikm  = master_secret,
    salt = empty or deployment salt,
    info = "shachain2pc channel seed share v1" || encode(channel_index)
)
```

`db_salt` may be stored cleartext next to the DB header because it protects only
key derivation hygiene. It must not affect channel shares, otherwise deleting the
DB would change channel behavior.

Open decision for implementation: whether to use SQLCipher (`rusqlite` +
SQLCipher) or an application-level encrypted store. SQLCipher is the most direct
fit for indexed durable state and crash-safe transactions. Application-level AEAD
over `redb`/`sled` is also possible but creates more footguns around indexing and
partial writes. Prefer SQLCipher unless build constraints become painful.

## Delta Epochs And Authenticated Frontier State

Authenticated MPC values are bound to the local Delta used by the current MPC
epoch and to the peer's matching epoch state. They are not ordinary durable cache
entries.

The first daemon version uses this policy:

- Each enabled channel has an active Delta epoch.
- Delta is random per `(channel, epoch, role)`, not deterministically derived
  from the master secret.
- Delta rotation is controlled by a configured work budget, measured in one-H
  jobs or AND gates/checks rather than in revealed secrets.
- Unrevealed authenticated frontier nodes are in memory only.
- Daemon restart, DB deletion, DB rollback, or Delta rotation drops the
  unrevealed authenticated frontier and rewarms it.
- The DB may store epoch metadata and counters for observability, but not enough
  material to continue an old authenticated frontier in v1.
- The daemon never stores or receives the peer's Delta. It may store peer epoch
  identifiers, commitments, or digests.

Deterministically deriving Delta from the master secret is intentionally not the
v1 design. It creates rollback/reuse hazards: after DB loss, the daemon could
recreate the same Delta while forgetting how much statistical budget was already
spent under it. If persistent authenticated frontier is added later, store the
random local Delta encrypted in the DB, bind every node to the epoch metadata,
and require both parties to prove they still hold the same epoch before using
the node.

## Identities And Channels

A channel is identified locally by `channel_index: u64` initially, as requested.
The plan should leave room to extend this to a stronger channel identity:

```text
channel_id = {
  index: u64,
  optional_peer_id: bytes,
  optional_external_channel_id: bytes
}
```

The daemon should reject accidental duplicate enabled channels for the same peer
unless explicitly overwriting an existing disabled record.

Channel state:

```text
Channel {
  index: u64,
  enabled: bool,
  last_observed_next_reveal_index: Option<u64>,
  precompute_target: u64,
  local_budget_snapshot: Budget,
  peer_budget_snapshot: Option<Budget>,
  created_at,
  updated_at
}
```

`last_observed_next_reveal_index` is advisory status only. The external channel
state machine must provide `expected_next_reveal_index` on every reveal request.
Older indices may be returned locally only if standard shachain derivability
allows it from known later secrets.

## Persistent State

The DB stores durable checkpoints, not required truth. Every table must be safe
to delete. The worst expected result is recomputation.

Suggested logical tables:

```text
meta(schema_version, db_salt, daemon_instance_id)
channels(channel_index, enabled, last_observed_next_reveal_index,
         precompute_target, ...)
peer_configs(peer_id, last_seen_config, last_seen_at)
known_secrets(channel_index, level, index, secret_ciphertext, inserted_at)
epoch_metadata(channel_index, epoch_id, counters, status, created_at, ...)
jobs(job_id, channel_index, kind, priority, state, lease_epoch, ...)
job_events(job_id, event_no, event_type, payload, created_at)
```

`known_secrets` stores revealed shachain values, encrypted by the DB. It uses
standard shachain insertion constraints, not arbitrary append-only storage.

`epoch_metadata` stores non-secret metadata about in-memory authenticated
frontier epochs. In v1 it is not sufficient to resume unrevealed precompute after
restart. A later persistent-frontier design may add encrypted epoch-local Delta
and authenticated nodes, but only with explicit epoch matching and budget
accounting.

`jobs` are persisted only for operator visibility and crash cleanup. On daemon
restart, in-flight MPC jobs are not resumed mid-message in the first version;
they are marked abandoned and recomputed from the last durable cache node.

## Refactor Prerequisite: Embeddable MPC Jobs

The current `party` binary is a command-oriented protocol runner. The daemon
needs an embeddable library with explicit job boundaries.

Refactor targets:

```text
shachain2pc-core
  deterministic shachain planning, cache lookup, shachain insert/derive rules

shachain2pc-mpc
  AG2PC session API, input authentication, run one H application, reveal API

shachain2pc-transport
  transport trait implemented by TCP today and gRPC streams later

shachain2pc-daemon
  scheduler, DB, local gRPC, peer gRPC, channel lifecycle

shachain2pc-cli
  local control client
```

The first embeddable API should be narrow:

```rust
trait MpcTransport {
    async fn send(&mut self, frame: Bytes) -> Result<()>;
    async fn recv(&mut self) -> Result<Bytes>;
    async fn flush(&mut self) -> Result<()>;
}

struct OneHashJobInput {
    channel_index: u64,
    parent: AuthenticatedValue,
    bit: u8,
}

struct OneHashJobOutput {
    child: AuthenticatedValue,
    cost: ResourceCost,
}

async fn run_one_hash(
    session: &mut MpcSession,
    transport: &mut dyn MpcTransport,
    input: OneHashJobInput,
) -> Result<OneHashJobOutput>;
```

The job is serializable at the boundary: before it starts and after it commits.
Mid-MPC pause/resume is explicitly deferred. Eviction cancels only the currently
running `H`; already committed unrevealed parents remain in the active in-memory
frontier, and revealed parents remain in the DB.

This satisfies the user-facing requirement of pausable/resumable work at the
cache level without pretending that the internal AG2PC transcript can be safely
snapshotted yet.

## gRPC Surfaces

There are two gRPC surfaces:

1. Peer API: daemon-to-daemon, authenticated and encrypted.
2. Local API: CLI-to-daemon, bound to loopback TCP in the first version.

Use `tonic` initially. For peer transport, use mTLS or pinned peer certificates
from the start. Unix domain sockets and Windows named pipes are deliberately
deferred to avoid platform-specific transport work in the first daemon version.

### Peer API

```proto
service PeerService {
  rpc Hello(HelloRequest) returns (HelloResponse);
  rpc ConfigStream(stream ConfigUpdate) returns (stream ConfigUpdate);
  rpc JobStream(stream PeerFrame) returns (stream PeerFrame);
}
```

`Hello` negotiates protocol versions, daemon identity, and supported features.

`ConfigStream` exchanges live budgets and precompute settings:

```text
ram_budget_bytes
worker_budget
precompute_target
enabled_channels summary/version
protocol_version
```

`JobStream` carries framed MPC messages plus job coordination frames. Use one
bidirectional stream per active job or per worker, not one global stream for all
jobs. A single global stream would make chatty one-H jobs block each other behind
HTTP/2 stream-level ordering and would undermine parallel workers.

```text
StartJob(job_id, channel_index, node, priority, transcript_digest)
MpcFrame(job_id, seq, bytes)
CancelJob(job_id, reason)
CommitJob(job_id, output_digest)
AbortJob(job_id, reason)
```

The peer protocol must be symmetric: either party can request work, but a job
starts only after both sides have accepted the same job descriptor.

Server and client authentication are both required. The server validates the
client certificate, the client validates the server certificate, and job
descriptors bind the expected peer identity.

### Local API

```proto
service ControlService {
  rpc Status(StatusRequest) returns (StatusResponse);
  rpc SetConfig(SetConfigRequest) returns (SetConfigResponse);
  rpc EnableChannel(EnableChannelRequest) returns (ChannelResponse);
  rpc DisableChannel(DisableChannelRequest) returns (ChannelResponse);
  rpc Reveal(RevealRequest) returns (RevealResponse);
  rpc ListChannels(ListChannelsRequest) returns (ListChannelsResponse);
  rpc ListJobs(ListJobsRequest) returns (ListJobsResponse);
}
```

CLI shape:

```text
shachain-daemon \
  --db /path/to/db \
  --master-secret-stdin \
  --listen-peer 0.0.0.0:9000 \
  --listen-local 127.0.0.1:9001 \
  --local-cert /path/to/local-cert.pem \
  --local-cookie /path/to/local-cookie \
  --peer https://peer.example:9000 \
  --max-ram-mb 1024 \
  --workers 2 \
  --precompute 1024

shachain-cli status
shachain-cli config set --max-ram-mb 512 --workers 1 --precompute 256
shachain-cli channel enable 42
shachain-cli channel disable 42
shachain-cli reveal 42 --expected-next 281474976710655
```

`channel enable 42` is idempotent. It creates or re-enables the channel locally.
Both parties must enable the same channel before background jobs run.

`reveal 42 --expected-next N` reveals the next sequential secret for channel 42.
It may return locally if the requested value is derivable from already revealed
shachain state. Otherwise it schedules a foreground MPC job. The expected index
is mandatory because the daemon DB is droppable cache, not the authority for the
Lightning channel state.

The local API uses loopback TCP in v1. On first start, the daemon creates a local
TLS certificate and a high-entropy cookie file. The CLI reads a local control
file containing the endpoint, certificate fingerprint, and cookie path. The CLI
pins the daemon certificate and sends the cookie as local authentication
metadata. The cookie file must be owner-readable only.

## Scheduler

The scheduler has two resource budgets:

```text
effective_ram_bytes = min(local_ram_bytes, peer_ram_bytes)
effective_workers   = min(local_workers, peer_workers)
effective_precompute = min(local_precompute, peer_precompute)
```

Budgets are exchanged on the peer `ConfigStream`. If peer config is missing,
background precompute is paused. Foreground reveal may still start if a fresh
peer config can be obtained during reveal setup. A peer can grief liveness by
advertising tiny budgets or `precompute=0`; this is not a confidentiality break,
but it must be visible in status and logs.

Job classes:

```text
ForegroundReveal  highest priority
Repair            required recomputation for a requested reveal
BackgroundFill    precompute toward target
Maintenance       DB cleanup, stale job cleanup
```

Eviction rules:

- Foreground reveal can evict background work.
- Lower-priority jobs are cancelled before starting new high-priority work.
- Eviction cancels only the currently running `H`.
- Completed revealed secrets remain persisted. Completed unrevealed
  authenticated parents remain in the active in-memory epoch frontier.
- Cancelled jobs are safe to reschedule.
- If local and peer authenticated frontier state disagrees, both parties choose
  the deepest common authenticated ancestor in the same epoch, or the latest
  revealed shachain ancestor, and jointly recompute from there.

Planning loop:

1. Read local config and last peer config.
2. Compute effective budgets.
3. For each enabled channel, compute desired frontier up to
   `effective_precompute`.
4. Generate candidate one-H jobs from missing cache edges.
5. Reserve RAM/workers for the highest-priority feasible jobs.
6. Start jobs through `JobStream`.
7. Commit unrevealed outputs to the active in-memory frontier, and commit any
   revealed outputs transactionally to DB.
8. Re-plan after each commit, cancel, config update, or reveal request.

RAM accounting starts conservative:

```text
one_hash_ram_estimate = measured_peak_for_one_H + safety_margin
job_ram = daemon_baseline_rss + active_workers * one_hash_ram_estimate
```

Initial sizing should use the current measurements as a starting point:
approximately 10 MB live heap and 26 MB RSS per concurrent one-H job, plus daemon
baseline RSS and a safety margin. Then refine with measured per-job telemetry.
The daemon should expose current RSS, estimated reserved RAM, and peak observed
RAM.

## Cache Algorithm, Version 1

Start with the simple per-edge cache:

- The root is the authenticated channel seed share combination.
- Each shachain edge is one MPC `H` application.
- A node is identified by `(channel_index, shachain_index_or_prefix, depth)`.
- The active epoch frontier stores unrevealed authenticated intermediate nodes in
  memory.
- The DB stores revealed secrets and metadata, not unrevealed authenticated
  nodes in v1.
- A disabled channel keeps DB state but does not schedule background work.
- Re-enabling uses existing nodes if both sides can agree on them; otherwise
  they are dropped and recomputed.

Reveal path:

1. Validate the caller-provided `expected_next_reveal_index`.
2. Validate requested reveal is sequential or locally derivable from known later
   secrets.
3. If locally derivable, return without peer MPC.
4. Otherwise promote required path to foreground priority.
5. Compute missing one-H edges until the target authenticated node exists.
6. Run interactive reveal for exactly that secret.
7. Insert the clear revealed secret using shachain rules.
8. Return the same secret on both local CLIs.

This avoids batch reveal and preserves the current sequential channel-update
model.

## Idempotence And Crash Behavior

The daemon must treat every operation as restartable:

- `EnableChannel` can be retried safely.
- `DisableChannel` can be retried safely.
- `Reveal` with the same expected next index can be retried. If the secret was
  already revealed and inserted, return it from local shachain state.
- Every reveal request must include the expected next index from the external
  channel state machine:

```text
Reveal(channel_index, requested_index, expected_next_reveal_index)
```

If the DB is older than the external channel state, the expected index supplied
by the caller prevents the daemon from treating stale DB state as authority. If
the caller cannot provide the expected next index, the daemon refuses to reveal.

## Observability

Expose:

- peer connected/disconnected;
- negotiated budgets and precompute target;
- enabled/disabled channel count;
- per-channel next reveal index;
- known shachain levels;
- active frontier/cache node count;
- active jobs and priorities;
- cancelled/aborted jobs;
- current RSS and peak RSS;
- per-job wall time, MPC time, bytes sent/received;
- cache hit/miss/recompute counts.

Logs must never include secrets, DB keys, authenticated wire values, or raw MPC
frames.

## Implementation Phases

### Phase 0: Freeze The Embedding Boundary

- Move reusable party logic out of `shachain2pc-party` into library crates.
- Define `MpcTransport`.
- Keep the existing CLI behavior working through the new library API.
- Add tests proving current single, chunked, tree/cache modes still match
  `ref_cli`.

Review gate: no daemon yet; only refactor and unchanged behavior.

### Phase 1: One-H Job API

- Implement `run_one_hash` over the existing AG2PC session.
- Represent authenticated values as serializable owned structs.
- Add deterministic job descriptors and transcript digests.
- Add cancellation at job boundaries.
- Add tests for one-H correctness, abort, and recomputation from parent.

Review gate: one-H jobs are embeddable and serializable at boundaries.

### Phase 2: Encrypted DB And Shachain Store

- Add encrypted DB setup and key derivation.
- Add channel records.
- Add known-secret shachain insertion/derivation.
- Add epoch metadata.
- Add crash/reopen tests.
- Add DB deletion/rollback recomputation tests.

Review gate: DB is droppable for cache state, revealed-secret storage is
consistent with shachain rules, and reveal APIs require caller-supplied expected
indices.

### Phase 3: Local Daemon And CLI API

- Add `shachain-daemon` process with local gRPC.
- Add `shachain-cli`.
- Add local loopback TLS certificate generation and cookie authentication.
- Implement status, config set, channel enable/disable, list channels/jobs.
- Keep peer/MPC mocked or in-process for this phase.

Review gate: local control plane is stable before peer networking.

### Phase 4: Peer gRPC And Budget Exchange

- Add peer identity/configuration.
- Add peer `Hello`, config stream, and job stream.
- Use mTLS or pinned certificates on both client and server sides.
- Negotiate min RAM, workers, and precompute target.
- Add disconnect/reconnect behavior.

Review gate: two daemons can agree on config and reject mismatched job
descriptors.

### Phase 5: Scheduler And Background Precompute

- Implement priority queue.
- Implement RAM/worker budget reservation.
- Implement eviction/cancellation of background jobs.
- Implement cache-aware planning from deepest common node.
- Implement Delta epoch work counters and rotation.
- Start background precompute after both parties enable a channel.

Review gate: background jobs fill cache under budgets and survive cancellation.

### Phase 6: Sequential Reveal

- Implement foreground reveal.
- Enforce sequential reveal with expected index.
- Use local derivation for older secrets derivable from known later secrets.
- Persist revealed secrets with shachain rules.
- Add tests for both parties printing the same secret.

Review gate: reveal correctness and no-output-on-abort.

### Phase 7: Integration And Fault Tests

- Two-daemon end-to-end tests.
- DB delete/rollback tests.
- Peer restart tests.
- Budget shrink/grow tests.
- Disable/re-enable tests.
- Evict-under-load tests.
- Reveal-while-background-precompute tests.
- Tamper/abort tests for foreground and background jobs.

Review gate: daemon is usable as a PoC service.

### Phase 8: Hardening

- Stronger local API hardening beyond the v1 loopback certificate and cookie.
- Production-quality secret input and memory handling.
- Schema migrations.
- Metrics endpoint.
- Backup/restore guidance.
- Human security review.

## Main Risks

1. **AG2PC session reuse and transport embedding.** The current protocol must be
   adapted to gRPC without changing cryptographic message ordering.
2. **Authenticated frontier persistence.** V1 avoids persisting unrevealed
   authenticated nodes. If later added, it must persist encrypted local Delta,
   epoch metadata, and budget counters, and it must never accept peer-mismatched
   epoch state.
3. **DB rollback vs external channel state.** A droppable DB is fine for cache
   state but dangerous for reveal sequence. The local API requires expected-index
   checks from day one.
4. **Budget accounting.** Conservative estimates are safe but may underutilize
   memory; aggressive estimates risk OOM. Start conservative and measure.
5. **Peer asymmetry.** Both sides may have different cache state. The protocol
   must routinely fall back to joint recomputation from a common authenticated
   ancestor or a revealed shachain ancestor.
6. **Operational security.** The master secret unlocks both DB and future
   channel shares. CLI input, logs, core dumps, and process memory all matter.
7. **Peer-budget griefing.** A peer can reduce liveness by advertising tiny
   RAM, worker, or precompute budgets. This should produce clear status and
   alerts, not silent stalls.

## First Concrete Step After Review

Start with Phase 0 and Phase 1 together:

1. Extract current party derivation logic into library APIs.
2. Define the transport trait.
3. Implement one-H authenticated job execution over the existing TCP transport.
4. Keep the current `party` binary as a thin compatibility wrapper.

This gives the daemon project a stable embeddable core before adding DB, gRPC,
or scheduling complexity.
