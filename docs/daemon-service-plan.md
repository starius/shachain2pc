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
- Persist only durable, droppable cache state. Losing or rolling back the DB must
  cause recomputation, not permanent protocol failure.
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

## Security Model

The current MPC protocol remains the cryptographic core. The daemon adds durable
state, scheduling, and control surfaces, so it must preserve these invariants:

- The local master secret is process memory only. It is provided at startup and
  zeroized on shutdown where possible.
- The encrypted DB key is derived from the master secret with domain separation.
- Channel seed shares are derived from the master secret with separate domain
  separation and do not depend on DB salt or mutable config.
- Cached nodes are authenticated MPC wire values or revealed shachain secrets
  allowed by normal shachain rules. Cached authenticated nodes are never converted
  into cleartext and re-input through normal private input.
- Revealed secrets are inserted into the local shachain store using standard
  shachain rules: at most one known value per level, and older derivable secrets
  can be answered locally.
- If a peer lacks an intermediate that we have, we must be able to discard ours
  and recompute from a common ancestor. Local cache asymmetry is not an error.
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
  next_reveal_index: u64,
  precompute_target: u64,
  local_budget_snapshot: Budget,
  peer_budget_snapshot: Option<Budget>,
  created_at,
  updated_at
}
```

`next_reveal_index` is the next secret that may be interactively revealed. Older
indices may be returned locally only if standard shachain derivability allows it
from known later secrets.

## Persistent State

The DB stores durable checkpoints, not required truth. Every table must be safe
to delete. The worst expected result is recomputation.

Suggested logical tables:

```text
meta(schema_version, db_salt, daemon_instance_id)
channels(channel_index, enabled, next_reveal_index, precompute_target, ...)
peer_configs(peer_id, last_seen_config, last_seen_at)
known_secrets(channel_index, level, index, secret_ciphertext, inserted_at)
auth_cache_nodes(channel_index, node_index, depth, metadata, encrypted_blob, ...)
jobs(job_id, channel_index, kind, priority, state, lease_epoch, ...)
job_events(job_id, event_no, event_type, payload, created_at)
```

`known_secrets` stores revealed shachain values, encrypted by the DB. It uses
standard shachain insertion constraints, not arbitrary append-only storage.

`auth_cache_nodes` stores cache nodes that are meaningful only to the current
daemon/MPC implementation. If deserialization fails after an upgrade, the node is
dropped and recomputed.

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
running `H`; already committed parents remain in the DB.

This satisfies the user-facing requirement of pausable/resumable work at the
cache level without pretending that the internal AG2PC transcript can be safely
snapshotted yet.

## gRPC Surfaces

There are two gRPC surfaces:

1. Peer API: daemon-to-daemon, authenticated and encrypted.
2. Local API: CLI-to-daemon, bound to localhost or a Unix domain socket.

Use `tonic` initially. For peer transport, use TLS/mTLS or Noise-style static
identity later. The first implementation may run with configured peer endpoints
and pinned public keys.

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

`JobStream` carries framed MPC messages plus job coordination frames:

```text
StartJob(job_id, channel_index, node, priority, transcript_digest)
MpcFrame(job_id, seq, bytes)
CancelJob(job_id, reason)
CommitJob(job_id, output_digest)
AbortJob(job_id, reason)
```

The peer protocol must be symmetric: either party can request work, but a job
starts only after both sides have accepted the same job descriptor.

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
  --peer https://peer.example:9000 \
  --max-ram-mb 1024 \
  --workers 2 \
  --precompute 1024

shachain-cli status
shachain-cli config set --max-ram-mb 512 --workers 1 --precompute 256
shachain-cli channel enable 42
shachain-cli channel disable 42
shachain-cli reveal 42
```

`channel enable 42` is idempotent. It creates or re-enables the channel locally.
Both parties must enable the same channel before background jobs run.

`reveal 42` reveals the next sequential secret for channel 42. It may return
locally if the requested value is derivable from already revealed shachain state.
Otherwise it schedules a foreground MPC job.

## Scheduler

The scheduler has two resource budgets:

```text
effective_ram_bytes = min(local_ram_bytes, peer_ram_bytes)
effective_workers   = min(local_workers, peer_workers)
effective_precompute = min(local_precompute, peer_precompute)
```

Budgets are exchanged on the peer `ConfigStream`. If peer config is missing,
background precompute is paused. Foreground reveal may still start if a fresh
peer config can be obtained during reveal setup.

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
- Completed parents/intermediates remain persisted.
- Cancelled jobs are safe to reschedule.
- If local and peer cache disagree, choose the deepest common durable ancestor
  and recompute from there.

Planning loop:

1. Read local config and last peer config.
2. Compute effective budgets.
3. For each enabled channel, compute desired frontier up to
   `effective_precompute`.
4. Generate candidate one-H jobs from missing cache edges.
5. Reserve RAM/workers for the highest-priority feasible jobs.
6. Start jobs through `JobStream`.
7. Commit outputs transactionally to DB.
8. Re-plan after each commit, cancel, config update, or reveal request.

RAM accounting starts conservative:

```text
one_hash_ram_estimate = measured_peak_for_one_H + safety_margin
job_ram = one_hash_ram_estimate
```

Then refine with measured per-job telemetry. The daemon should expose current
RSS, estimated reserved RAM, and peak observed RAM.

## Cache Algorithm, Version 1

Start with the simple per-edge cache:

- The root is the authenticated channel seed share combination.
- Each shachain edge is one MPC `H` application.
- A node is identified by `(channel_index, shachain_index_or_prefix, depth)`.
- The cache stores authenticated intermediate nodes.
- A disabled channel keeps DB state but does not schedule background work.
- Re-enabling uses existing nodes if both sides can agree on them; otherwise
  they are dropped and recomputed.

Reveal path:

1. Validate requested reveal is sequential or locally derivable from known later
   secrets.
2. If locally derivable, return without peer MPC.
3. Otherwise promote required path to foreground priority.
4. Compute missing one-H edges until the target authenticated node exists.
5. Run interactive reveal for exactly that secret.
6. Insert the clear revealed secret using shachain rules.
7. Return the same secret on both local CLIs.

This avoids batch reveal and preserves the current sequential channel-update
model.

## Idempotence And Crash Behavior

The daemon must treat every operation as restartable:

- `EnableChannel` can be retried safely.
- `DisableChannel` can be retried safely.
- `Reveal` with the same expected next index can be retried. If the secret was
  already revealed and inserted, return it from local shachain state.
- DB rollback may forget a reveal. This is dangerous unless the caller provides
  or checks the expected next index. The API should include an expected sequence
  field before production use:

```text
Reveal(channel_index, expected_next_reveal_index)
```

If the DB is older than the external channel state, the caller must restore the
expected next reveal index via control API before revealing. The daemon should
make this explicit in status output.

## Observability

Expose:

- peer connected/disconnected;
- negotiated budgets and precompute target;
- enabled/disabled channel count;
- per-channel next reveal index;
- known shachain levels;
- cache node count;
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
- Add authenticated cache node serialization.
- Add crash/reopen tests.
- Add DB deletion/rollback recomputation tests.

Review gate: DB is droppable and idempotent for cache state.

### Phase 3: Local Daemon And CLI API

- Add `shachain-daemon` process with local gRPC.
- Add `shachain-cli`.
- Implement status, config set, channel enable/disable, list channels/jobs.
- Keep peer/MPC mocked or in-process for this phase.

Review gate: local control plane is stable before peer networking.

### Phase 4: Peer gRPC And Budget Exchange

- Add peer identity/configuration.
- Add peer `Hello`, config stream, and job stream.
- Negotiate min RAM, workers, and precompute target.
- Add disconnect/reconnect behavior.

Review gate: two daemons can agree on config and reject mismatched job
descriptors.

### Phase 5: Scheduler And Background Precompute

- Implement priority queue.
- Implement RAM/worker budget reservation.
- Implement eviction/cancellation of background jobs.
- Implement cache-aware planning from deepest common node.
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

- Authentication and authorization for local API.
- Peer TLS/mTLS or pinned identity.
- Production-quality secret input and memory handling.
- Schema migrations.
- Metrics endpoint.
- Backup/restore guidance.
- Human security review.

## Main Risks

1. **AG2PC session reuse and transport embedding.** The current protocol must be
   adapted to gRPC without changing cryptographic message ordering.
2. **Persisting authenticated values.** Serialization must include enough
   versioning and metadata to reject stale or incompatible cache nodes.
3. **DB rollback vs external channel state.** A droppable DB is fine for cache
   state but dangerous for reveal sequence. The local API needs expected-index
   checks and clear status.
4. **Budget accounting.** Conservative estimates are safe but may underutilize
   memory; aggressive estimates risk OOM. Start conservative and measure.
5. **Peer asymmetry.** Both sides may have different cache state. The protocol
   must routinely fall back to recomputation from a common ancestor.
6. **Operational security.** The master secret unlocks both DB and future
   channel shares. CLI input, logs, core dumps, and process memory all matter.

## First Concrete Step After Review

Start with Phase 0 and Phase 1 together:

1. Extract current party derivation logic into library APIs.
2. Define the transport trait.
3. Implement one-H authenticated job execution over the existing TCP transport.
4. Keep the current `party` binary as a thin compatibility wrapper.

This gives the daemon project a stable embeddable core before adding DB, gRPC,
or scheduling complexity.
