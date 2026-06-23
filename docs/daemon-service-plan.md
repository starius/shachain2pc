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
- Persist unrevealed authenticated precompute encrypted in the DB so the
  precomputed frontier survives daemon restarts.
- Use one fixed local Delta per channel, derived from the master secret. Do not
  rotate Delta in the first daemon design.
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
- Do not persist cleartext future shachain secrets. Unrevealed frontier state is
  authenticated MPC state, not a revealed secret.
- Do not make any MPC randomness deterministic except the local per-channel
  Delta. OT, garbling, leaky-AND, preprocessing, and per-job randomness must stay
  fresh on every computation.

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
- The local per-channel Delta is derived from the master secret with its own
  domain separation. It is fixed for the channel lifetime.
- Cached state is split into two classes:
  - revealed shachain secrets, which are durable DB state and are governed by
    normal shachain rules;
  - unrevealed authenticated frontier nodes, which are tied to the fixed
    per-channel Delta and are stored encrypted in the DB only when they are
    exact revealable target leaves.
- Session-local labeled trunk/intermediate nodes are RAM-only. A live
  per-channel session may keep at most one labeled node per shachain layer for
  in-process extension, but those labels and intermediates are not persisted and
  are discarded on restart.
- Unrevealed authenticated nodes are never converted into cleartext and re-input
  through normal private input.
- Persisted authenticated nodes are valid only with the same channel, role,
  protocol version, circuit digest, local Delta derivation, and peer job
  descriptor. If any binding does not match, both parties discard the node and
  recompute.
- Revealed secrets are inserted into the local shachain store using standard
  shachain rules: at most one known value per level, and older derivable secrets
  can be answered locally.
- If a peer lacks a durable target leaf that we have, we discard ours and
  jointly recompute it. Local cache asymmetry is not an error, but unilateral
  catch-up is not possible for authenticated nodes because fresh randomness will
  not recreate the same node.
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
DB-key derivation hygiene. It must not affect channel seed shares or channel
Delta, otherwise deleting the DB would change channel behavior.

Open decision for implementation: whether to use SQLCipher (`rusqlite` +
SQLCipher) or an application-level encrypted store. SQLCipher is the most direct
fit for indexed durable state and crash-safe transactions. Application-level AEAD
over `redb`/`sled` is also possible but creates more footguns around indexing and
partial writes. Prefer SQLCipher unless build constraints become painful.

## Fixed Delta And Authenticated Frontier State

Authenticated MPC values are bound to the local Delta used for their channel.
The daemon uses one fixed local Delta per channel for the channel lifetime. This
is a deliberate simplification: the statistical-security budget is sized for a
lifetime cap far above realistic channel use, so Delta rotation is not needed in
the first design.

Derived Delta:

```text
channel_delta(channel_index, party_role) = HKDF-SHA256(
    ikm  = master_secret,
    salt = empty or deployment salt,
    info = "shachain2pc channel delta v1" ||
           encode(channel_index) ||
           encode(party_role)
)
```

After derivation, apply the structural bit constraints required by the MPC
protocol, such as the required low bit. The daemon never stores or receives the
peer's Delta.

The safety rule that replaces rotation is static lifetime sizing:

```text
ssp_effective = ssp_target + ceil_log2(delta_lifetime_checked_units_cap)
```

`delta_lifetime_checked_units_cap` is a conservative upper bound for all checked
work under one channel Delta. It must count every checked unit consumed under
that Delta, including work repeated after restart, DB rollback, crash loops, and
cache rewarm. The implementation must define the checked unit according to the
AG2PC bucket/security formula before funds-facing use; back-of-envelope
"number of commitments" is not sufficient.

Because the surcharge is logarithmic, the cap can be orders of magnitude above a
realistic channel lifetime. The intended configuration should make exhausting
the cap infeasible in practice. A best-effort cumulative counter is still useful
as monitoring and should alert on abnormal rewarm or crash-loop activity, but
the counter is not the safety mechanism. Safety comes from the static cap used
to size `ssp_effective`.

Determinism applies only to Delta. Every computation still uses fresh OT,
garbling, leaky-AND, preprocessing, and per-job randomness. Reusing any of that
randomness to make authenticated nodes "recomputable" would be a protocol break.

Persisted authenticated frontier nodes are encrypted under the DB key and bound
to:

- channel index and optional external channel id;
- party role;
- protocol version;
- circuit digest;
- local fixed-Delta derivation version;
- node index/depth;
- peer identity and job descriptor digest;
- security parameter and lifetime cap.

On restart, the daemon re-derives the local Delta from the master secret and can
resume from persisted authenticated nodes whose bindings still match. If either
party lacks a node, or if the bindings disagree, both parties discard that node
and its descendants and jointly recompute from the deepest common authenticated
ancestor. If no authenticated ancestor is common, they recompute from the channel
seed share.

Persisting the frontier is also good for the Delta lifetime budget: a normal
restart resumes existing authenticated nodes and does not spend new checked
units. Only DB loss, DB rollback, binding mismatch, or peer asymmetry forces
rewarm work that consumes more checked units under the same Delta.

Both parties must agree on the public security parameters for a channel,
including `ssp_target`, `ssp_effective`, and
`delta_lifetime_checked_units_cap`. These values are included in job descriptors
and frontier binding digests. Mismatch means refuse the job or drop the cached
node and recompute under the agreed parameters.

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
  ssp_target: u32,
  delta_lifetime_checked_units_cap: u64,
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

The DB stores durable checkpoints and encrypted local state, not authoritative
channel truth. Every table must be safe to delete. The worst expected result is
lost precompute and recomputation.

Suggested logical tables:

```text
meta(schema_version, db_salt, daemon_instance_id)
channels(channel_index, enabled, last_observed_next_reveal_index,
         precompute_target, ssp_target, delta_lifetime_checked_units_cap, ...)
peer_configs(peer_id, last_seen_config, last_seen_at)
known_secrets(channel_index, level, index, secret_ciphertext, inserted_at)
frontier_nodes(channel_index, node_index, depth, binding_digest,
               encrypted_blob, created_at, ...)
delta_budget_monitor(channel_index, estimated_checked_units, updated_at)
jobs(job_id, channel_index, kind, priority, state, lease_epoch, ...)
job_events(job_id, event_no, event_type, payload, created_at)
```

`known_secrets` stores revealed shachain values, encrypted by the DB. It uses
standard shachain insertion constraints, not arbitrary append-only storage.
Known secrets can answer older derivable reveals in their own subtree, but they
cannot rebuild the upstream trunk or authenticated frontier because shachain `H`
is one-way.

`frontier_nodes` stores unrevealed authenticated nodes encrypted under `db_key`.
The plaintext is never a clear shachain secret; it is the local authenticated
MPC representation required to continue computing from that node under the fixed
per-channel Delta. Every node carries a binding digest. Binding mismatch means
drop and recompute, not best-effort repair.

`delta_budget_monitor` is a best-effort operational counter. It helps detect
abnormal repeated recomputation under the same channel Delta, but it is not
trusted for safety because the DB can be deleted or rolled back.

`jobs` are persisted only for operator visibility and crash cleanup. On daemon
restart, in-flight MPC jobs are not resumed mid-message in the first version;
they are marked abandoned and recomputed from the latest matching frontier node
or from the channel seed share.

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
running `H`; already committed unrevealed parents remain in the encrypted
frontier, and revealed parents remain in the DB.

This satisfies the user-facing requirement of pausable/resumable work at the
cache level without pretending that the internal AG2PC transcript can be safely
snapshotted yet.

## gRPC Surfaces

There are two gRPC surfaces:

1. Peer API: daemon-to-daemon, authenticated and encrypted.
2. Local API: CLI-to-daemon, bound to loopback TCP in the first version.

Use `tonic` initially. The implemented peer transport supports mTLS with a
configured local identity, CA root, and expected peer DNS name. Unix domain
sockets and Windows named pipes are deliberately deferred to avoid
platform-specific transport work in the first daemon version. The daemon keeps
one reusable tonic channel to its peer and clones it for RPCs. Tonic clones
share the underlying HTTP/2 connection, so frontier queries and each channel
session's `main`/`sibling` JobStream pair multiplex over one peer connection
instead of reconnecting per operation.

### Peer API

```proto
service PeerService {
  rpc Hello(HelloRequest) returns (HelloResponse);
  rpc ConfigStream(stream ConfigUpdate) returns (stream ConfigUpdate);
  rpc JobStream(stream JobFrame) returns (stream JobFrame);
}
```

`Hello` negotiates protocol versions, daemon identity, and supported features.

`ConfigStream` exchanges live budgets and precompute settings:

```text
ram_budget_bytes
worker_budget
precompute_target
ssp_target
delta_lifetime_checked_units_cap
enabled_channels summary/version
protocol_version
```

`JobStream` carries framed MPC messages plus job coordination frames. Use one
pair of bidirectional streams per live channel precompute session: one stream
for AG2PC `main` and one for `sibling`. Target indices are sent as
authenticated in-band commands over the live session. Do not multiplex the
AG2PC `main` and `sibling` logical channels onto one ordered stream, because
opposite-direction AG2PC traffic can block behind stream-level ordering and
undermine progress.

```text
StartJob(job_id, channel_index, node, priority, transcript_digest)
MpcFrame(job_id, seq, bytes)
CancelJob(job_id, reason)
CommitJob(job_id, output_digest)
AbortJob(job_id, reason)
```

The peer protocol must be symmetric: either party can request work, but a job
starts only after both sides have accepted the same job descriptor. The
descriptor includes the circuit digest, node id, peer identity, `ssp_target`,
`ssp_effective`, and `delta_lifetime_checked_units_cap`.

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
- Completed revealed secrets remain persisted. Completed unrevealed target
  leaves remain persisted in the encrypted frontier. Session-local
  trunk/intermediate nodes stay in RAM only.
- Cancelled jobs are safe to reschedule.
- If local and peer authenticated frontier state disagrees, both parties choose
  the deepest common authenticated ancestor with matching bindings and jointly
  recompute from there. If no authenticated ancestor is common, they recompute
  from the channel seed share. Revealed leaves are still useful for local older
  reveals, but they generally do not reconstruct upstream frontier state.

Planning loop:

1. Read local config and last peer config.
2. Compute effective budgets.
3. For each enabled channel, compute desired frontier up to
   `effective_precompute`.
4. Generate candidate one-H jobs from missing cache edges.
5. Reserve RAM/workers for the highest-priority feasible target.
6. Start or reuse the channel's live precompute session through `JobStream`.
7. Commit unrevealed outputs transactionally to the encrypted frontier, and
   commit any revealed outputs transactionally to DB.
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
- The encrypted frontier stores unrevealed authenticated intermediate nodes.
- The DB stores revealed secrets, authenticated frontier nodes, and metadata.
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
- encrypted frontier/cache node count;
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
- Make the local Delta an explicit session input so the same channel Delta can
  be reused after daemon restart while all other MPC randomness stays fresh.
- Add deterministic job descriptors and transcript digests.
- Add cancellation at job boundaries.
- Add tests for one-H correctness, abort, and recomputation from parent.

Review gate: one-H jobs are embeddable and serializable at boundaries, and a
persisted authenticated parent can be loaded into a fresh session with the same
local Delta and fresh preprocessing randomness.

### Phase 2: Encrypted DB And Shachain Store

- Add encrypted DB setup and key derivation.
- Add channel records.
- Add known-secret shachain insertion/derivation.
- Add fixed-Delta derivation and security-budget sizing.
- Add authenticated frontier node serialization, encryption, and binding
  validation.
- Add exact checked-unit accounting for the configured
  `delta_lifetime_checked_units_cap`.
- Add crash/reopen tests.
- Add DB deletion/rollback recomputation tests.

Review gate: DB is droppable for correctness, encrypted frontier survives normal
restart, revealed-secret storage is consistent with shachain rules, and reveal
APIs require caller-supplied expected indices.

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
- Agree on public channel security parameters, including `ssp_target` and
  `delta_lifetime_checked_units_cap`.
- Add disconnect/reconnect behavior.

Review gate: two daemons can agree on config and reject mismatched job
descriptors.

### Phase 5: Scheduler And Background Precompute

- Implement priority queue.
- Implement RAM/worker budget reservation.
- Implement eviction/cancellation of background jobs.
- Implement cache-aware planning from the live session cache and the common
  durable target-leaf subset.
- Implement fixed-Delta checked-unit monitoring and alerts.
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
2. **Restart re-warm.** Persisted unrevealed target leaves are revealable after
   restart, but they are not used as computation parents because labels and
   one-time protocol randomness are intentionally not persisted. Extending after
   restart starts a fresh session and re-warms from the seed.
3. **Deterministic Delta misuse.** Only Delta is deterministic. Reusing any OT,
   garbling, leaky-AND, preprocessing, or per-job randomness across runs would
   be a serious protocol break.
4. **Lifetime budget sizing.** No Delta rotation means the static
   `delta_lifetime_checked_units_cap` must be extremely conservative and must
   count repeated work from restart, rollback, and crash-loop rewarm. The DB
   counter is monitoring only, not a safety boundary.
5. **DB rollback vs external channel state.** A droppable DB is fine for cache
   state but dangerous for reveal sequence. The local API requires expected-index
   checks from day one.
6. **RAM budget accounting.** Conservative estimates are safe but may underutilize
   memory; aggressive estimates risk OOM. Start conservative and measure.
7. **Peer asymmetry.** Both sides may have different cache state. The protocol
   must routinely fall back to joint recomputation from a common authenticated
   ancestor or a revealed shachain ancestor.
8. **Operational security.** The master secret unlocks both DB and future
   channel shares. CLI input, logs, core dumps, and process memory all matter.
9. **Peer-budget griefing.** A peer can reduce liveness by advertising tiny
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
