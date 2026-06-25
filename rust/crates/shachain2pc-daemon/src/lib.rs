pub mod pb {
    tonic::include_proto!("shachain2pc.daemon.v1");
}

use hmac::{Hmac, Mac};
use openssl::rand::rand_bytes;
use openssl::symm::{decrypt_aead, encrypt_aead, Cipher};
use pb::control_service_server::{ControlService, ControlServiceServer};
use pb::peer_service_server::{PeerService, PeerServiceServer};
use redb::{Database, Durability, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shachain2pc_circuit::{generate_from_seed, sha256_compress_gadget, Circuit};
use shachain2pc_emp_compat::{
    normalize_ag2pc_delta, AShareBundle, Ag2pcSecureWires, HASH_DIGEST_BYTES,
};
use shachain2pc_emp_wire::{Ag2pcStreams, Block, ByteIo, ChannelByteStream, BLOCK_BYTES};
use shachain2pc_mpc_runner::{
    run_session_handshake, ByteFrameTransport, RunnerSessionParams, TransportPair,
};
use shachain2pc_party::{
    reveal_node_fast_job, reveal_node_from_peer_share, reveal_node_local_share, run_party,
    run_seed_root_job_with_circuit, Args as PartyArgs, IndexSpec, MpcTcpEndpoint, PartyOutput,
    PrecomputeSession,
};
use shachain2pc_types::{Index48, Role, Value32, INDEX_BITS, MAX_INDEX};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Mutex, Notify};
use tokio::task::AbortHandle;
use tokio::time::{sleep, timeout, Duration};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{
    Certificate, Channel, ClientTlsConfig, Endpoint, Identity, Server, ServerTlsConfig,
};
use tonic::{Request, Response, Status, Streaming};
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

const DB_MAGIC: &[u8; 8] = b"S2PCDB1\0";
const DB_AAD: &[u8] = b"shachain2pc daemon db v1";
const DB_SALT_LEN: usize = 32;
const DB_NONCE_LEN: usize = 12;
const DB_TAG_LEN: usize = 16;
const REDB_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("r");
const REDB_META_VERIFIER: &[u8] = b"shachain2pc daemon redb verifier v1";
const RECORD_META: u8 = 0;
const RECORD_CHANNEL: u8 = 1;
const RECORD_SECRET: u8 = 2;
const RECORD_FRONTIER: u8 = 3;
const DEFAULT_SSP_TARGET: u32 = 40;
const DEFAULT_DELTA_CAP: u64 = 1u64 << 32;
const PROTOCOL_VERSION: u32 = 1;
const JOBSTREAM_SESSION_BINDING_DOMAIN: &[u8] = b"shachain2pc daemon JobStream precompute v1";
const MIB: u64 = 1024 * 1024;
const DEFAULT_ONE_H_WORKER_PEAK_RSS_BYTES: u64 = 192 * MIB;
const DEFAULT_IDLE_SESSION_RSS_BYTES: u64 = MIB;
const DEFAULT_PEER_REVEAL_WAIT: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub enum DaemonError {
    Usage(String),
    Io(std::io::Error),
    Crypto(String),
    Json(serde_json::Error),
    TonicTransport(tonic::transport::Error),
    TonicStatus(Box<Status>),
    Parse(String),
    NotFound(String),
    Refused(String),
    Party(shachain2pc_party::PartyError),
}

impl fmt::Display for DaemonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(msg)
            | Self::Crypto(msg)
            | Self::Parse(msg)
            | Self::NotFound(msg)
            | Self::Refused(msg) => f.write_str(msg),
            Self::Io(e) => write!(f, "{e}"),
            Self::Json(e) => write!(f, "{e}"),
            Self::TonicTransport(e) => write!(f, "{e}"),
            Self::TonicStatus(e) => write!(f, "{e}"),
            Self::Party(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for DaemonError {}

impl From<std::io::Error> for DaemonError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for DaemonError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl From<tonic::transport::Error> for DaemonError {
    fn from(value: tonic::transport::Error) -> Self {
        Self::TonicTransport(value)
    }
}

impl From<Status> for DaemonError {
    fn from(value: Status) -> Self {
        Self::TonicStatus(Box::new(value))
    }
}

impl From<shachain2pc_party::PartyError> for DaemonError {
    fn from(value: shachain2pc_party::PartyError) -> Self {
        Self::Party(value)
    }
}

impl From<shachain2pc_emp_wire::WireError> for DaemonError {
    fn from(value: shachain2pc_emp_wire::WireError) -> Self {
        Self::Party(shachain2pc_party::PartyError::Wire(value))
    }
}

pub type Result<T> = std::result::Result<T, DaemonError>;

#[derive(Clone, Debug)]
pub struct DaemonConfig {
    pub role: Role,
    pub db_path: PathBuf,
    pub control_addr: SocketAddr,
    pub peer_addr: SocketAddr,
    pub peer_url: Option<String>,
    pub peer_tls: Option<PeerTlsConfig>,
    pub mpc_port: u16,
    pub max_ram_bytes: u64,
    pub workers: u32,
    pub precompute: u64,
    pub control_file: Option<PathBuf>,
    pub cookie_file: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct PeerTlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub ca_path: PathBuf,
    pub domain_name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ControlFile {
    pub addr: String,
    pub cookie_path: String,
}

#[derive(Clone)]
pub struct DaemonHandle {
    state: DaemonState,
}

impl DaemonHandle {
    pub fn state(&self) -> DaemonState {
        self.state.clone()
    }
}

#[derive(Clone)]
pub struct DaemonState {
    inner: Arc<Mutex<Inner>>,
    db_writer: DbWriter,
    grpc_jobs: Arc<Mutex<BTreeMap<String, PendingGrpcJob>>>,
    pending_reveals: Arc<Mutex<BTreeMap<RevealRequestKey, PendingReveal>>>,
    pending_reveal_notify: Arc<Notify>,
    precompute_sessions: Arc<Mutex<BTreeMap<u64, PrecomputeSessionHandle>>>,
    incoming_precompute_sessions: Arc<Mutex<BTreeMap<u64, AbortHandle>>>,
    peer_channel: Option<Channel>,
    sha: Arc<Circuit>,
}

struct Inner {
    cfg: DaemonConfig,
    master_secret: SecretBytes,
    cookie: String,
    db: PlainDb,
    active_jobs: BTreeMap<String, JobRecord>,
    next_job_id: u64,
    baseline_daemon_rss_bytes: u64,
}

struct SecretBytes(Vec<u8>);

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct PlainDb {
    channels: BTreeMap<String, ChannelRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ChannelScalars {
    enabled: bool,
    last_observed_next_reveal_index: Option<u64>,
    precompute_target: u64,
    ssp_target: u32,
    delta_lifetime_checked_units_cap: u64,
    estimated_checked_units: u64,
    attempted_checked_units: u64,
    failed_precompute_jobs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredRecord {
    record_type: u8,
    channel_index: u64,
    sub_id: u64,
    payload: StoredPayload,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum StoredPayload {
    Meta { verifier_hex: String },
    Channel(ChannelScalars),
    Secret { secret_hex: String },
    Frontier(WireRecord),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ChannelRecord {
    enabled: bool,
    last_observed_next_reveal_index: Option<u64>,
    precompute_target: u64,
    ssp_target: u32,
    delta_lifetime_checked_units_cap: u64,
    frontier_nodes: BTreeMap<String, WireRecord>,
    known_secrets: BTreeMap<String, String>,
    estimated_checked_units: u64,
    #[serde(default)]
    attempted_checked_units: u64,
    #[serde(default)]
    failed_precompute_jobs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WireRecord {
    public_binding_hex: String,
    local_binding_hex: String,
    wires: SerializableWires,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SerializableWires {
    lambda: Vec<u8>,
    mac: Vec<[u8; BLOCK_BYTES]>,
    key: Vec<[u8; BLOCK_BYTES]>,
}

#[derive(Clone, Debug)]
struct JobRecord {
    channel_index: u64,
    kind: String,
    state: String,
    planned_checked_units: u64,
}

#[derive(Clone, Copy, Debug)]
struct PeerFrontierConfig {
    channel_enabled: bool,
    precompute: u64,
    workers: u32,
    effective_workers: u32,
    ram_limited_workers_raw: u32,
    ram_overcommit_warning: bool,
    ssp_target: u32,
    delta_lifetime_checked_units_cap: u64,
}

#[derive(Clone, Copy, Debug)]
struct ResourceModel {
    configured_workers: u32,
    effective_workers: u32,
    ram_limited_workers_raw: u32,
    ram_overcommit_warning: bool,
    baseline_daemon_rss_bytes: u64,
    current_rss_bytes: u64,
    idle_session_rss_estimate_bytes: u64,
    one_h_worker_peak_rss_estimate_bytes: u64,
    live_session_count: u64,
    reserved_ram_bytes: u64,
}

struct PrecomputeJob {
    job_id: String,
    planned_checked_units: u64,
}

struct IncomingPrecomputeJob {
    job_id: String,
}

struct IncomingPrecomputeSession {
    delta: Block,
    ssp: usize,
    share: Value32,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RevealRequestKey {
    channel_index: u64,
    requested_index: u64,
    expected_next_index: u64,
    allow_seed_reveal: bool,
}

struct PendingReveal {
    response: oneshot::Sender<Result<Value32>>,
}

enum PrecomputeStart {
    AlreadyStored,
    Run(PrecomputeJob),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GrpcJobDescriptor {
    job_id: String,
    channel_index: u64,
    target_index: u64,
    ssp: u32,
    ssp_target: u32,
    delta_lifetime_checked_units_cap: u64,
    digest: [u8; 32],
}

struct PendingGrpcJob {
    descriptor: GrpcJobDescriptor,
    main: Option<ChannelByteStream>,
    sibling: Option<ChannelByteStream>,
}

#[derive(Clone)]
struct PrecomputeSessionHandle {
    tx: mpsc::Sender<PrecomputeSessionCommand>,
}

enum PrecomputeSessionCommand {
    Plan {
        index: Index48,
        response: oneshot::Sender<Result<u64>>,
    },
    Precompute {
        index: Index48,
        response: oneshot::Sender<Result<Ag2pcSecureWires>>,
    },
}

#[derive(Clone)]
struct DbWriter {
    tx: mpsc::Sender<WriteOp>,
}

enum WriteOp {
    Batch {
        mutations: Vec<Mutation>,
        durability: DbDurability,
    },
    Flush {
        ack: oneshot::Sender<Result<()>>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DbDurability {
    Eventual,
    Immediate,
}

#[derive(Clone, Debug)]
enum Mutation {
    Upsert {
        key: LogicalKey,
        record: StoredRecord,
    },
    Delete {
        key: LogicalKey,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LogicalKey {
    record_type: u8,
    channel_index: u64,
    sub_id: u64,
}

struct DbStore;

impl DbStore {
    fn open(path: PathBuf, master_secret: &[u8]) -> Result<(PlainDb, DbWriter)> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        if is_legacy_db_file(&path)? {
            let legacy = read_legacy_db(&path, master_secret)?;
            let migrated = path.with_extension(format!(
                "{}.migrated",
                path.extension()
                    .and_then(|ext| ext.to_str())
                    .unwrap_or("db")
            ));
            fs::rename(&path, migrated)?;
            migrate_legacy_db(&path, master_secret, &legacy)?;
            return Self::open(path, master_secret);
        }

        let subkeys = DbSubkeys::derive(master_secret);
        let database = if path.exists() {
            Database::open(&path).map_err(redb_error)?
        } else {
            Database::create(&path).map_err(redb_error)?
        };
        ensure_meta_record(&database, &subkeys)?;
        let db = load_redb_state(&database, &subkeys)?;
        let writer = spawn_db_writer(database, subkeys);
        Ok((db, writer))
    }
}

#[derive(Clone)]
struct DbSubkeys {
    key_prf: [u8; 32],
    value_aead: [u8; 32],
}

impl DbSubkeys {
    fn derive(master_secret: &[u8]) -> Self {
        let mut key_prf = [0u8; 32];
        let mut value_aead = [0u8; 32];
        hkdf_expand(master_secret, b"", b"shachain-db-key-prf-v1", &mut key_prf);
        hkdf_expand(
            master_secret,
            b"",
            b"shachain-db-value-aead-v1",
            &mut value_aead,
        );
        Self {
            key_prf,
            value_aead,
        }
    }
}

impl DbWriter {
    async fn write_batch(&self, mutations: Vec<Mutation>, durability: DbDurability) -> Result<()> {
        if mutations.is_empty() {
            return Ok(());
        }
        let op = WriteOp::Batch {
            mutations,
            durability,
        };
        match self.tx.try_send(op) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(op)) => {
                eprintln!("WARNING: DB writer queue is full; waiting for enqueue");
                self.tx
                    .send(op)
                    .await
                    .map_err(|_| DaemonError::Crypto("DB writer stopped".to_owned()))
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Err(DaemonError::Crypto("DB writer stopped".to_owned()))
            }
        }
    }

    async fn flush(&self) -> Result<()> {
        let (ack, rx) = oneshot::channel();
        self.tx
            .send(WriteOp::Flush { ack })
            .await
            .map_err(|_| DaemonError::Crypto("DB writer stopped".to_owned()))?;
        rx.await
            .map_err(|_| DaemonError::Crypto("DB writer stopped".to_owned()))?
    }
}

fn spawn_db_writer(database: Database, subkeys: DbSubkeys) -> DbWriter {
    let (tx, mut rx) = mpsc::channel(16_384);
    let database = Arc::new(database);
    tokio::spawn(async move {
        while let Some(first) = rx.recv().await {
            let mut mutations = Vec::new();
            let mut acks = Vec::new();
            let mut durability = DbDurability::Eventual;
            collect_write_op(first, &mut mutations, &mut acks, &mut durability);
            while let Ok(op) = rx.try_recv() {
                collect_write_op(op, &mut mutations, &mut acks, &mut durability);
            }
            let result = if mutations.is_empty() && acks.is_empty() {
                Ok(())
            } else {
                let database = Arc::clone(&database);
                let subkeys = subkeys.clone();
                tokio::task::spawn_blocking(move || {
                    apply_mutations(&database, &subkeys, mutations, durability)
                })
                .await
                .map_err(|e| DaemonError::Crypto(format!("DB writer task failed: {e}")))
                .and_then(|inner| inner)
            };
            if let Err(err) = result {
                let msg = err.to_string();
                for ack in acks {
                    let _ = ack.send(Err(DaemonError::Crypto(msg.clone())));
                }
                eprintln!("WARNING: DB writer failed: {err}");
            } else {
                for ack in acks {
                    let _ = ack.send(Ok(()));
                }
            }
        }
    });
    DbWriter { tx }
}

fn collect_write_op(
    op: WriteOp,
    mutations: &mut Vec<Mutation>,
    acks: &mut Vec<oneshot::Sender<Result<()>>>,
    durability: &mut DbDurability,
) {
    match op {
        WriteOp::Batch {
            mutations: batch,
            durability: batch_durability,
        } => {
            mutations.extend(batch);
            if batch_durability == DbDurability::Immediate {
                *durability = DbDurability::Immediate;
            }
        }
        WriteOp::Flush { ack } => {
            *durability = DbDurability::Immediate;
            acks.push(ack);
        }
    }
}

fn apply_mutations(
    database: &Database,
    subkeys: &DbSubkeys,
    mutations: Vec<Mutation>,
    durability: DbDurability,
) -> Result<()> {
    let mut write = database.begin_write().map_err(redb_error)?;
    write.set_durability(match durability {
        DbDurability::Eventual => Durability::Eventual,
        DbDurability::Immediate => Durability::Immediate,
    });
    {
        let mut table = write.open_table(REDB_TABLE).map_err(redb_error)?;
        for mutation in mutations {
            match mutation {
                Mutation::Upsert { key, record } => {
                    let stored_key = stored_key(subkeys, key);
                    let value = encrypt_stored_record(subkeys, &stored_key, &record)?;
                    table
                        .insert(stored_key.as_slice(), value.as_slice())
                        .map_err(redb_error)?;
                }
                Mutation::Delete { key } => {
                    let stored_key = stored_key(subkeys, key);
                    table.remove(stored_key.as_slice()).map_err(redb_error)?;
                }
            }
        }
    }
    write.commit().map_err(redb_error)
}

fn ensure_meta_record(database: &Database, subkeys: &DbSubkeys) -> Result<()> {
    let mut write = database.begin_write().map_err(redb_error)?;
    write.set_durability(Durability::Immediate);
    let key = LogicalKey::meta();
    let stored_key = stored_key(subkeys, key);
    {
        let mut table = write.open_table(REDB_TABLE).map_err(redb_error)?;
        let existing = table
            .get(stored_key.as_slice())
            .map_err(redb_error)?
            .map(|value| value.value().to_vec());
        if let Some(value) = existing {
            let record = decrypt_stored_record(subkeys, &stored_key, &value)?;
            validate_meta_record(&record)?;
        } else {
            let record = StoredRecord {
                record_type: RECORD_META,
                channel_index: 0,
                sub_id: 0,
                payload: StoredPayload::Meta {
                    verifier_hex: to_hex(REDB_META_VERIFIER),
                },
            };
            let value = encrypt_stored_record(subkeys, &stored_key, &record)?;
            table
                .insert(stored_key.as_slice(), value.as_slice())
                .map_err(redb_error)?;
        }
    }
    write.commit().map_err(redb_error)
}

fn load_redb_state(database: &Database, subkeys: &DbSubkeys) -> Result<PlainDb> {
    let read = database.begin_read().map_err(redb_error)?;
    let table = read.open_table(REDB_TABLE).map_err(redb_error)?;
    let mut db = PlainDb::default();
    for item in table.iter().map_err(redb_error)? {
        let (key, value) = item.map_err(redb_error)?;
        let key = key.value().to_vec();
        let record = decrypt_stored_record(subkeys, &key, value.value())?;
        apply_stored_record(&mut db, record)?;
    }
    Ok(db)
}

fn apply_stored_record(db: &mut PlainDb, record: StoredRecord) -> Result<()> {
    match &record.payload {
        StoredPayload::Meta { .. } => validate_meta_record(&record),
        StoredPayload::Channel(scalars) => {
            if record.record_type != RECORD_CHANNEL || record.sub_id != 0 {
                return Err(DaemonError::Crypto(
                    "stored channel record has a bad logical key".to_owned(),
                ));
            }
            let channel = db
                .channels
                .entry(channel_key(record.channel_index))
                .or_insert_with(empty_channel_record);
            channel.apply_scalars(scalars.clone());
            Ok(())
        }
        StoredPayload::Secret { secret_hex } => {
            if record.record_type != RECORD_SECRET {
                return Err(DaemonError::Crypto(
                    "stored secret record has a bad logical key".to_owned(),
                ));
            }
            let channel = db
                .channels
                .entry(channel_key(record.channel_index))
                .or_insert_with(empty_channel_record);
            channel
                .known_secrets
                .insert(record.sub_id.to_string(), secret_hex.clone());
            Ok(())
        }
        StoredPayload::Frontier(wire) => {
            if record.record_type != RECORD_FRONTIER {
                return Err(DaemonError::Crypto(
                    "stored frontier record has a bad logical key".to_owned(),
                ));
            }
            let channel = db
                .channels
                .entry(channel_key(record.channel_index))
                .or_insert_with(empty_channel_record);
            channel
                .frontier_nodes
                .insert(record.sub_id.to_string(), wire.clone());
            Ok(())
        }
    }
}

fn validate_meta_record(record: &StoredRecord) -> Result<()> {
    match &record.payload {
        StoredPayload::Meta { verifier_hex }
            if record.record_type == RECORD_META
                && record.channel_index == 0
                && record.sub_id == 0
                && verifier_hex == &to_hex(REDB_META_VERIFIER) =>
        {
            Ok(())
        }
        _ => Err(DaemonError::Crypto(
            "encrypted DB verifier record is invalid".to_owned(),
        )),
    }
}

fn encrypt_stored_record(
    subkeys: &DbSubkeys,
    stored_key: &[u8; 32],
    record: &StoredRecord,
) -> Result<Vec<u8>> {
    let plaintext = serde_json::to_vec(record)?;
    let mut nonce = [0u8; DB_NONCE_LEN];
    let mut tag = [0u8; DB_TAG_LEN];
    rand_bytes(&mut nonce).map_err(|e| DaemonError::Crypto(e.to_string()))?;
    let ciphertext = encrypt_aead(
        Cipher::aes_256_gcm(),
        &subkeys.value_aead,
        Some(&nonce),
        stored_key,
        &plaintext,
        &mut tag,
    )
    .map_err(|e| DaemonError::Crypto(e.to_string()))?;
    let mut out = Vec::with_capacity(DB_NONCE_LEN + DB_TAG_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&tag);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn decrypt_stored_record(
    subkeys: &DbSubkeys,
    stored_key: &[u8],
    value: &[u8],
) -> Result<StoredRecord> {
    if stored_key.len() != 32 {
        return Err(DaemonError::Crypto(
            "encrypted DB stored key has a bad length".to_owned(),
        ));
    }
    if value.len() < DB_NONCE_LEN + DB_TAG_LEN {
        return Err(DaemonError::Crypto(
            "encrypted DB value is truncated".to_owned(),
        ));
    }
    let nonce: [u8; DB_NONCE_LEN] = value[..DB_NONCE_LEN]
        .try_into()
        .expect("nonce length checked");
    let tag: [u8; DB_TAG_LEN] = value[DB_NONCE_LEN..DB_NONCE_LEN + DB_TAG_LEN]
        .try_into()
        .expect("tag length checked");
    let ciphertext = &value[DB_NONCE_LEN + DB_TAG_LEN..];
    let plaintext = decrypt_aead(
        Cipher::aes_256_gcm(),
        &subkeys.value_aead,
        Some(&nonce),
        stored_key,
        ciphertext,
        &tag,
    )
    .map_err(|e| DaemonError::Crypto(e.to_string()))?;
    Ok(serde_json::from_slice(&plaintext)?)
}

fn stored_key(subkeys: &DbSubkeys, key: LogicalKey) -> [u8; 32] {
    // Deterministic HMAC keys keep records addressable while hiding channel
    // ids and indices. The store still leaks record count and update pattern.
    hmac_sha256(&subkeys.key_prf, &key.canonical_bytes())
}

fn is_legacy_db_file(path: &Path) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let bytes = fs::read(path)?;
    Ok(bytes.starts_with(DB_MAGIC))
}

fn read_legacy_db(path: &Path, master_secret: &[u8]) -> Result<PlainDb> {
    let bytes = fs::read(path)?;
    if bytes.len() < DB_MAGIC.len() + DB_SALT_LEN + DB_NONCE_LEN + DB_TAG_LEN
        || &bytes[..DB_MAGIC.len()] != DB_MAGIC
    {
        return Err(DaemonError::Crypto(
            "legacy encrypted DB has an invalid header".to_owned(),
        ));
    }
    let mut cursor = DB_MAGIC.len();
    let salt = read_array::<DB_SALT_LEN>(&bytes, &mut cursor)?;
    let nonce = read_array::<DB_NONCE_LEN>(&bytes, &mut cursor)?;
    let tag = read_array::<DB_TAG_LEN>(&bytes, &mut cursor)?;
    let ciphertext = &bytes[cursor..];
    let key = derive_db_key(master_secret, &salt);
    let plaintext = decrypt_aead(
        Cipher::aes_256_gcm(),
        &key,
        Some(&nonce),
        DB_AAD,
        ciphertext,
        &tag,
    )
    .map_err(|e| DaemonError::Crypto(e.to_string()))?;
    Ok(serde_json::from_slice(&plaintext)?)
}

fn migrate_legacy_db(path: &Path, master_secret: &[u8], db: &PlainDb) -> Result<()> {
    let subkeys = DbSubkeys::derive(master_secret);
    let database = Database::create(path).map_err(redb_error)?;
    ensure_meta_record(&database, &subkeys)?;
    apply_mutations(
        &database,
        &subkeys,
        plain_db_mutations(db),
        DbDurability::Immediate,
    )
}

fn redb_error<E: fmt::Display>(error: E) -> DaemonError {
    DaemonError::Crypto(format!("redb error: {error}"))
}

impl LogicalKey {
    fn meta() -> Self {
        Self {
            record_type: RECORD_META,
            channel_index: 0,
            sub_id: 0,
        }
    }

    fn channel(channel_index: u64) -> Self {
        Self {
            record_type: RECORD_CHANNEL,
            channel_index,
            sub_id: 0,
        }
    }

    fn secret(channel_index: u64, index: u64) -> Self {
        Self {
            record_type: RECORD_SECRET,
            channel_index,
            sub_id: index,
        }
    }

    fn frontier(channel_index: u64, mask: u64) -> Self {
        Self {
            record_type: RECORD_FRONTIER,
            channel_index,
            sub_id: mask,
        }
    }

    fn canonical_bytes(self) -> [u8; 17] {
        let mut out = [0u8; 17];
        out[0] = self.record_type;
        out[1..9].copy_from_slice(&self.channel_index.to_be_bytes());
        out[9..17].copy_from_slice(&self.sub_id.to_be_bytes());
        out
    }
}

impl ChannelRecord {
    fn scalars(&self) -> ChannelScalars {
        ChannelScalars {
            enabled: self.enabled,
            last_observed_next_reveal_index: self.last_observed_next_reveal_index,
            precompute_target: self.precompute_target,
            ssp_target: self.ssp_target,
            delta_lifetime_checked_units_cap: self.delta_lifetime_checked_units_cap,
            estimated_checked_units: self.estimated_checked_units,
            attempted_checked_units: self.attempted_checked_units,
            failed_precompute_jobs: self.failed_precompute_jobs,
        }
    }

    fn apply_scalars(&mut self, scalars: ChannelScalars) {
        self.enabled = scalars.enabled;
        self.last_observed_next_reveal_index = scalars.last_observed_next_reveal_index;
        self.precompute_target = scalars.precompute_target;
        self.ssp_target = scalars.ssp_target;
        self.delta_lifetime_checked_units_cap = scalars.delta_lifetime_checked_units_cap;
        self.estimated_checked_units = scalars.estimated_checked_units;
        self.attempted_checked_units = scalars.attempted_checked_units;
        self.failed_precompute_jobs = scalars.failed_precompute_jobs;
    }
}

fn empty_channel_record() -> ChannelRecord {
    ChannelRecord {
        enabled: false,
        last_observed_next_reveal_index: None,
        precompute_target: 0,
        ssp_target: DEFAULT_SSP_TARGET,
        delta_lifetime_checked_units_cap: DEFAULT_DELTA_CAP,
        frontier_nodes: BTreeMap::new(),
        known_secrets: BTreeMap::new(),
        estimated_checked_units: 0,
        attempted_checked_units: 0,
        failed_precompute_jobs: 0,
    }
}

fn upsert_channel_mutation(channel_index: u64, channel: &ChannelRecord) -> Mutation {
    Mutation::Upsert {
        key: LogicalKey::channel(channel_index),
        record: StoredRecord {
            record_type: RECORD_CHANNEL,
            channel_index,
            sub_id: 0,
            payload: StoredPayload::Channel(channel.scalars()),
        },
    }
}

fn upsert_secret_mutation(channel_index: u64, index: u64, secret_hex: String) -> Mutation {
    Mutation::Upsert {
        key: LogicalKey::secret(channel_index, index),
        record: StoredRecord {
            record_type: RECORD_SECRET,
            channel_index,
            sub_id: index,
            payload: StoredPayload::Secret { secret_hex },
        },
    }
}

fn upsert_frontier_mutation(channel_index: u64, mask: u64, record: WireRecord) -> Mutation {
    Mutation::Upsert {
        key: LogicalKey::frontier(channel_index, mask),
        record: StoredRecord {
            record_type: RECORD_FRONTIER,
            channel_index,
            sub_id: mask,
            payload: StoredPayload::Frontier(record),
        },
    }
}

fn delete_secret_mutation(channel_index: u64, index: u64) -> Mutation {
    Mutation::Delete {
        key: LogicalKey::secret(channel_index, index),
    }
}

fn delete_frontier_mutation(channel_index: u64, mask: u64) -> Mutation {
    Mutation::Delete {
        key: LogicalKey::frontier(channel_index, mask),
    }
}

fn plain_db_mutations(db: &PlainDb) -> Vec<Mutation> {
    let mut out = Vec::new();
    for (channel_s, channel) in &db.channels {
        let Ok(channel_index) = channel_s.parse::<u64>() else {
            continue;
        };
        out.push(upsert_channel_mutation(channel_index, channel));
        for (index_s, secret_hex) in &channel.known_secrets {
            if let Ok(index) = index_s.parse::<u64>() {
                out.push(upsert_secret_mutation(
                    channel_index,
                    index,
                    secret_hex.clone(),
                ));
            }
        }
        for (mask_s, record) in &channel.frontier_nodes {
            if let Ok(mask) = mask_s.parse::<u64>() {
                out.push(upsert_frontier_mutation(
                    channel_index,
                    mask,
                    record.clone(),
                ));
            }
        }
    }
    out
}

pub async fn run_daemon(cfg: DaemonConfig, master_secret: Vec<u8>) -> Result<()> {
    let state = init_daemon_state(cfg, master_secret)?;
    tokio::spawn(scheduler_loop(state.clone()));
    let control = ControlApi {
        state: state.clone(),
    };
    let peer = PeerApi {
        state: state.clone(),
    };
    let bind = {
        let inner = state.inner.lock().await;
        if let Some(path) = &inner.cfg.control_file {
            write_control_file(path, &inner.cfg.control_addr, &inner.cookie, &inner.cfg)?;
        }
        inner.cfg.control_addr
    };
    let peer_addr = {
        let inner = state.inner.lock().await;
        inner.cfg.peer_addr
    };
    let control_server = Server::builder()
        .add_service(ControlServiceServer::new(control))
        .serve(bind);
    let peer_server = {
        let inner = state.inner.lock().await;
        let mut builder = Server::builder();
        if let Some(tls) = &inner.cfg.peer_tls {
            builder = builder.tls_config(peer_server_tls_config(tls)?)?;
        }
        builder
            .add_service(PeerServiceServer::new(peer))
            .serve(peer_addr)
    };
    tokio::try_join!(control_server, peer_server)?;
    Ok(())
}

async fn scheduler_loop(state: DaemonState) {
    loop {
        sleep(Duration::from_secs(1)).await;
        let _ = state.run_scheduler_once().await;
    }
}

pub fn init_daemon_state(cfg: DaemonConfig, master_secret: Vec<u8>) -> Result<DaemonState> {
    if master_secret.len() < 32 {
        return Err(DaemonError::Usage(
            "master secret must contain at least 32 bytes".to_owned(),
        ));
    }
    let (db, db_writer) = DbStore::open(cfg.db_path.clone(), &master_secret)?;
    let cookie = load_or_create_cookie(&cfg)?;
    let peer_channel = peer_channel_from_url(&cfg.peer_url, cfg.peer_tls.as_ref())?;
    let baseline_daemon_rss_bytes = current_rss_bytes().unwrap_or(0);
    let sha = Arc::new(
        sha256_compress_gadget()
            .map_err(|e| DaemonError::Crypto(format!("failed to load SHA circuit: {e}")))?,
    );
    Ok(DaemonState {
        inner: Arc::new(Mutex::new(Inner {
            cfg,
            master_secret: SecretBytes(master_secret),
            cookie,
            db,
            active_jobs: BTreeMap::new(),
            next_job_id: 0,
            baseline_daemon_rss_bytes,
        })),
        db_writer,
        grpc_jobs: Arc::new(Mutex::new(BTreeMap::new())),
        pending_reveals: Arc::new(Mutex::new(BTreeMap::new())),
        pending_reveal_notify: Arc::new(Notify::new()),
        precompute_sessions: Arc::new(Mutex::new(BTreeMap::new())),
        incoming_precompute_sessions: Arc::new(Mutex::new(BTreeMap::new())),
        peer_channel,
        sha,
    })
}

#[derive(Clone)]
struct ControlApi {
    state: DaemonState,
}

#[tonic::async_trait]
impl ControlService for ControlApi {
    async fn status(
        &self,
        request: Request<pb::StatusRequest>,
    ) -> std::result::Result<Response<pb::StatusResponse>, Status> {
        self.state.check_cookie(&request).await?;
        let resources = self.state.resource_model().await;
        let inner = self.state.inner.lock().await;
        Ok(Response::new(pb::StatusResponse {
            role: inner.cfg.role.party_id() as u32,
            local_addr: inner.cfg.control_addr.to_string(),
            peer_addr: inner
                .cfg
                .peer_url
                .clone()
                .unwrap_or_else(|| inner.cfg.peer_addr.to_string()),
            max_ram_bytes: inner.cfg.max_ram_bytes,
            workers: resources.configured_workers,
            precompute: inner.cfg.precompute,
            channel_count: inner.db.channels.len() as u64,
            active_job_count: inner.active_jobs.len() as u64,
            effective_workers: resources.effective_workers,
            ram_limited_workers_raw: resources.ram_limited_workers_raw,
            ram_overcommit_warning: resources.ram_overcommit_warning,
            baseline_daemon_rss_bytes: resources.baseline_daemon_rss_bytes,
            current_rss_bytes: resources.current_rss_bytes,
            idle_session_rss_estimate_bytes: resources.idle_session_rss_estimate_bytes,
            one_h_worker_peak_rss_estimate_bytes: resources.one_h_worker_peak_rss_estimate_bytes,
            live_session_count: resources.live_session_count,
            reserved_ram_bytes: resources.reserved_ram_bytes,
        }))
    }

    async fn set_config(
        &self,
        request: Request<pb::SetConfigRequest>,
    ) -> std::result::Result<Response<pb::SetConfigResponse>, Status> {
        self.state.check_cookie(&request).await?;
        let req = request.into_inner();
        let mut inner = self.state.inner.lock().await;
        if let Some(v) = req.max_ram_bytes {
            inner.cfg.max_ram_bytes = v;
        }
        if let Some(v) = req.workers {
            inner.cfg.workers = v.max(1);
        }
        if let Some(v) = req.precompute {
            inner.cfg.precompute = v;
        }
        drop(inner);
        let resources = self.state.resource_model().await;
        let inner = self.state.inner.lock().await;
        Ok(Response::new(pb::SetConfigResponse {
            max_ram_bytes: inner.cfg.max_ram_bytes,
            workers: inner.cfg.workers,
            precompute: inner.cfg.precompute,
            effective_workers: resources.effective_workers,
            ram_overcommit_warning: resources.ram_overcommit_warning,
        }))
    }

    async fn enable_channel(
        &self,
        request: Request<pb::EnableChannelRequest>,
    ) -> std::result::Result<Response<pb::ChannelResponse>, Status> {
        self.state.check_cookie(&request).await?;
        let req = request.into_inner();
        let mut inner = self.state.inner.lock().await;
        let key = channel_key(req.channel_index);
        let default_precompute = if req.precompute == 0 {
            inner.cfg.precompute
        } else {
            req.precompute
        };
        let channel = inner
            .db
            .channels
            .entry(key)
            .or_insert_with(|| ChannelRecord {
                enabled: true,
                last_observed_next_reveal_index: None,
                precompute_target: default_precompute,
                ssp_target: if req.ssp_target == 0 {
                    DEFAULT_SSP_TARGET
                } else {
                    req.ssp_target
                },
                delta_lifetime_checked_units_cap: if req.delta_lifetime_checked_units_cap == 0 {
                    DEFAULT_DELTA_CAP
                } else {
                    req.delta_lifetime_checked_units_cap
                },
                frontier_nodes: BTreeMap::new(),
                known_secrets: BTreeMap::new(),
                estimated_checked_units: 0,
                attempted_checked_units: 0,
                failed_precompute_jobs: 0,
            });
        channel.enabled = true;
        channel.precompute_target = default_precompute;
        if req.ssp_target != 0 {
            channel.ssp_target = req.ssp_target;
        }
        if req.delta_lifetime_checked_units_cap != 0 {
            channel.delta_lifetime_checked_units_cap = req.delta_lifetime_checked_units_cap;
        }
        let response = channel_response(req.channel_index, channel);
        let mutations = vec![upsert_channel_mutation(req.channel_index, channel)];
        drop(inner);
        self.state
            .db_writer
            .write_batch(mutations, DbDurability::Immediate)
            .await
            .map_err(to_status)?;
        self.state.db_writer.flush().await.map_err(to_status)?;
        Ok(Response::new(response))
    }

    async fn disable_channel(
        &self,
        request: Request<pb::DisableChannelRequest>,
    ) -> std::result::Result<Response<pb::ChannelResponse>, Status> {
        self.state.check_cookie(&request).await?;
        let req = request.into_inner();
        let mut inner = self.state.inner.lock().await;
        let key = channel_key(req.channel_index);
        if inner
            .active_jobs
            .values()
            .any(|job| job.channel_index == req.channel_index)
        {
            return Err(Status::failed_precondition(
                "channel has an active precompute job",
            ));
        }
        let channel = inner
            .db
            .channels
            .get_mut(&key)
            .ok_or_else(|| Status::not_found("channel is not enabled"))?;
        channel.enabled = false;
        let drop_masks = channel
            .frontier_nodes
            .keys()
            .filter_map(|mask| mask.parse::<u64>().ok())
            .collect::<Vec<_>>();
        channel.frontier_nodes.clear();
        let response = channel_response(req.channel_index, channel);
        let mut mutations = vec![upsert_channel_mutation(req.channel_index, channel)];
        mutations.extend(
            drop_masks
                .into_iter()
                .map(|mask| delete_frontier_mutation(req.channel_index, mask)),
        );
        drop(inner);
        self.state
            .db_writer
            .write_batch(mutations, DbDurability::Immediate)
            .await
            .map_err(to_status)?;
        self.state.db_writer.flush().await.map_err(to_status)?;
        self.state.drop_precompute_session(req.channel_index).await;
        Ok(Response::new(response))
    }

    async fn precompute(
        &self,
        request: Request<pb::PrecomputeRequest>,
    ) -> std::result::Result<Response<pb::PrecomputeResponse>, Status> {
        self.state.check_cookie(&request).await?;
        let req = request.into_inner();
        let out = self
            .state
            .precompute_path(req.channel_index, req.target_index)
            .await
            .map_err(to_status)?;
        Ok(Response::new(out))
    }

    async fn reveal(
        &self,
        request: Request<pb::RevealRequest>,
    ) -> std::result::Result<Response<pb::RevealResponse>, Status> {
        self.state.check_cookie(&request).await?;
        let req = request.into_inner();
        let out = self
            .state
            .reveal(
                req.channel_index,
                req.requested_index,
                req.expected_next_index,
                req.allow_seed_reveal,
            )
            .await
            .map_err(to_status)?;
        Ok(Response::new(out))
    }

    async fn list_channels(
        &self,
        request: Request<pb::ListChannelsRequest>,
    ) -> std::result::Result<Response<pb::ListChannelsResponse>, Status> {
        self.state.check_cookie(&request).await?;
        let inner = self.state.inner.lock().await;
        let channels = inner
            .db
            .channels
            .iter()
            .filter_map(|(key, channel)| {
                key.parse::<u64>()
                    .ok()
                    .map(|index| channel_response(index, channel))
            })
            .collect();
        Ok(Response::new(pb::ListChannelsResponse { channels }))
    }

    async fn list_jobs(
        &self,
        request: Request<pb::ListJobsRequest>,
    ) -> std::result::Result<Response<pb::ListJobsResponse>, Status> {
        self.state.check_cookie(&request).await?;
        let inner = self.state.inner.lock().await;
        let jobs = inner
            .active_jobs
            .iter()
            .map(|(id, job)| pb::JobInfo {
                job_id: id.clone(),
                channel_index: job.channel_index,
                kind: format!("{} checked={}", job.kind, job.planned_checked_units),
                state: job.state.clone(),
            })
            .collect();
        Ok(Response::new(pb::ListJobsResponse { jobs }))
    }
}

#[derive(Clone)]
struct PeerApi {
    state: DaemonState,
}

#[tonic::async_trait]
impl PeerService for PeerApi {
    type JobStreamStream = ReceiverStream<std::result::Result<pb::JobFrame, Status>>;

    async fn hello(
        &self,
        _request: Request<pb::HelloRequest>,
    ) -> std::result::Result<Response<pb::HelloResponse>, Status> {
        let inner = self.state.inner.lock().await;
        Ok(Response::new(pb::HelloResponse {
            role: inner.cfg.role.party_id() as u32,
            daemon_id: daemon_id(&inner.master_secret.0),
            protocol_version: PROTOCOL_VERSION,
        }))
    }

    async fn config(
        &self,
        _request: Request<pb::ConfigUpdate>,
    ) -> std::result::Result<Response<pb::ConfigUpdate>, Status> {
        let resources = self.state.resource_model().await;
        let inner = self.state.inner.lock().await;
        Ok(Response::new(pb::ConfigUpdate {
            max_ram_bytes: inner.cfg.max_ram_bytes,
            workers: inner.cfg.workers,
            precompute: inner.cfg.precompute,
            ssp_target: DEFAULT_SSP_TARGET,
            delta_lifetime_checked_units_cap: DEFAULT_DELTA_CAP,
            effective_workers: resources.effective_workers,
            ram_limited_workers_raw: resources.ram_limited_workers_raw,
            ram_overcommit_warning: resources.ram_overcommit_warning,
        }))
    }

    async fn get_frontier(
        &self,
        request: Request<pb::GetFrontierRequest>,
    ) -> std::result::Result<Response<pb::GetFrontierResponse>, Status> {
        let resources = self.state.resource_model().await;
        let req = request.into_inner();
        let inner = self.state.inner.lock().await;
        let Some(channel) = inner.db.channels.get(&channel_key(req.channel_index)) else {
            return Ok(Response::new(pb::GetFrontierResponse {
                nodes: Vec::new(),
                channel_enabled: false,
                precompute: 0,
                ssp_target: 0,
                delta_lifetime_checked_units_cap: 0,
                workers: inner.cfg.workers,
                effective_workers: resources.effective_workers,
                ram_limited_workers_raw: resources.ram_limited_workers_raw,
                ram_overcommit_warning: resources.ram_overcommit_warning,
            }));
        };
        let nodes = channel
            .frontier_nodes
            .iter()
            .filter_map(|(mask, node)| {
                mask.parse::<u64>().ok().map(|mask| pb::FrontierNode {
                    mask,
                    public_binding_hex: node.public_binding_hex.clone(),
                })
            })
            .collect();
        Ok(Response::new(pb::GetFrontierResponse {
            nodes,
            channel_enabled: channel.enabled,
            precompute: channel.precompute_target,
            ssp_target: channel.ssp_target,
            delta_lifetime_checked_units_cap: channel.delta_lifetime_checked_units_cap,
            workers: inner.cfg.workers,
            effective_workers: resources.effective_workers,
            ram_limited_workers_raw: resources.ram_limited_workers_raw,
            ram_overcommit_warning: resources.ram_overcommit_warning,
        }))
    }

    async fn job_stream(
        &self,
        request: Request<Streaming<pb::JobFrame>>,
    ) -> std::result::Result<Response<Self::JobStreamStream>, Status> {
        let (descriptor, channel, stream, response) =
            open_peer_job_stream(request.into_inner()).await?;
        self.state
            .register_incoming_job_stream(descriptor, channel, stream)
            .await?;
        Ok(Response::new(response))
    }

    async fn reveal_cached(
        &self,
        request: Request<pb::RevealCachedRequest>,
    ) -> std::result::Result<Response<pb::RevealCachedResponse>, Status> {
        let out = self
            .state
            .handle_peer_cached_reveal(request.into_inner())
            .await
            .map_err(to_status)?;
        Ok(Response::new(out))
    }
}

async fn open_peer_job_stream(
    mut incoming: Streaming<pb::JobFrame>,
) -> std::result::Result<
    (
        GrpcJobDescriptor,
        u32,
        ChannelByteStream,
        ReceiverStream<std::result::Result<pb::JobFrame, Status>>,
    ),
    Status,
> {
    let start = incoming
        .message()
        .await?
        .ok_or_else(|| Status::invalid_argument("missing JobStream start frame"))?;
    let descriptor = descriptor_from_job_frame(&start).map_err(Status::invalid_argument)?;
    let channel = validate_job_channel(start.channel).map_err(Status::invalid_argument)?;
    if !start.start {
        return Err(Status::invalid_argument(
            "first JobStream frame must be a start frame",
        ));
    }
    if !start.payload.is_empty() {
        return Err(Status::invalid_argument(
            "JobStream start frame must not carry payload",
        ));
    }

    let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(64);
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(64);
    let (response_tx, response_rx) = mpsc::channel::<std::result::Result<pb::JobFrame, Status>>(64);

    let forward_descriptor = descriptor.clone();
    tokio::spawn(async move {
        while let Ok(Some(frame)) = incoming.message().await {
            if frame.start
                || frame.job_id != forward_descriptor.job_id
                || frame.channel != channel
                || !validate_job_payload_context(&frame, &forward_descriptor)
            {
                break;
            }
            if in_tx.send(frame.payload).await.is_err() {
                break;
            }
        }
    });

    let response_descriptor = descriptor.clone();
    tokio::spawn(async move {
        while let Some(payload) = out_rx.recv().await {
            let frame = job_frame(&response_descriptor, channel, false, payload);
            if response_tx.send(Ok(frame)).await.is_err() {
                break;
            }
        }
    });

    Ok((
        descriptor,
        channel,
        ChannelByteStream::new(out_tx, in_rx),
        ReceiverStream::new(response_rx),
    ))
}

async fn open_peer_job_channel(
    peer_channel: Channel,
    descriptor: &GrpcJobDescriptor,
    channel: u32,
) -> Result<ChannelByteStream> {
    let channel =
        validate_job_channel(channel).map_err(|msg| DaemonError::Refused(msg.to_owned()))?;
    let (request_tx, request_rx) = mpsc::channel::<pb::JobFrame>(64);
    request_tx
        .send(job_frame(descriptor, channel, true, Vec::new()))
        .await
        .map_err(|_| DaemonError::Refused("JobStream request channel closed".to_owned()))?;
    let mut client = pb::peer_service_client::PeerServiceClient::new(peer_channel);
    let response = client
        .job_stream(ReceiverStream::new(request_rx))
        .await?
        .into_inner();

    let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(64);
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(64);

    let request_descriptor = descriptor.clone();
    let request_tx_forward = request_tx.clone();
    tokio::spawn(async move {
        while let Some(payload) = out_rx.recv().await {
            let frame = job_frame(&request_descriptor, channel, false, payload);
            if request_tx_forward.send(frame).await.is_err() {
                break;
            }
        }
    });

    let response_descriptor = descriptor.clone();
    tokio::spawn(async move {
        let mut response = response;
        while let Ok(Some(frame)) = response.message().await {
            if frame.start
                || frame.job_id != response_descriptor.job_id
                || frame.channel != channel
                || !validate_job_payload_context(&frame, &response_descriptor)
            {
                break;
            }
            if in_tx.send(frame.payload).await.is_err() {
                break;
            }
        }
    });

    Ok(ChannelByteStream::new(out_tx, in_rx))
}

impl PrecomputeSessionHandle {
    async fn plan(&self, index: Index48) -> Result<u64> {
        let (response, rx) = oneshot::channel();
        self.tx
            .send(PrecomputeSessionCommand::Plan { index, response })
            .await
            .map_err(|_| DaemonError::Refused("precompute session is closed".to_owned()))?;
        rx.await
            .map_err(|_| DaemonError::Refused("precompute session stopped".to_owned()))?
    }

    async fn precompute(&self, index: Index48) -> Result<Ag2pcSecureWires> {
        let (response, rx) = oneshot::channel();
        self.tx
            .send(PrecomputeSessionCommand::Precompute { index, response })
            .await
            .map_err(|_| DaemonError::Refused("precompute session is closed".to_owned()))?;
        rx.await
            .map_err(|_| DaemonError::Refused("precompute session stopped".to_owned()))?
    }
}

async fn run_outgoing_precompute_session(
    mut session: PrecomputeSession<ChannelByteStream>,
    mut rx: mpsc::Receiver<PrecomputeSessionCommand>,
) {
    while let Some(command) = rx.recv().await {
        match command {
            PrecomputeSessionCommand::Plan { index, response } => {
                let _ = response.send(Ok(session.planned_checked_units(index)));
            }
            PrecomputeSessionCommand::Precompute { index, response } => {
                let target_bytes = index.get().to_le_bytes();
                let send_result = async {
                    session.streams_mut().main.send_data(&target_bytes).await?;
                    session.streams_mut().main.flush().await?;
                    Ok::<(), shachain2pc_emp_wire::WireError>(())
                }
                .await
                .map_err(DaemonError::from);
                let result = match send_result {
                    Ok(()) => session
                        .precompute_target(index)
                        .await
                        .map_err(DaemonError::from),
                    Err(e) => Err(e),
                };
                let failed = result.is_err();
                let _ = response.send(result);
                if failed {
                    break;
                }
            }
        }
    }
}

impl DaemonState {
    async fn resource_model(&self) -> ResourceModel {
        let outgoing = self.precompute_sessions.lock().await.len() as u64;
        let incoming = self.incoming_precompute_sessions.lock().await.len() as u64;
        let live_session_count = outgoing.saturating_add(incoming);
        let inner = self.inner.lock().await;
        resource_model(&inner, live_session_count)
    }

    async fn check_cookie<T>(&self, request: &Request<T>) -> std::result::Result<(), Status> {
        let cookie = request
            .metadata()
            .get("x-shachain-cookie")
            .ok_or_else(|| Status::unauthenticated("missing local cookie"))?
            .to_str()
            .map_err(|_| Status::unauthenticated("bad local cookie"))?
            .to_owned();
        let expected = self.inner.lock().await.cookie.clone();
        if cookie == expected {
            Ok(())
        } else {
            Err(Status::unauthenticated("bad local cookie"))
        }
    }

    async fn register_incoming_job_stream(
        &self,
        descriptor: GrpcJobDescriptor,
        channel: u32,
        stream: ChannelByteStream,
    ) -> std::result::Result<(), Status> {
        let mut jobs = self.grpc_jobs.lock().await;
        let entry = jobs
            .entry(descriptor.job_id.clone())
            .or_insert_with(|| PendingGrpcJob {
                descriptor: descriptor.clone(),
                main: None,
                sibling: None,
            });
        if entry.descriptor != descriptor {
            return Err(Status::invalid_argument("JobStream descriptor mismatch"));
        }
        let slot = match channel {
            1 => &mut entry.main,
            2 => &mut entry.sibling,
            _ => return Err(Status::invalid_argument("JobStream channel must be 1 or 2")),
        };
        if slot.is_some() {
            return Err(Status::already_exists("duplicate JobStream channel"));
        }
        *slot = Some(stream);
        if entry.main.is_some() && entry.sibling.is_some() {
            let mut ready = jobs
                .remove(&descriptor.job_id)
                .expect("ready JobStream entry exists");
            let streams = Ag2pcStreams {
                main: ready.main.take().expect("main stream is ready"),
                sibling: ready.sibling.take().expect("sibling stream is ready"),
            };
            let state = self.clone();
            let channel_index = ready.descriptor.channel_index;
            let task_state = state.clone();
            let task = tokio::spawn(async move {
                let _ = task_state
                    .clone()
                    .run_incoming_precompute_session(ready.descriptor, streams)
                    .await;
                task_state
                    .unregister_incoming_precompute_session(channel_index)
                    .await;
            });
            let abort_handle = task.abort_handle();
            let old = {
                state
                    .incoming_precompute_sessions
                    .lock()
                    .await
                    .insert(channel_index, abort_handle)
            };
            if let Some(old) = old {
                old.abort();
            }
        }
        Ok(())
    }

    async fn run_incoming_precompute_session(
        self,
        descriptor: GrpcJobDescriptor,
        mut streams: Ag2pcStreams<ChannelByteStream>,
    ) -> Result<()> {
        let job = self.begin_incoming_precompute_session(&descriptor).await?;
        streams =
            match run_jobstream_session_handshake(self.role().await, &descriptor, streams).await {
                Ok(streams) => streams,
                Err(e) => return Err(e),
            };
        let role = self.role().await;
        let mut session = match PrecomputeSession::setup_with_streams_and_circuit(
            streams,
            role,
            job.share,
            job.delta,
            job.ssp,
            self.sha.clone(),
        )
        .await
        {
            Ok(session) => session,
            Err(e) => return Err(e.into()),
        };
        loop {
            let target_bytes = match session.streams_mut().main.recv_data(8).await {
                Ok(bytes) => bytes,
                Err(e) => return Err(e.into()),
            };
            let target_index = u64::from_le_bytes(
                target_bytes
                    .try_into()
                    .map_err(|_| DaemonError::Parse("bad precompute target command".to_owned()))?,
            );
            let index =
                Index48::new(target_index).map_err(|e| DaemonError::Parse(e.to_string()))?;
            let planned_checked_units = session.planned_checked_units(index);
            let target_job = self
                .begin_incoming_precompute_target(&descriptor, index, planned_checked_units)
                .await?;
            let wires = match session.precompute_target(index).await {
                Ok(wires) => wires,
                Err(e) => {
                    self.finish_job(&target_job.job_id, true).await;
                    return Err(e.into());
                }
            };
            if let Err(e) = self
                .store_precomputed_target_wires_and_finish_job(
                    descriptor.channel_index,
                    &target_job.job_id,
                    planned_checked_units,
                    index.get(),
                    wires,
                )
                .await
            {
                self.finish_job(&target_job.job_id, true).await;
                return Err(e);
            }
        }
    }

    async fn role(&self) -> Role {
        self.inner.lock().await.cfg.role
    }

    async fn reveal(
        &self,
        channel_index: u64,
        requested_index: u64,
        expected_next_index: u64,
        allow_seed_reveal: bool,
    ) -> Result<pb::RevealResponse> {
        let index = Index48::new(requested_index).map_err(|e| DaemonError::Parse(e.to_string()))?;
        if index.get() == 0 && !allow_seed_reveal {
            return Err(DaemonError::Refused(
                "I=0 reveals the seed; pass allow_seed_reveal to proceed".to_owned(),
            ));
        }
        let mut from_cache = false;
        if let Some(secret) = self.derive_known(channel_index, index).await? {
            from_cache = true;
            return Ok(pb::RevealResponse {
                channel_index,
                index: index.get(),
                secret_hex: secret.to_hex(),
                from_cache,
            });
        }
        if requested_index != expected_next_index {
            return Err(DaemonError::Refused(
                "requested index must match expected_next_index unless locally derivable"
                    .to_owned(),
            ));
        }
        self.reconcile_with_peer(channel_index).await?;
        if let Some(node) = self.load_node(channel_index, index.get()).await? {
            let secret = self
                .reveal_cached_node(
                    channel_index,
                    index,
                    expected_next_index,
                    allow_seed_reveal,
                    &node,
                )
                .await?;
            self.store_known_secret(channel_index, index, expected_next_index, secret)
                .await?;
            return Ok(pb::RevealResponse {
                channel_index,
                index: index.get(),
                secret_hex: secret.to_hex(),
                from_cache: true,
            });
        }
        if index.get() == 0 {
            let node = self.ensure_root(channel_index).await?;
            let secret = self
                .reveal_cached_node(
                    channel_index,
                    index,
                    expected_next_index,
                    allow_seed_reveal,
                    &node,
                )
                .await?;
            self.store_known_secret(channel_index, index, expected_next_index, secret)
                .await?;
            Ok(pb::RevealResponse {
                channel_index,
                index: index.get(),
                secret_hex: secret.to_hex(),
                from_cache,
            })
        } else {
            let secret = self.run_full_derivation(channel_index, index).await?;
            self.store_known_secret(channel_index, index, expected_next_index, secret)
                .await?;
            Ok(pb::RevealResponse {
                channel_index,
                index: index.get(),
                secret_hex: secret.to_hex(),
                from_cache,
            })
        }
    }

    async fn run_scheduler_once(&self) -> Result<()> {
        if self.role().await != Role::Alice {
            return Ok(());
        }
        let candidates = self.scheduler_candidates().await;
        for channel_index in candidates {
            let Some(peer) = self.peer_frontier(channel_index).await? else {
                continue;
            };
            if !peer.channel_enabled {
                continue;
            }
            self.reconcile_with_peer(channel_index).await?;
            let effective_precompute = self
                .effective_precompute_target(channel_index, peer)
                .await?;
            if effective_precompute == 0 {
                continue;
            }
            if let Some(target) = self
                .next_missing_frontier(channel_index, effective_precompute)
                .await?
            {
                let state = self.clone();
                tokio::spawn(async move {
                    let _ = state.precompute_path_jobstream(channel_index, target).await;
                });
            }
        }
        Ok(())
    }

    async fn scheduler_candidates(&self) -> Vec<u64> {
        let resources = self.resource_model().await;
        let inner = self.inner.lock().await;
        if inner.cfg.workers == 0 || inner.cfg.precompute == 0 {
            return Vec::new();
        }
        if inner.active_jobs.len() >= resources.effective_workers as usize {
            return Vec::new();
        }
        inner
            .db
            .channels
            .iter()
            .filter_map(|(key, channel)| {
                let channel_index = key.parse::<u64>().ok()?;
                if !channel.enabled || channel.precompute_target == 0 {
                    return None;
                }
                let busy = inner
                    .active_jobs
                    .values()
                    .any(|job| job.channel_index == channel_index);
                if busy {
                    return None;
                }
                Some(channel_index)
            })
            .collect()
    }

    async fn validate_peer_security_params(
        &self,
        channel_index: u64,
        peer: PeerFrontierConfig,
    ) -> Result<()> {
        let inner = self.inner.lock().await;
        let channel = inner
            .db
            .channels
            .get(&channel_key(channel_index))
            .ok_or_else(|| DaemonError::NotFound("channel is not enabled".to_owned()))?;
        if peer.ssp_target != channel.ssp_target
            || peer.delta_lifetime_checked_units_cap != channel.delta_lifetime_checked_units_cap
        {
            return Err(DaemonError::Refused(
                "peer channel security parameters do not match".to_owned(),
            ));
        }
        Ok(())
    }

    async fn effective_precompute_target(
        &self,
        channel_index: u64,
        peer: PeerFrontierConfig,
    ) -> Result<u64> {
        self.validate_peer_security_params(channel_index, peer)
            .await?;
        let inner = self.inner.lock().await;
        let channel = inner
            .db
            .channels
            .get(&channel_key(channel_index))
            .ok_or_else(|| DaemonError::NotFound("channel is not enabled".to_owned()))?;
        Ok(channel
            .precompute_target
            .min(inner.cfg.precompute)
            .min(peer.precompute))
    }

    async fn next_missing_frontier(
        &self,
        channel_index: u64,
        effective_precompute: u64,
    ) -> Result<Option<u64>> {
        let inner = self.inner.lock().await;
        let Some(channel) = inner.db.channels.get(&channel_key(channel_index)) else {
            return Ok(None);
        };
        for index in 1..=effective_precompute.min(MAX_INDEX) {
            let key = node_key(index);
            let (public, local) = binding_pair(&inner, channel_index, index);
            let present = channel.frontier_nodes.get(&key).is_some_and(|record| {
                record.public_binding_hex == to_hex(&public)
                    && record.local_binding_hex == to_hex(&local)
            });
            if !present {
                return Ok(Some(index));
            }
        }
        Ok(None)
    }

    async fn precompute_path(
        &self,
        channel_index: u64,
        target_index: u64,
    ) -> Result<pb::PrecomputeResponse> {
        self.precompute_path_jobstream(channel_index, target_index)
            .await
    }

    async fn precompute_session_handle(
        &self,
        channel_index: u64,
        peer: PeerFrontierConfig,
    ) -> Result<PrecomputeSessionHandle> {
        {
            let mut sessions = self.precompute_sessions.lock().await;
            if let Some(handle) = sessions.get(&channel_index) {
                if !handle.tx.is_closed() {
                    return Ok(handle.clone());
                }
            }
            sessions.remove(&channel_index);
        }

        let (role, delta, ssp, ssp_target, cap, share, session_id) = {
            let mut inner = self.inner.lock().await;
            let key = channel_key(channel_index);
            let channel = inner
                .db
                .channels
                .get(&key)
                .ok_or_else(|| DaemonError::NotFound("channel is not enabled".to_owned()))?;
            if !channel.enabled {
                return Err(DaemonError::Refused("channel is disabled".to_owned()));
            }
            if peer.ssp_target != channel.ssp_target
                || peer.delta_lifetime_checked_units_cap != channel.delta_lifetime_checked_units_cap
            {
                return Err(DaemonError::Refused(
                    "peer channel security parameters do not match".to_owned(),
                ));
            }
            let ssp_target = channel.ssp_target;
            let cap = channel.delta_lifetime_checked_units_cap;
            inner.next_job_id = inner.next_job_id.saturating_add(1);
            (
                inner.cfg.role,
                channel_delta(&inner.master_secret.0, channel_index, inner.cfg.role),
                ssp_effective(ssp_target, cap),
                ssp_target,
                cap,
                channel_seed_share(&inner.master_secret.0, channel_index),
                format!("precompute-session-{}-{}", channel_index, inner.next_job_id),
            )
        };
        let descriptor = GrpcJobDescriptor {
            job_id: session_id,
            channel_index,
            target_index: 0,
            ssp: ssp as u32,
            ssp_target,
            delta_lifetime_checked_units_cap: cap,
            digest: job_digest(channel_index, "precompute-session", 0, 0, ssp as u32),
        };
        let mut streams = self.open_peer_job_streams(&descriptor).await?;
        streams = run_jobstream_session_handshake(role, &descriptor, streams).await?;
        let session = PrecomputeSession::setup_with_streams_and_circuit(
            streams,
            role,
            share,
            delta,
            ssp,
            self.sha.clone(),
        )
        .await?;
        let (tx, rx) = mpsc::channel(8);
        let handle = PrecomputeSessionHandle { tx };
        self.precompute_sessions
            .lock()
            .await
            .insert(channel_index, handle.clone());
        tokio::spawn(run_outgoing_precompute_session(session, rx));
        Ok(handle)
    }

    async fn drop_precompute_session(&self, channel_index: u64) {
        self.precompute_sessions.lock().await.remove(&channel_index);
        if let Some(handle) = self
            .incoming_precompute_sessions
            .lock()
            .await
            .remove(&channel_index)
        {
            handle.abort();
        }
    }

    async fn unregister_incoming_precompute_session(&self, channel_index: u64) {
        self.incoming_precompute_sessions
            .lock()
            .await
            .remove(&channel_index);
    }

    async fn precompute_path_jobstream(
        &self,
        channel_index: u64,
        target_index: u64,
    ) -> Result<pb::PrecomputeResponse> {
        let index = Index48::new(target_index).map_err(|e| DaemonError::Parse(e.to_string()))?;
        let peer = match self.peer_frontier(channel_index).await? {
            Some(peer) if peer.channel_enabled => peer,
            Some(_) => {
                return Err(DaemonError::Refused(
                    "peer has not enabled this channel".to_owned(),
                ));
            }
            None => {
                return Err(DaemonError::Refused(
                    "peer URL is not configured".to_owned(),
                ))
            }
        };
        if let Err(e) = self
            .validate_peer_security_params(channel_index, peer)
            .await
        {
            let planned_checked_units = set_bits_desc(index.get()).len() as u64;
            self.record_failed_precompute_attempt(channel_index, planned_checked_units)
                .await?;
            return Err(e);
        }
        self.reconcile_with_peer(channel_index).await?;
        let session = self.precompute_session_handle(channel_index, peer).await?;
        let planned_checked_units = match session.plan(index).await {
            Ok(planned) => planned,
            Err(e) => {
                self.drop_precompute_session(channel_index).await;
                return Err(e);
            }
        };
        let job = match self
            .begin_precompute_jobstream(channel_index, index, peer, planned_checked_units)
            .await?
        {
            PrecomputeStart::AlreadyStored => {
                return Ok(pb::PrecomputeResponse {
                    channel_index,
                    target_index: index.get(),
                    nodes_stored: 0,
                    checked_units: 0,
                });
            }
            PrecomputeStart::Run(job) => job,
        };
        let wires = match session.precompute(index).await {
            Ok(wires) => wires,
            Err(e) => {
                self.drop_precompute_session(channel_index).await;
                self.finish_job(&job.job_id, true).await;
                return Err(e);
            }
        };
        let nodes_stored = match self
            .store_precomputed_target_wires_and_finish_job(
                channel_index,
                &job.job_id,
                job.planned_checked_units,
                index.get(),
                wires,
            )
            .await
        {
            Ok(nodes_stored) => nodes_stored,
            Err(e) => {
                self.finish_job(&job.job_id, true).await;
                return Err(e);
            }
        };
        Ok(pb::PrecomputeResponse {
            channel_index,
            target_index: index.get(),
            nodes_stored,
            checked_units: job.planned_checked_units,
        })
    }

    async fn reveal_cached_node(
        &self,
        channel_index: u64,
        index: Index48,
        expected_next_index: u64,
        allow_seed_reveal: bool,
        node: &Ag2pcSecureWires,
    ) -> Result<Value32> {
        if index.get() == 0 {
            return self.reveal_persisted_node(channel_index, index, node).await;
        }
        match (self.role().await, self.peer_channel.is_some()) {
            (Role::Alice, true) => {
                self.reveal_cached_node_via_peer(
                    channel_index,
                    index,
                    expected_next_index,
                    allow_seed_reveal,
                    node,
                )
                .await
            }
            (Role::Bob, true) => {
                self.await_incoming_cached_reveal(
                    channel_index,
                    index,
                    expected_next_index,
                    allow_seed_reveal,
                    node,
                )
                .await
            }
            _ => self.reveal_persisted_node(channel_index, index, node).await,
        }
    }

    async fn reveal_cached_node_via_peer(
        &self,
        channel_index: u64,
        index: Index48,
        expected_next_index: u64,
        allow_seed_reveal: bool,
        node: &Ag2pcSecureWires,
    ) -> Result<Value32> {
        let (delta, ssp_target, cap, public_binding_hex) =
            self.reveal_node_context(channel_index, index.get()).await?;
        let local = reveal_node_local_share(node)?;
        let peer_channel = self
            .peer_channel
            .clone()
            .ok_or_else(|| DaemonError::Refused("peer URL is not configured".to_owned()))?;
        let mut client = pb::peer_service_client::PeerServiceClient::new(peer_channel);
        let response = client
            .reveal_cached(pb::RevealCachedRequest {
                channel_index,
                requested_index: index.get(),
                expected_next_index,
                allow_seed_reveal,
                share_bits: local.share_bits,
                mac_digest: local.mac_digest.to_vec(),
                ssp_target,
                delta_lifetime_checked_units_cap: cap,
                public_binding_hex,
            })
            .await?
            .into_inner();
        let peer_digest = parse_mac_digest(response.mac_digest, "RevealCached response")?;
        let opened = reveal_node_from_peer_share(node, delta, &response.share_bits, peer_digest)?;
        Ok(opened.value)
    }

    async fn await_incoming_cached_reveal(
        &self,
        channel_index: u64,
        index: Index48,
        expected_next_index: u64,
        allow_seed_reveal: bool,
        node: &Ag2pcSecureWires,
    ) -> Result<Value32> {
        reveal_node_local_share(node)?;
        let key = RevealRequestKey {
            channel_index,
            requested_index: index.get(),
            expected_next_index,
            allow_seed_reveal,
        };
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.pending_reveals.lock().await;
            if pending
                .insert(key, PendingReveal { response: tx })
                .is_some()
            {
                return Err(DaemonError::Refused(
                    "cached reveal is already pending".to_owned(),
                ));
            }
        }
        self.pending_reveal_notify.notify_waiters();
        match timeout(peer_reveal_wait(), rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(DaemonError::Refused(
                "cached reveal peer handler stopped".to_owned(),
            )),
            Err(_) => {
                self.pending_reveals.lock().await.remove(&key);
                Err(DaemonError::Refused(
                    "timed out waiting for peer cached reveal".to_owned(),
                ))
            }
        }
    }

    async fn handle_peer_cached_reveal(
        &self,
        req: pb::RevealCachedRequest,
    ) -> Result<pb::RevealCachedResponse> {
        let key = RevealRequestKey {
            channel_index: req.channel_index,
            requested_index: req.requested_index,
            expected_next_index: req.expected_next_index,
            allow_seed_reveal: req.allow_seed_reveal,
        };
        let pending = self.take_pending_reveal(key).await?;
        match self.complete_peer_cached_reveal(req).await {
            Ok((response, value)) => {
                let _ = pending.response.send(Ok(value));
                Ok(response)
            }
            Err(err) => {
                let msg = err.to_string();
                let _ = pending.response.send(Err(DaemonError::Refused(msg)));
                Err(err)
            }
        }
    }

    async fn take_pending_reveal(&self, key: RevealRequestKey) -> Result<PendingReveal> {
        timeout(peer_reveal_wait(), async {
            loop {
                let notified = self.pending_reveal_notify.notified();
                if let Some(pending) = self.pending_reveals.lock().await.remove(&key) {
                    return pending;
                }
                notified.await;
            }
        })
        .await
        .map_err(|_| {
            DaemonError::Refused("cached reveal needs matching local authorization".to_owned())
        })
    }

    async fn complete_peer_cached_reveal(
        &self,
        req: pb::RevealCachedRequest,
    ) -> Result<(pb::RevealCachedResponse, Value32)> {
        let index =
            Index48::new(req.requested_index).map_err(|e| DaemonError::Parse(e.to_string()))?;
        if index.get() == 0 && !req.allow_seed_reveal {
            return Err(DaemonError::Refused(
                "I=0 reveals the seed; pass allow_seed_reveal to proceed".to_owned(),
            ));
        }
        if req.requested_index != req.expected_next_index {
            return Err(DaemonError::Refused(
                "requested index must match expected_next_index".to_owned(),
            ));
        }
        let peer_digest = parse_mac_digest(req.mac_digest, "RevealCached request")?;
        let node = self
            .load_node(req.channel_index, index.get())
            .await?
            .ok_or_else(|| DaemonError::NotFound("cached reveal node is not stored".to_owned()))?;
        let (delta, ssp_target, cap, public_binding_hex) = self
            .reveal_node_context(req.channel_index, index.get())
            .await?;
        if req.ssp_target != ssp_target
            || req.delta_lifetime_checked_units_cap != cap
            || req.public_binding_hex != public_binding_hex
        {
            return Err(DaemonError::Refused(
                "cached reveal binding does not match local channel".to_owned(),
            ));
        }
        let local = reveal_node_local_share(&node)?;
        let opened = reveal_node_from_peer_share(&node, delta, &req.share_bits, peer_digest)?;
        self.store_known_secret(
            req.channel_index,
            index,
            req.expected_next_index,
            opened.value,
        )
        .await?;
        Ok((
            pb::RevealCachedResponse {
                share_bits: local.share_bits,
                mac_digest: local.mac_digest.to_vec(),
            },
            opened.value,
        ))
    }

    async fn reveal_node_context(
        &self,
        channel_index: u64,
        mask: u64,
    ) -> Result<(Block, u32, u64, String)> {
        let inner = self.inner.lock().await;
        let channel = inner
            .db
            .channels
            .get(&channel_key(channel_index))
            .ok_or_else(|| DaemonError::NotFound("channel is not enabled".to_owned()))?;
        if !channel.enabled {
            return Err(DaemonError::Refused("channel is disabled".to_owned()));
        }
        let delta = channel_delta(&inner.master_secret.0, channel_index, inner.cfg.role);
        let (public, _) = binding_pair(&inner, channel_index, mask);
        Ok((
            delta,
            channel.ssp_target,
            channel.delta_lifetime_checked_units_cap,
            to_hex(&public),
        ))
    }

    async fn reveal_persisted_node(
        &self,
        channel_index: u64,
        index: Index48,
        node: &Ag2pcSecureWires,
    ) -> Result<Value32> {
        let (endpoint, delta, ssp) = self.job_context(channel_index).await?;
        let digest = job_digest(
            channel_index,
            "reveal",
            index.get(),
            index.get(),
            ssp as u32,
        );
        reveal_node_fast_job(endpoint, node, delta, digest)
            .await
            .map_err(Into::into)
    }

    async fn store_known_secret(
        &self,
        channel_index: u64,
        index: Index48,
        expected_next_index: u64,
        secret: Value32,
    ) -> Result<()> {
        let mut inner = self.inner.lock().await;
        let key = channel_key(channel_index);
        let channel = inner
            .db
            .channels
            .get_mut(&key)
            .ok_or_else(|| DaemonError::NotFound("channel is not enabled".to_owned()))?;
        let mut redundant = false;
        let mut drop_keys = Vec::new();
        for (stored_index_s, stored_secret_hex) in &channel.known_secrets {
            let Ok(stored_index) = stored_index_s.parse::<u64>() else {
                drop_keys.push(stored_index_s.clone());
                continue;
            };
            let stored_secret = Value32::from_hex(stored_secret_hex)
                .map_err(|e| DaemonError::Parse(e.to_string()))?;
            if derive_from_known(stored_index, stored_secret, index.get()) == Some(secret) {
                redundant = true;
                break;
            }
            if derive_from_known(index.get(), secret, stored_index) == Some(stored_secret) {
                drop_keys.push(stored_index_s.clone());
            }
        }
        if !redundant {
            for key in &drop_keys {
                channel.known_secrets.remove(key.as_str());
            }
            channel
                .known_secrets
                .insert(index.get().to_string(), secret.to_hex());
        }
        channel.frontier_nodes.remove(&node_key(index.get()));
        channel.last_observed_next_reveal_index = Some(expected_next_index.saturating_sub(1));
        let mut mutations = Vec::new();
        if !redundant {
            mutations.push(upsert_secret_mutation(
                channel_index,
                index.get(),
                secret.to_hex(),
            ));
            for key in drop_keys {
                if let Ok(index) = key.parse::<u64>() {
                    mutations.push(delete_secret_mutation(channel_index, index));
                }
            }
        }
        mutations.push(delete_frontier_mutation(channel_index, index.get()));
        mutations.push(upsert_channel_mutation(channel_index, channel));
        drop(inner);
        self.db_writer
            .write_batch(mutations, DbDurability::Eventual)
            .await
    }

    async fn run_full_derivation(&self, channel_index: u64, index: Index48) -> Result<Value32> {
        let (role, port, peer_ip, share) = {
            let inner = self.inner.lock().await;
            let channel = inner
                .db
                .channels
                .get(&channel_key(channel_index))
                .ok_or_else(|| DaemonError::NotFound("channel is not enabled".to_owned()))?;
            if !channel.enabled {
                return Err(DaemonError::Refused("channel is disabled".to_owned()));
            }
            let peer_ip = inner
                .cfg
                .peer_url
                .as_deref()
                .and_then(peer_ip_from_url)
                .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
            (
                inner.cfg.role,
                inner.cfg.mpc_port,
                peer_ip,
                channel_seed_share(&inner.master_secret.0, channel_index),
            )
        };
        match run_party(PartyArgs {
            role,
            port,
            index_spec: IndexSpec::Single(index),
            share,
            peer_ip,
            allow_seed_reveal: false,
        })
        .await?
        {
            PartyOutput::Single(value) => Ok(value),
            PartyOutput::Range(_) => Err(DaemonError::Refused(
                "daemon full derivation fallback expected one output".to_owned(),
            )),
        }
    }

    async fn ensure_root(&self, channel_index: u64) -> Result<Ag2pcSecureWires> {
        if let Some(node) = self.load_node(channel_index, 0).await? {
            return Ok(node);
        }
        let (endpoint, delta, ssp) = self.job_context(channel_index).await?;
        let share = self.channel_share(channel_index).await?;
        let digest = job_digest(channel_index, "root", 0, 0, ssp as u32);
        let root =
            run_seed_root_job_with_circuit(endpoint, share, delta, digest, ssp, self.sha.as_ref())
                .await?;
        self.store_node(channel_index, 0, &root).await?;
        Ok(root)
    }

    async fn job_context(&self, channel_index: u64) -> Result<(MpcTcpEndpoint, Block, usize)> {
        let inner = self.inner.lock().await;
        let channel = inner
            .db
            .channels
            .get(&channel_key(channel_index))
            .ok_or_else(|| DaemonError::NotFound("channel is not enabled".to_owned()))?;
        if !channel.enabled {
            return Err(DaemonError::Refused("channel is disabled".to_owned()));
        }
        let peer_ip = inner
            .cfg
            .peer_url
            .as_deref()
            .and_then(peer_ip_from_url)
            .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let endpoint = MpcTcpEndpoint {
            role: inner.cfg.role,
            port: inner.cfg.mpc_port,
            peer_ip,
        };
        let delta = channel_delta(&inner.master_secret.0, channel_index, inner.cfg.role);
        let ssp = ssp_effective(channel.ssp_target, channel.delta_lifetime_checked_units_cap);
        Ok((endpoint, delta, ssp))
    }

    async fn begin_precompute_jobstream(
        &self,
        channel_index: u64,
        index: Index48,
        peer: PeerFrontierConfig,
        planned_checked_units: u64,
    ) -> Result<PrecomputeStart> {
        let resources = self.resource_model().await;
        let mut inner = self.inner.lock().await;
        let key = channel_key(channel_index);
        let key_node = node_key(index.get());
        let channel = inner
            .db
            .channels
            .get(&key)
            .ok_or_else(|| DaemonError::NotFound("channel is not enabled".to_owned()))?;
        if !channel.enabled {
            return Err(DaemonError::Refused("channel is disabled".to_owned()));
        }
        let (public, local) = binding_pair(&inner, channel_index, index.get());
        if channel.frontier_nodes.get(&key_node).is_some_and(|record| {
            record.public_binding_hex == to_hex(&public)
                && record.local_binding_hex == to_hex(&local)
        }) {
            return Ok(PrecomputeStart::AlreadyStored);
        }
        if inner
            .active_jobs
            .values()
            .any(|job| job.channel_index == channel_index)
        {
            return Err(DaemonError::Refused(
                "channel already has an active precompute job".to_owned(),
            ));
        }
        let worker_count = resources
            .effective_workers
            .min(peer.effective_workers.min(peer.workers.max(1)));
        if worker_count == 0 {
            return Err(DaemonError::Refused(
                "no shared precompute worker is available".to_owned(),
            ));
        }
        if inner.active_jobs.len() >= worker_count as usize {
            return Err(DaemonError::Refused(
                "all shared precompute workers are busy".to_owned(),
            ));
        }
        if resources.ram_overcommit_warning || peer.ram_overcommit_warning {
            eprintln!(
                "WARNING: RAM budget is below the modeled idle-session plus one-worker floor; precompute may exceed max_ram_bytes (local_raw_workers={}, peer_raw_workers={})",
                resources.ram_limited_workers_raw,
                peer.ram_limited_workers_raw
            );
        }
        let reserved: u64 = inner
            .active_jobs
            .values()
            .filter(|job| job.channel_index == channel_index)
            .map(|job| job.planned_checked_units)
            .sum();
        let used = channel
            .estimated_checked_units
            .saturating_add(reserved)
            .saturating_add(planned_checked_units);
        if used > channel.delta_lifetime_checked_units_cap {
            return Err(DaemonError::Refused(format!(
                "precompute would exceed Delta lifetime checked-unit cap: estimated={} reserved={} requested={} cap={}",
                channel.estimated_checked_units,
                reserved,
                planned_checked_units,
                channel.delta_lifetime_checked_units_cap
            )));
        }
        let channel = inner
            .db
            .channels
            .get_mut(&key)
            .ok_or_else(|| DaemonError::NotFound("channel is not enabled".to_owned()))?;
        channel.attempted_checked_units = channel
            .attempted_checked_units
            .saturating_add(planned_checked_units);
        inner.next_job_id = inner.next_job_id.saturating_add(1);
        let job_id = format!("precompute-{}-{}", channel_index, inner.next_job_id);
        inner.active_jobs.insert(
            job_id.clone(),
            JobRecord {
                channel_index,
                kind: "precompute".to_owned(),
                state: format!("grpc target={}", index.get()),
                planned_checked_units,
            },
        );
        let channel = inner
            .db
            .channels
            .get(&key)
            .expect("channel exists after attempted counter update");
        let mutations = vec![upsert_channel_mutation(channel_index, channel)];
        drop(inner);
        self.db_writer
            .write_batch(mutations, DbDurability::Eventual)
            .await?;
        Ok(PrecomputeStart::Run(PrecomputeJob {
            job_id,
            planned_checked_units,
        }))
    }

    async fn record_failed_precompute_attempt(
        &self,
        channel_index: u64,
        planned_checked_units: u64,
    ) -> Result<()> {
        let mut inner = self.inner.lock().await;
        let channel = inner
            .db
            .channels
            .get_mut(&channel_key(channel_index))
            .ok_or_else(|| DaemonError::NotFound("channel is not enabled".to_owned()))?;
        channel.attempted_checked_units = channel
            .attempted_checked_units
            .saturating_add(planned_checked_units);
        channel.failed_precompute_jobs = channel.failed_precompute_jobs.saturating_add(1);
        let mutations = vec![upsert_channel_mutation(channel_index, channel)];
        drop(inner);
        self.db_writer
            .write_batch(mutations, DbDurability::Eventual)
            .await
    }

    async fn begin_incoming_precompute_session(
        &self,
        descriptor: &GrpcJobDescriptor,
    ) -> Result<IncomingPrecomputeSession> {
        let inner = self.inner.lock().await;
        let key = channel_key(descriptor.channel_index);
        let channel = inner
            .db
            .channels
            .get(&key)
            .ok_or_else(|| DaemonError::NotFound("channel is not enabled".to_owned()))?;
        if !channel.enabled {
            return Err(DaemonError::Refused("channel is disabled".to_owned()));
        }
        if descriptor.ssp_target != channel.ssp_target
            || descriptor.delta_lifetime_checked_units_cap
                != channel.delta_lifetime_checked_units_cap
        {
            return Err(DaemonError::Refused(
                "incoming JobStream security parameters do not match".to_owned(),
            ));
        }
        let ssp = ssp_effective(channel.ssp_target, channel.delta_lifetime_checked_units_cap);
        if descriptor.ssp != ssp as u32 {
            return Err(DaemonError::Refused(
                "incoming JobStream uses the wrong security parameter".to_owned(),
            ));
        }
        let expected_digest = job_digest(
            descriptor.channel_index,
            "precompute-session",
            0,
            0,
            descriptor.ssp,
        );
        if descriptor.digest != expected_digest {
            return Err(DaemonError::Refused(
                "incoming JobStream digest does not match local job".to_owned(),
            ));
        }
        if descriptor.target_index != 0 {
            return Err(DaemonError::Refused(
                "incoming precompute session must use target index 0".to_owned(),
            ));
        }
        let delta = channel_delta(
            &inner.master_secret.0,
            descriptor.channel_index,
            inner.cfg.role,
        );
        let share = channel_seed_share(&inner.master_secret.0, descriptor.channel_index);
        Ok(IncomingPrecomputeSession { delta, ssp, share })
    }

    async fn begin_incoming_precompute_target(
        &self,
        descriptor: &GrpcJobDescriptor,
        index: Index48,
        planned_checked_units: u64,
    ) -> Result<IncomingPrecomputeJob> {
        let resources = self.resource_model().await;
        let mut inner = self.inner.lock().await;
        let key = channel_key(descriptor.channel_index);
        let channel = inner
            .db
            .channels
            .get(&key)
            .ok_or_else(|| DaemonError::NotFound("channel is not enabled".to_owned()))?;
        if !channel.enabled {
            return Err(DaemonError::Refused("channel is disabled".to_owned()));
        }
        if descriptor.ssp_target != channel.ssp_target
            || descriptor.delta_lifetime_checked_units_cap
                != channel.delta_lifetime_checked_units_cap
        {
            return Err(DaemonError::Refused(
                "incoming JobStream security parameters do not match".to_owned(),
            ));
        }
        if inner.active_jobs.len() >= resources.effective_workers as usize {
            return Err(DaemonError::Refused(
                "all local precompute workers are busy".to_owned(),
            ));
        }
        if resources.ram_overcommit_warning {
            eprintln!(
                "WARNING: RAM budget is below the modeled idle-session plus one-worker floor; incoming precompute may exceed max_ram_bytes"
            );
        }
        if inner
            .active_jobs
            .values()
            .any(|job| job.channel_index == descriptor.channel_index)
        {
            return Err(DaemonError::Refused(
                "channel already has an active precompute job".to_owned(),
            ));
        }
        let reserved: u64 = inner
            .active_jobs
            .values()
            .filter(|job| job.channel_index == descriptor.channel_index)
            .map(|job| job.planned_checked_units)
            .sum();
        let used = channel
            .estimated_checked_units
            .saturating_add(reserved)
            .saturating_add(planned_checked_units);
        if used > channel.delta_lifetime_checked_units_cap {
            return Err(DaemonError::Refused(
                "incoming JobStream would exceed Delta lifetime checked-unit cap".to_owned(),
            ));
        }
        let channel = inner
            .db
            .channels
            .get_mut(&key)
            .ok_or_else(|| DaemonError::NotFound("channel is not enabled".to_owned()))?;
        channel.attempted_checked_units = channel
            .attempted_checked_units
            .saturating_add(planned_checked_units);
        let job_id = format!("{}-target-{}", descriptor.job_id, index.get());
        inner.active_jobs.insert(
            job_id.clone(),
            JobRecord {
                channel_index: descriptor.channel_index,
                kind: "precompute".to_owned(),
                state: format!("grpc target={}", index.get()),
                planned_checked_units,
            },
        );
        let channel = inner
            .db
            .channels
            .get(&key)
            .expect("channel exists after incoming attempted counter update");
        let mutations = vec![upsert_channel_mutation(descriptor.channel_index, channel)];
        drop(inner);
        self.db_writer
            .write_batch(mutations, DbDurability::Eventual)
            .await?;
        Ok(IncomingPrecomputeJob { job_id })
    }

    async fn open_peer_job_streams(
        &self,
        descriptor: &GrpcJobDescriptor,
    ) -> Result<Ag2pcStreams<ChannelByteStream>> {
        let peer_channel = self
            .peer_channel
            .clone()
            .ok_or_else(|| DaemonError::Refused("peer URL is not configured".to_owned()))?;
        let main = open_peer_job_channel(peer_channel.clone(), descriptor, 1).await?;
        let sibling = open_peer_job_channel(peer_channel, descriptor, 2).await?;
        Ok(Ag2pcStreams { main, sibling })
    }

    async fn channel_share(&self, channel_index: u64) -> Result<Value32> {
        let inner = self.inner.lock().await;
        Ok(channel_seed_share(&inner.master_secret.0, channel_index))
    }

    async fn load_node(&self, channel_index: u64, mask: u64) -> Result<Option<Ag2pcSecureWires>> {
        let inner = self.inner.lock().await;
        let Some(channel) = inner.db.channels.get(&channel_key(channel_index)) else {
            return Ok(None);
        };
        let Some(record) = channel.frontier_nodes.get(&node_key(mask)) else {
            return Ok(None);
        };
        let (public, local) = binding_pair(&inner, channel_index, mask);
        if record.public_binding_hex != to_hex(&public)
            || record.local_binding_hex != to_hex(&local)
        {
            return Ok(None);
        }
        Ok(Some(record.wires.to_secure_wires()))
    }

    async fn store_node(
        &self,
        channel_index: u64,
        mask: u64,
        wires: &Ag2pcSecureWires,
    ) -> Result<()> {
        let mut inner = self.inner.lock().await;
        let (public, local) = binding_pair(&inner, channel_index, mask);
        let channel = inner
            .db
            .channels
            .get_mut(&channel_key(channel_index))
            .ok_or_else(|| DaemonError::NotFound("channel is not enabled".to_owned()))?;
        let record = WireRecord {
            public_binding_hex: to_hex(&public),
            local_binding_hex: to_hex(&local),
            wires: SerializableWires::from_secure_wires(wires),
        };
        channel
            .frontier_nodes
            .insert(node_key(mask), record.clone());
        let mutations = vec![upsert_frontier_mutation(channel_index, mask, record)];
        drop(inner);
        self.db_writer
            .write_batch(mutations, DbDurability::Eventual)
            .await
    }

    async fn store_precomputed_target_wires_and_finish_job(
        &self,
        channel_index: u64,
        job_id: &str,
        planned_checked_units: u64,
        target_mask: u64,
        wires: Ag2pcSecureWires,
    ) -> Result<u64> {
        let mut inner = self.inner.lock().await;
        let key = channel_key(channel_index);
        let (public, local) = binding_pair(&inner, channel_index, target_mask);
        let channel = inner
            .db
            .channels
            .get_mut(&key)
            .ok_or_else(|| DaemonError::NotFound("channel is not enabled".to_owned()))?;
        if !channel.enabled {
            return Err(DaemonError::Refused("channel is disabled".to_owned()));
        }
        let record = WireRecord {
            public_binding_hex: to_hex(&public),
            local_binding_hex: to_hex(&local),
            wires: SerializableWires::from_secure_wires(&wires),
        };
        channel
            .frontier_nodes
            .insert(node_key(target_mask), record.clone());
        if let Some(channel) = inner.db.channels.get_mut(&key) {
            channel.estimated_checked_units = channel
                .estimated_checked_units
                .saturating_add(planned_checked_units);
        }
        inner.active_jobs.remove(job_id);
        let channel = inner
            .db
            .channels
            .get(&key)
            .expect("channel exists after update");
        let mutations = vec![
            upsert_frontier_mutation(channel_index, target_mask, record),
            upsert_channel_mutation(channel_index, channel),
        ];
        drop(inner);
        self.db_writer
            .write_batch(mutations, DbDurability::Eventual)
            .await?;
        Ok(1)
    }

    async fn peer_frontier(&self, channel_index: u64) -> Result<Option<PeerFrontierConfig>> {
        Ok(self
            .peer_frontier_response(channel_index)
            .await?
            .map(|(_, config)| config))
    }

    async fn peer_frontier_response(
        &self,
        channel_index: u64,
    ) -> Result<Option<(pb::GetFrontierResponse, PeerFrontierConfig)>> {
        let Some(peer_channel) = self.peer_channel.clone() else {
            return Ok(None);
        };
        let mut client = pb::peer_service_client::PeerServiceClient::new(peer_channel);
        let response = client
            .get_frontier(pb::GetFrontierRequest { channel_index })
            .await?
            .into_inner();
        let config = PeerFrontierConfig {
            channel_enabled: response.channel_enabled,
            precompute: response.precompute,
            workers: response.workers,
            effective_workers: response.effective_workers.max(1),
            ram_limited_workers_raw: response.ram_limited_workers_raw,
            ram_overcommit_warning: response.ram_overcommit_warning,
            ssp_target: response.ssp_target,
            delta_lifetime_checked_units_cap: response.delta_lifetime_checked_units_cap,
        };
        Ok(Some((response, config)))
    }

    async fn finish_job(&self, job_id: &str, failed: bool) {
        let mut inner = self.inner.lock().await;
        let mut mutations = Vec::new();
        if let Some(job) = inner.active_jobs.remove(job_id) {
            if failed {
                if let Some(channel) = inner.db.channels.get_mut(&channel_key(job.channel_index)) {
                    channel.failed_precompute_jobs =
                        channel.failed_precompute_jobs.saturating_add(1);
                    mutations.push(upsert_channel_mutation(job.channel_index, channel));
                }
            }
        }
        drop(inner);
        let _ = self
            .db_writer
            .write_batch(mutations, DbDurability::Eventual)
            .await;
    }

    async fn reconcile_with_peer(&self, channel_index: u64) -> Result<()> {
        let Some((response, _peer_config)) = self.peer_frontier_response(channel_index).await?
        else {
            return Ok(());
        };
        if !response.channel_enabled {
            return Ok(());
        }
        let peer: HashMap<u64, String> = response
            .nodes
            .into_iter()
            .map(|node| (node.mask, node.public_binding_hex))
            .collect();
        let mut inner = self.inner.lock().await;
        let key = channel_key(channel_index);
        let Some(channel) = inner.db.channels.get_mut(&key) else {
            return Ok(());
        };
        let mut drop_masks = Vec::new();
        for (mask_s, node) in &channel.frontier_nodes {
            let Ok(mask) = mask_s.parse::<u64>() else {
                drop_masks.push(mask_s.clone());
                continue;
            };
            if peer.get(&mask) != Some(&node.public_binding_hex) {
                drop_masks.push(mask_s.clone());
            }
        }
        let mut mutations = Vec::new();
        for mask in drop_masks {
            channel.frontier_nodes.remove(&mask);
            if let Ok(mask) = mask.parse::<u64>() {
                mutations.push(delete_frontier_mutation(channel_index, mask));
            }
        }
        drop(inner);
        self.db_writer
            .write_batch(mutations, DbDurability::Eventual)
            .await
    }

    async fn derive_known(
        &self,
        channel_index: u64,
        requested: Index48,
    ) -> Result<Option<Value32>> {
        let inner = self.inner.lock().await;
        let Some(channel) = inner.db.channels.get(&channel_key(channel_index)) else {
            return Ok(None);
        };
        for (index_s, secret_hex) in &channel.known_secrets {
            let Ok(from_index) = index_s.parse::<u64>() else {
                continue;
            };
            let secret =
                Value32::from_hex(secret_hex).map_err(|e| DaemonError::Parse(e.to_string()))?;
            if let Some(out) = derive_from_known(from_index, secret, requested.get()) {
                return Ok(Some(out));
            }
        }
        Ok(None)
    }
}

impl SerializableWires {
    fn from_secure_wires(wires: &Ag2pcSecureWires) -> Self {
        Self {
            lambda: wires.lambda.clone(),
            mac: wires
                .wire_bundle
                .iter()
                .map(|bundle| *bundle.mac.as_bytes())
                .collect(),
            key: wires
                .wire_bundle
                .iter()
                .map(|bundle| *bundle.key.as_bytes())
                .collect(),
        }
    }

    fn to_secure_wires(&self) -> Ag2pcSecureWires {
        Ag2pcSecureWires {
            lambda: self.lambda.clone(),
            wire_bundle: self
                .mac
                .iter()
                .zip(&self.key)
                .map(|(mac, key)| AShareBundle {
                    mac: Block::from_bytes(*mac),
                    key: Block::from_bytes(*key),
                })
                .collect(),
            label0: Vec::new(),
            eval_label: Vec::new(),
        }
    }
}

fn channel_response(index: u64, channel: &ChannelRecord) -> pb::ChannelResponse {
    pb::ChannelResponse {
        channel_index: index,
        enabled: channel.enabled,
        precompute: channel.precompute_target,
        ssp_target: channel.ssp_target,
        delta_lifetime_checked_units_cap: channel.delta_lifetime_checked_units_cap,
        frontier_nodes: channel.frontier_nodes.len() as u64,
        known_secrets: channel.known_secrets.len() as u64,
        estimated_checked_units: channel.estimated_checked_units,
        attempted_checked_units: channel.attempted_checked_units,
        failed_precompute_jobs: channel.failed_precompute_jobs,
    }
}

fn to_status(err: DaemonError) -> Status {
    match err {
        DaemonError::NotFound(msg) => Status::not_found(msg),
        DaemonError::Refused(msg) | DaemonError::Usage(msg) | DaemonError::Parse(msg) => {
            Status::invalid_argument(msg)
        }
        other => Status::internal(other.to_string()),
    }
}

fn parse_mac_digest(bytes: Vec<u8>, context: &str) -> Result<[u8; HASH_DIGEST_BYTES]> {
    if bytes.len() != HASH_DIGEST_BYTES {
        return Err(DaemonError::Parse(format!(
            "{context} MAC digest must be {HASH_DIGEST_BYTES} bytes"
        )));
    }
    let mut out = [0u8; HASH_DIGEST_BYTES];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn peer_reveal_wait() -> Duration {
    std::env::var("SHACHAIN2PC_PEER_REVEAL_WAIT_MS")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .map(Duration::from_millis)
        .unwrap_or(DEFAULT_PEER_REVEAL_WAIT)
}

fn binding_pair(inner: &Inner, channel_index: u64, mask: u64) -> ([u8; 32], [u8; 32]) {
    let channel = inner
        .db
        .channels
        .get(&channel_key(channel_index))
        .expect("channel exists for binding");
    let public = public_binding(
        channel_index,
        mask,
        channel.ssp_target,
        channel.delta_lifetime_checked_units_cap,
    );
    let mut hasher = Sha256::new();
    hasher.update(b"shachain2pc frontier local binding v1");
    hasher.update(public);
    hasher.update([inner.cfg.role.party_id()]);
    (public, hasher.finalize().into())
}

fn public_binding(channel_index: u64, mask: u64, ssp_target: u32, cap: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"shachain2pc frontier public binding v1");
    hasher.update(channel_index.to_le_bytes());
    hasher.update(mask.to_le_bytes());
    hasher.update(ssp_target.to_le_bytes());
    hasher.update(cap.to_le_bytes());
    hasher.update(PROTOCOL_VERSION.to_le_bytes());
    hasher.finalize().into()
}

fn job_digest(
    channel_index: u64,
    kind: &str,
    parent_mask: u64,
    child_mask: u64,
    ssp: u32,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"shachain2pc daemon one-H job v1");
    hasher.update(channel_index.to_le_bytes());
    hasher.update(kind.as_bytes());
    hasher.update(parent_mask.to_le_bytes());
    hasher.update(child_mask.to_le_bytes());
    hasher.update(ssp.to_le_bytes());
    hasher.update(PROTOCOL_VERSION.to_le_bytes());
    hasher.finalize().into()
}

fn descriptor_from_job_frame(
    frame: &pb::JobFrame,
) -> std::result::Result<GrpcJobDescriptor, &'static str> {
    if frame.job_id.is_empty() {
        return Err("JobStream job_id is empty");
    }
    if frame.digest.len() != 32 {
        return Err("JobStream digest must be 32 bytes");
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&frame.digest);
    Ok(GrpcJobDescriptor {
        job_id: frame.job_id.clone(),
        channel_index: frame.channel_index,
        target_index: frame.target_index,
        ssp: frame.ssp,
        ssp_target: frame.ssp_target,
        delta_lifetime_checked_units_cap: frame.delta_lifetime_checked_units_cap,
        digest,
    })
}

fn validate_job_channel(channel: u32) -> std::result::Result<u32, &'static str> {
    match channel {
        1 | 2 => Ok(channel),
        _ => Err("JobStream channel must be 1 or 2"),
    }
}

fn validate_job_payload_context(frame: &pb::JobFrame, descriptor: &GrpcJobDescriptor) -> bool {
    frame.channel_index == descriptor.channel_index
        && frame.target_index == descriptor.target_index
        && frame.ssp == descriptor.ssp
        && frame.ssp_target == descriptor.ssp_target
        && frame.delta_lifetime_checked_units_cap == descriptor.delta_lifetime_checked_units_cap
        && frame.digest.as_slice() == descriptor.digest
}

async fn run_jobstream_session_handshake(
    role: Role,
    descriptor: &GrpcJobDescriptor,
    streams: Ag2pcStreams<ChannelByteStream>,
) -> Result<Ag2pcStreams<ChannelByteStream>> {
    let params = RunnerSessionParams::new(
        descriptor.ssp,
        descriptor.digest.to_vec(),
        jobstream_session_binding(descriptor),
    );
    let mut framed = TransportPair {
        main: ByteFrameTransport::new(streams.main),
        sibling: ByteFrameTransport::new(streams.sibling),
    };
    run_session_handshake(
        &mut framed,
        descriptor.job_id.as_bytes().to_vec(),
        role,
        params,
    )
    .await
    .map_err(|e| DaemonError::Refused(format!("JobStream session handshake failed: {e}")))?;
    Ok(Ag2pcStreams {
        main: framed.main.into_inner(),
        sibling: framed.sibling.into_inner(),
    })
}

fn jobstream_session_binding(descriptor: &GrpcJobDescriptor) -> Vec<u8> {
    let mut out = Vec::with_capacity(JOBSTREAM_SESSION_BINDING_DOMAIN.len() + 8 + 8 + 4 + 8 + 4);
    out.extend_from_slice(JOBSTREAM_SESSION_BINDING_DOMAIN);
    out.extend_from_slice(&descriptor.channel_index.to_le_bytes());
    out.extend_from_slice(&descriptor.target_index.to_le_bytes());
    out.extend_from_slice(&descriptor.ssp_target.to_le_bytes());
    out.extend_from_slice(&descriptor.delta_lifetime_checked_units_cap.to_le_bytes());
    out.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    out
}

fn job_frame(
    descriptor: &GrpcJobDescriptor,
    channel: u32,
    start: bool,
    payload: Vec<u8>,
) -> pb::JobFrame {
    pb::JobFrame {
        job_id: descriptor.job_id.clone(),
        channel,
        channel_index: descriptor.channel_index,
        target_index: descriptor.target_index,
        ssp: descriptor.ssp,
        digest: descriptor.digest.to_vec(),
        start,
        payload,
        ssp_target: descriptor.ssp_target,
        delta_lifetime_checked_units_cap: descriptor.delta_lifetime_checked_units_cap,
    }
}

pub fn channel_seed_share(master_secret: &[u8], channel_index: u64) -> Value32 {
    let mut out = [0u8; 32];
    hkdf_expand(
        master_secret,
        b"",
        &info_with_u64(b"shachain2pc channel seed share v1", channel_index),
        &mut out,
    );
    Value32::new(out)
}

pub fn channel_delta(master_secret: &[u8], channel_index: u64, role: Role) -> Block {
    let mut out = [0u8; 16];
    let mut info = info_with_u64(b"shachain2pc channel delta v1", channel_index);
    info.push(role.party_id());
    hkdf_expand(master_secret, b"", &info, &mut out);
    normalize_ag2pc_delta(role, Block::from_bytes(out))
}

fn derive_db_key(master_secret: &[u8], salt: &[u8; DB_SALT_LEN]) -> [u8; 32] {
    let mut out = [0u8; 32];
    hkdf_expand(
        master_secret,
        salt,
        b"shachain2pc daemon db key v1",
        &mut out,
    );
    out
}

fn hkdf_expand(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) {
    let prk = hmac_sha256(if salt.is_empty() { &[0u8; 32] } else { salt }, ikm);
    let mut t = Vec::new();
    let mut offset = 0usize;
    for counter in 1u8.. {
        let mut msg = Vec::with_capacity(t.len() + info.len() + 1);
        msg.extend_from_slice(&t);
        msg.extend_from_slice(info);
        msg.push(counter);
        t = hmac_sha256(&prk, &msg).to_vec();
        let take = (out.len() - offset).min(t.len());
        out[offset..offset + take].copy_from_slice(&t[..take]);
        offset += take;
        if offset == out.len() {
            break;
        }
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn peer_channel_from_url(
    peer_url: &Option<String>,
    tls: Option<&PeerTlsConfig>,
) -> Result<Option<Channel>> {
    let Some(peer_url) = peer_url else {
        return Ok(None);
    };
    let mut endpoint = Endpoint::from_shared(peer_url.clone())
        .map_err(|e| DaemonError::Parse(format!("bad peer URL: {e}")))?;
    if let Some(tls) = tls {
        endpoint = endpoint.tls_config(peer_client_tls_config(tls)?)?;
    }
    Ok(Some(endpoint.connect_lazy()))
}

fn peer_server_tls_config(tls: &PeerTlsConfig) -> Result<ServerTlsConfig> {
    Ok(ServerTlsConfig::new()
        .identity(load_tls_identity(tls)?)
        .client_ca_root(load_tls_ca(tls)?))
}

fn peer_client_tls_config(tls: &PeerTlsConfig) -> Result<ClientTlsConfig> {
    Ok(ClientTlsConfig::new()
        .ca_certificate(load_tls_ca(tls)?)
        .identity(load_tls_identity(tls)?)
        .domain_name(tls.domain_name.clone()))
}

fn load_tls_identity(tls: &PeerTlsConfig) -> Result<Identity> {
    let cert = fs::read(&tls.cert_path)?;
    let key = fs::read(&tls.key_path)?;
    Ok(Identity::from_pem(cert, key))
}

fn load_tls_ca(tls: &PeerTlsConfig) -> Result<Certificate> {
    Ok(Certificate::from_pem(fs::read(&tls.ca_path)?))
}

fn info_with_u64(prefix: &[u8], value: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(prefix.len() + 8);
    out.extend_from_slice(prefix);
    out.extend_from_slice(&value.to_le_bytes());
    out
}

fn ssp_effective(ssp_target: u32, cap: u64) -> usize {
    let cap_log = if cap <= 1 {
        0
    } else {
        u64::BITS - (cap - 1).leading_zeros()
    };
    (ssp_target + cap_log) as usize
}

fn resource_model(inner: &Inner, live_session_count: u64) -> ResourceModel {
    let current = current_rss_bytes().unwrap_or(0);
    resource_model_with_current_rss(inner, live_session_count, current)
}

fn resource_model_with_current_rss(
    inner: &Inner,
    live_session_count: u64,
    current: u64,
) -> ResourceModel {
    let baseline = inner.baseline_daemon_rss_bytes;
    let idle_sessions = live_session_count.saturating_mul(DEFAULT_IDLE_SESSION_RSS_BYTES);
    let modeled_floor = baseline.saturating_add(idle_sessions);
    let active_jobs = inner.active_jobs.len() as u64;
    let observed_floor =
        current.saturating_sub(active_jobs.saturating_mul(DEFAULT_ONE_H_WORKER_PEAK_RSS_BYTES));
    let rss_floor = modeled_floor.max(observed_floor);
    let worker_budget = inner.cfg.max_ram_bytes.saturating_sub(rss_floor);
    let raw = worker_budget / DEFAULT_ONE_H_WORKER_PEAK_RSS_BYTES;
    let ram_limited_workers_raw = raw.min(u32::MAX as u64) as u32;
    let ram_limited_workers = ram_limited_workers_raw.max(1);
    let effective_workers = inner.cfg.workers.min(ram_limited_workers).max(1);
    let modeled_reserved =
        rss_floor.saturating_add(active_jobs.saturating_mul(DEFAULT_ONE_H_WORKER_PEAK_RSS_BYTES));
    let active_reserved = active_jobs
        .saturating_mul(DEFAULT_ONE_H_WORKER_PEAK_RSS_BYTES)
        .saturating_add(idle_sessions);
    let reserved_ram_bytes = modeled_reserved.max(current).max(active_reserved);
    ResourceModel {
        configured_workers: inner.cfg.workers,
        effective_workers,
        ram_limited_workers_raw,
        ram_overcommit_warning: ram_limited_workers_raw == 0,
        baseline_daemon_rss_bytes: baseline,
        current_rss_bytes: current,
        idle_session_rss_estimate_bytes: DEFAULT_IDLE_SESSION_RSS_BYTES,
        one_h_worker_peak_rss_estimate_bytes: DEFAULT_ONE_H_WORKER_PEAK_RSS_BYTES,
        live_session_count,
        reserved_ram_bytes,
    }
}

fn current_rss_bytes() -> Option<u64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    parse_proc_status_kib(&status, "VmRSS:").map(|kib| kib.saturating_mul(1024))
}

fn parse_proc_status_kib(status: &str, field: &str) -> Option<u64> {
    let line = status.lines().find(|line| line.starts_with(field))?;
    let mut parts = line.split_whitespace();
    let _name = parts.next()?;
    parts.next()?.parse().ok()
}

fn set_bits_desc(value: u64) -> Vec<usize> {
    let mut bits = Vec::new();
    for bit in (0..INDEX_BITS).rev() {
        if ((value >> bit) & 1) != 0 {
            bits.push(bit as usize);
        }
    }
    bits
}

fn derive_from_known(from_index: u64, secret: Value32, to_index: u64) -> Option<Value32> {
    if from_index & !to_index != 0 {
        return None;
    }
    let missing = to_index & !from_index;
    if from_index != 0 {
        let lowest_applied = from_index.trailing_zeros();
        if missing >> lowest_applied != 0 {
            return None;
        }
    }
    let mut p = secret.into_bytes();
    for bit in set_bits_desc(missing) {
        p[bit / 8] ^= 1u8 << (bit % 8);
        let digest = Sha256::digest(p);
        p.copy_from_slice(&digest);
    }
    Some(Value32::new(p))
}

pub fn reference_for_channel(
    master_a: &[u8],
    master_b: &[u8],
    channel_index: u64,
    index: Index48,
) -> Value32 {
    let seed = channel_seed_share(master_a, channel_index)
        .xor(channel_seed_share(master_b, channel_index));
    generate_from_seed(seed, index)
}

fn channel_key(index: u64) -> String {
    index.to_string()
}

fn node_key(mask: u64) -> String {
    mask.to_string()
}

fn daemon_id(master_secret: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"shachain2pc daemon id v1");
    hasher.update(master_secret);
    to_hex(&hasher.finalize())
}

fn load_or_create_cookie(cfg: &DaemonConfig) -> Result<String> {
    let Some(path) = &cfg.cookie_file else {
        return random_cookie();
    };
    if path.exists() {
        return Ok(fs::read_to_string(path)?.trim().to_owned());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let cookie = random_cookie()?;
    fs::write(path, format!("{cookie}\n"))?;
    Ok(cookie)
}

fn random_cookie() -> Result<String> {
    let mut bytes = [0u8; 32];
    rand_bytes(&mut bytes).map_err(|e| DaemonError::Crypto(e.to_string()))?;
    Ok(to_hex(&bytes))
}

fn write_control_file(
    path: &Path,
    addr: &SocketAddr,
    cookie: &str,
    cfg: &DaemonConfig,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let cookie_path = if let Some(path) = &cfg.cookie_file {
        path.to_string_lossy().into_owned()
    } else {
        format!("inline:{cookie}")
    };
    let file = ControlFile {
        addr: format!("http://{addr}"),
        cookie_path,
    };
    fs::write(path, serde_json::to_vec_pretty(&file)?)?;
    Ok(())
}

pub fn read_control_file(path: &Path) -> Result<(String, String)> {
    let file: ControlFile = serde_json::from_slice(&fs::read(path)?)?;
    let cookie = if let Some(inline) = file.cookie_path.strip_prefix("inline:") {
        inline.to_owned()
    } else {
        fs::read_to_string(file.cookie_path)?.trim().to_owned()
    };
    Ok((file.addr, cookie))
}

fn peer_ip_from_url(url: &str) -> Option<IpAddr> {
    let without_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let host = without_scheme.split('/').next().unwrap_or(without_scheme);
    let host = host.rsplit_once(':').map(|(host, _)| host).unwrap_or(host);
    host.parse().ok()
}

fn read_array<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Result<[u8; N]> {
    if *cursor + N > bytes.len() {
        return Err(DaemonError::Crypto("encrypted DB is truncated".to_owned()));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[*cursor..*cursor + N]);
    *cursor += N;
    Ok(out)
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(nibble_hex(b >> 4));
        out.push(nibble_hex(b & 0x0f));
    }
    out
}

fn from_hex(input: &str) -> Result<Vec<u8>> {
    if input.len().checked_rem(2) != Some(0) {
        return Err(DaemonError::Parse("hex string has odd length".to_owned()));
    }
    let byte_len = input.len() / 2;
    let mut out = Vec::with_capacity(byte_len);
    let bytes = input.as_bytes();
    for i in 0..byte_len {
        out.push((hex_nibble(bytes[2 * i])? << 4) | hex_nibble(bytes[2 * i + 1])?);
    }
    Ok(out)
}

fn hex_nibble(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(DaemonError::Parse(format!("bad hex char '{}'", c as char))),
    }
}

fn nibble_hex(n: u8) -> char {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    char::from(DIGITS[usize::from(n & 0x0f)])
}

pub fn parse_master_secret_hex(input: &str) -> Result<Vec<u8>> {
    from_hex(input)
}

pub fn parse_role(input: &str) -> Result<Role> {
    let id = input
        .parse::<u8>()
        .map_err(|_| DaemonError::Parse(format!("role must be 1 or 2, got {input}")))?;
    Role::from_party_id(id).map_err(|e| DaemonError::Parse(e.to_string()))
}

pub fn parse_addr(input: &str) -> Result<SocketAddr> {
    input
        .parse()
        .map_err(|_| DaemonError::Parse(format!("bad socket address: {input}")))
}

pub fn max_index() -> u64 {
    MAX_INDEX
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn fixed_delta_derivation_is_role_structured_and_stable() {
        let master = [7u8; 32];
        let a = channel_delta(&master, 42, Role::Alice);
        let b = channel_delta(&master, 42, Role::Bob);
        assert_eq!(a, channel_delta(&master, 42, Role::Alice));
        assert_ne!(a, b);
        assert_eq!(a.as_bytes()[0] & 1, 1);
        assert_eq!(a.as_bytes()[0] & 2, 2);
        assert_eq!(b.as_bytes()[0] & 1, 1);
        assert_eq!(b.as_bytes()[0] & 2, 0);
    }

    #[tokio::test]
    async fn redb_store_round_trips_and_rejects_wrong_secret() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("db.enc");
        let master = vec![1u8; 32];
        let (_, writer) = DbStore::open(path.clone(), &master).unwrap();
        let mut channel = empty_channel_record();
        channel.enabled = true;
        channel.precompute_target = 7;
        channel.delta_lifetime_checked_units_cap = 100;
        writer
            .write_batch(
                vec![
                    upsert_channel_mutation(1, &channel),
                    upsert_secret_mutation(1, 3, "11".repeat(32)),
                    upsert_frontier_mutation(1, 5, sample_wire_record()),
                ],
                DbDurability::Immediate,
            )
            .await
            .unwrap();
        close_writer_for_test(writer).await;

        let (loaded, writer) = DbStore::open(path.clone(), &master).unwrap();
        close_writer_for_test(writer).await;
        let loaded_channel = loaded.channels.get("1").unwrap();
        assert!(loaded_channel.enabled);
        assert_eq!(loaded_channel.precompute_target, 7);
        assert!(loaded_channel.known_secrets.contains_key("3"));
        assert!(loaded_channel.frontier_nodes.contains_key("5"));
        assert!(DbStore::open(path, &[2u8; 32]).is_err());
    }

    #[test]
    fn redb_stored_keys_are_opaque_and_addressable() {
        let master = [1u8; 32];
        let subkeys = DbSubkeys::derive(&master);
        let other = DbSubkeys::derive(&[2u8; 32]);
        let logical = LogicalKey::secret(42, 0x0102_0304_0506);
        let key = stored_key(&subkeys, logical);
        assert_eq!(key, stored_key(&subkeys, logical));
        assert_ne!(key, stored_key(&other, logical));
        assert_ne!(&key[..17], &logical.canonical_bytes());
        assert!(!key.windows(8).any(|window| window == 42u64.to_be_bytes()));
        assert!(!key
            .windows(8)
            .any(|window| window == 0x0102_0304_0506u64.to_be_bytes()));
    }

    #[tokio::test]
    async fn redb_store_rejects_tampered_value() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("db.redb");
        let master = vec![3u8; 32];
        let (_, writer) = DbStore::open(path.clone(), &master).unwrap();
        let mut channel = empty_channel_record();
        channel.enabled = true;
        writer
            .write_batch(
                vec![upsert_channel_mutation(9, &channel)],
                DbDurability::Immediate,
            )
            .await
            .unwrap();
        close_writer_for_test(writer).await;
        tamper_first_redb_value(&path);
        assert!(DbStore::open(path, &master).is_err());
    }

    #[tokio::test]
    async fn legacy_blob_migrates_to_redb() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("db.enc");
        let master = vec![4u8; 32];
        let mut db = PlainDb::default();
        let mut channel = empty_channel_record();
        channel.enabled = true;
        channel
            .known_secrets
            .insert("7".to_owned(), "22".repeat(32));
        db.channels.insert("2".to_owned(), channel);
        write_legacy_db_for_test(&path, &master, &db);

        let (loaded, writer) = DbStore::open(path.clone(), &master).unwrap();
        close_writer_for_test(writer).await;
        assert!(loaded
            .channels
            .get("2")
            .unwrap()
            .known_secrets
            .contains_key("7"));
        assert!(path.exists());
        assert!(dir.path().join("db.enc.migrated").exists());
    }

    #[test]
    fn durable_wires_do_not_serialize_session_labels() {
        let wires = Ag2pcSecureWires {
            lambda: vec![1],
            wire_bundle: vec![AShareBundle {
                mac: Block::make(1, 2),
                key: Block::make(3, 4),
            }],
            label0: vec![Block::make(5, 6)],
            eval_label: vec![Block::make(7, 8)],
        };
        let durable = SerializableWires::from_secure_wires(&wires);
        let loaded = durable.to_secure_wires();
        assert_eq!(loaded.lambda, wires.lambda);
        assert_eq!(loaded.wire_bundle, wires.wire_bundle);
        assert!(loaded.label0.is_empty());
        assert!(loaded.eval_label.is_empty());
    }

    #[test]
    fn daemon_has_single_sha_circuit_parse_site() {
        const NEEDLE: &str = concat!("sha256_compress_", "gadget(");
        let source = include_str!("lib.rs");
        assert_eq!(source.matches(NEEDLE).count(), 1);
    }

    #[test]
    fn circuit_is_shareable_between_tasks() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Circuit>();
    }

    #[test]
    fn known_secret_derivation_matches_reference_when_possible() {
        let seed =
            Value32::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                .unwrap();
        let from = Index48::from_hex("2").unwrap();
        let to = Index48::from_hex("3").unwrap();
        let from_secret = generate_from_seed(seed, from);
        let derived = derive_from_known(from.get(), from_secret, to.get()).unwrap();
        assert_eq!(derived, generate_from_seed(seed, to));
        assert!(derive_from_known(to.get(), generate_from_seed(seed, to), from.get()).is_none());
        assert!(derive_from_known(
            1,
            generate_from_seed(seed, Index48::from_hex("1").unwrap()),
            to.get()
        )
        .is_none());
    }

    #[test]
    fn known_secret_derivation_rejects_unreachable_prefixes() {
        let seed =
            Value32::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                .unwrap();
        let from = Index48::from_hex("2").unwrap();
        let from_secret = generate_from_seed(seed, from);
        assert_eq!(
            derive_from_known(
                from.get(),
                from_secret,
                Index48::from_hex("3").unwrap().get()
            ),
            Some(generate_from_seed(seed, Index48::from_hex("3").unwrap()))
        );
        assert!(derive_from_known(
            from.get(),
            from_secret,
            Index48::from_hex("6").unwrap().get()
        )
        .is_none());
    }

    #[test]
    fn ram_model_derives_effective_workers_after_idle_sessions() {
        let mut inner = test_inner(
            100 * MIB
                + 3 * DEFAULT_IDLE_SESSION_RSS_BYTES
                + 2 * DEFAULT_ONE_H_WORKER_PEAK_RSS_BYTES,
            8,
            100 * MIB,
        );
        inner.active_jobs.insert(
            "job".to_owned(),
            JobRecord {
                channel_index: 1,
                kind: "precompute".to_owned(),
                state: "test".to_owned(),
                planned_checked_units: 1,
            },
        );
        let model = resource_model_with_current_rss(&inner, 3, 0);
        assert_eq!(model.configured_workers, 8);
        assert_eq!(model.ram_limited_workers_raw, 2);
        assert_eq!(model.effective_workers, 2);
        assert!(!model.ram_overcommit_warning);
        assert_eq!(
            model.reserved_ram_bytes,
            100 * MIB + DEFAULT_ONE_H_WORKER_PEAK_RSS_BYTES + 3 * DEFAULT_IDLE_SESSION_RSS_BYTES
        );
    }

    #[test]
    fn ram_model_warns_but_keeps_one_effective_worker() {
        let inner = test_inner(
            100 * MIB + 3 * DEFAULT_IDLE_SESSION_RSS_BYTES - 1,
            4,
            100 * MIB,
        );
        let model = resource_model_with_current_rss(&inner, 3, 0);
        assert_eq!(model.ram_limited_workers_raw, 0);
        assert_eq!(model.effective_workers, 1);
        assert!(model.ram_overcommit_warning);
    }

    #[test]
    fn ram_model_accounts_for_observed_rss_floor() {
        let inner = test_inner(1024 * MIB, 8, 100 * MIB);
        let model = resource_model_with_current_rss(&inner, 0, 800 * MIB);
        assert_eq!(model.ram_limited_workers_raw, 1);
        assert_eq!(model.effective_workers, 1);
        assert_eq!(model.reserved_ram_bytes, 800 * MIB);
    }

    fn test_inner(max_ram_bytes: u64, workers: u32, baseline_daemon_rss_bytes: u64) -> Inner {
        let dir = tempdir().unwrap();
        let master = vec![1u8; 32];
        Inner {
            cfg: DaemonConfig {
                role: Role::Alice,
                db_path: dir.path().join("test.db"),
                control_addr: "127.0.0.1:1".parse().unwrap(),
                peer_addr: "127.0.0.1:2".parse().unwrap(),
                peer_url: None,
                peer_tls: None,
                mpc_port: 30000,
                max_ram_bytes,
                workers,
                precompute: 0,
                control_file: None,
                cookie_file: None,
            },
            master_secret: SecretBytes(master),
            cookie: "cookie".to_owned(),
            db: PlainDb::default(),
            active_jobs: BTreeMap::new(),
            next_job_id: 0,
            baseline_daemon_rss_bytes,
        }
    }

    fn sample_wire_record() -> WireRecord {
        let wires = Ag2pcSecureWires {
            lambda: vec![0, 1],
            wire_bundle: vec![
                AShareBundle {
                    mac: Block::make(1, 2),
                    key: Block::make(3, 4),
                },
                AShareBundle {
                    mac: Block::make(5, 6),
                    key: Block::make(7, 8),
                },
            ],
            label0: Vec::new(),
            eval_label: Vec::new(),
        };
        WireRecord {
            public_binding_hex: "aa".repeat(32),
            local_binding_hex: "bb".repeat(32),
            wires: SerializableWires::from_secure_wires(&wires),
        }
    }

    async fn close_writer_for_test(writer: DbWriter) {
        writer.flush().await.unwrap();
        drop(writer);
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
    }

    fn tamper_first_redb_value(path: &Path) {
        let database = Database::open(path).unwrap();
        let write = database.begin_write().unwrap();
        let (key, mut value) = {
            let table = write.open_table(REDB_TABLE).unwrap();
            let (key, value) = table.iter().unwrap().next().unwrap().unwrap();
            (key.value().to_vec(), value.value().to_vec())
        };
        {
            let mut table = write.open_table(REDB_TABLE).unwrap();
            let last = value.last_mut().unwrap();
            *last ^= 1;
            table.insert(key.as_slice(), value.as_slice()).unwrap();
        }
        write.commit().unwrap();
    }

    fn write_legacy_db_for_test(path: &Path, master_secret: &[u8], db: &PlainDb) {
        let salt = [9u8; DB_SALT_LEN];
        let nonce = [8u8; DB_NONCE_LEN];
        let key = derive_db_key(master_secret, &salt);
        let plaintext = serde_json::to_vec(db).unwrap();
        let mut tag = [0u8; DB_TAG_LEN];
        let ciphertext = encrypt_aead(
            Cipher::aes_256_gcm(),
            &key,
            Some(&nonce),
            DB_AAD,
            &plaintext,
            &mut tag,
        )
        .unwrap();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(DB_MAGIC);
        bytes.extend_from_slice(&salt);
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&tag);
        bytes.extend_from_slice(&ciphertext);
        fs::write(path, bytes).unwrap();
    }
}
