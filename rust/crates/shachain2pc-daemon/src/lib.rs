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
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, watch, Mutex, Notify};
use tokio::task::AbortHandle;
use tokio::time::{sleep, timeout, Duration, Instant, MissedTickBehavior};
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
const JOBSTREAM_PAYLOAD_CHUNK_BYTES: usize = 512 * 1024;
const DEFAULT_PEER_REVEAL_WAIT: Duration = Duration::from_secs(30);
const DEFAULT_DB_CHECKPOINT_INTERVAL: Duration = Duration::from_secs(5);
const SCHEDULER_FALLBACK_INTERVAL: Duration = Duration::from_secs(1);
const FULL_FRONTIER_RECONCILE_INTERVAL: Duration = Duration::from_secs(60);
const PEER_HTTP2_STREAM_WINDOW_BYTES: u32 = 16 * 1024 * 1024;
const PEER_HTTP2_CONNECTION_WINDOW_BYTES: u32 = 512 * 1024 * 1024;
const PEER_HTTP2_MAX_CONCURRENT_STREAMS: u32 = 4096;
const PEER_GRPC_CHANNEL_SHARDS: usize = 32;

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
    scheduler_notify: Arc<Notify>,
    scheduled_precompute_channels: Arc<Mutex<BTreeSet<u64>>>,
    full_reconcile_after: Arc<Mutex<BTreeMap<u64, Instant>>>,
    precompute_sessions: Arc<Mutex<BTreeMap<u64, PrecomputeSessionHandle>>>,
    incoming_precompute_sessions: Arc<Mutex<BTreeMap<u64, AbortHandle>>>,
    peer_channels: Option<Arc<[Channel]>>,
    sha: Arc<Circuit>,
}

struct Inner {
    cfg: DaemonConfig,
    master_secret: SecretBytes,
    cookie: String,
    db: PlainDb,
    active_jobs: BTreeMap<String, JobRecord>,
    next_job_id: u64,
}

struct SecretBytes(Vec<u8>);

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

// Encrypted redb persistence, legacy migration, and DB mutation helpers.
include!("db.rs");

pub async fn run_daemon(cfg: DaemonConfig, master_secret: Vec<u8>) -> Result<()> {
    let state = init_daemon_state(cfg, master_secret)?;
    let scheduler = tokio::spawn(scheduler_loop(state.clone()));
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
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let shutdown_task = tokio::spawn(wait_for_shutdown_signal(shutdown_tx));
    let control_server = Server::builder()
        .add_service(ControlServiceServer::new(control))
        .serve_with_shutdown(bind, wait_for_shutdown(shutdown_rx.clone()));
    let peer_server = {
        let inner = state.inner.lock().await;
        let mut builder = Server::builder()
            .initial_stream_window_size(Some(PEER_HTTP2_STREAM_WINDOW_BYTES))
            .initial_connection_window_size(Some(PEER_HTTP2_CONNECTION_WINDOW_BYTES))
            .max_concurrent_streams(Some(PEER_HTTP2_MAX_CONCURRENT_STREAMS));
        if let Some(tls) = &inner.cfg.peer_tls {
            builder = builder.tls_config(peer_server_tls_config(tls)?)?;
        }
        builder
            .add_service(PeerServiceServer::new(peer))
            .serve_with_shutdown(peer_addr, wait_for_shutdown(shutdown_rx))
    };
    let server_result = tokio::try_join!(control_server, peer_server);
    scheduler.abort();
    shutdown_task.abort();
    let flush_result = state.db_writer.flush().await;
    server_result?;
    flush_result?;
    Ok(())
}

async fn wait_for_shutdown(mut rx: watch::Receiver<bool>) {
    loop {
        if *rx.borrow() {
            break;
        }
        if rx.changed().await.is_err() {
            break;
        }
    }
}

async fn wait_for_shutdown_signal(tx: watch::Sender<bool>) {
    wait_for_process_shutdown().await;
    let _ = tx.send(true);
}

async fn wait_for_process_shutdown() {
    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

async fn scheduler_loop(state: DaemonState) {
    loop {
        let _ = state.run_scheduler_once().await;
        tokio::select! {
            _ = state.scheduler_notify.notified() => {}
            _ = sleep(SCHEDULER_FALLBACK_INTERVAL) => {}
        }
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
    let peer_channels = peer_channels_from_url(&cfg.peer_url, cfg.peer_tls.as_ref())?;
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
        })),
        db_writer,
        grpc_jobs: Arc::new(Mutex::new(BTreeMap::new())),
        pending_reveals: Arc::new(Mutex::new(BTreeMap::new())),
        pending_reveal_notify: Arc::new(Notify::new()),
        scheduler_notify: Arc::new(Notify::new()),
        scheduled_precompute_channels: Arc::new(Mutex::new(BTreeSet::new())),
        full_reconcile_after: Arc::new(Mutex::new(BTreeMap::new())),
        precompute_sessions: Arc::new(Mutex::new(BTreeMap::new())),
        incoming_precompute_sessions: Arc::new(Mutex::new(BTreeMap::new())),
        peer_channels,
        sha,
    })
}

// gRPC control and peer service adapters plus JobStream byte-channel glue.
include!("services.rs");

// Live per-channel precompute session driver.
include!("precompute_driver.rs");

// Daemon state machine methods.
include!("state.rs");

// Protocol bindings, TLS, derivation, parsing, and small helpers.
include!("helpers.rs");

#[cfg(test)]
mod tests;
