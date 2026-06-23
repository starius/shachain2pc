pub mod pb {
    tonic::include_proto!("shachain2pc.daemon.v1");
}

use hmac::{Hmac, Mac};
use openssl::rand::rand_bytes;
use openssl::symm::{decrypt_aead, encrypt_aead, Cipher};
use pb::control_service_server::{ControlService, ControlServiceServer};
use pb::peer_service_server::{PeerService, PeerServiceServer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shachain2pc_circuit::generate_from_seed;
use shachain2pc_emp_compat::{normalize_ag2pc_delta, AShareBundle, Ag2pcSecureWires};
use shachain2pc_emp_wire::{Block, BLOCK_BYTES};
use shachain2pc_party::{
    reveal_node_job, run_party, run_precompute_path_job, run_seed_root_job, Args as PartyArgs,
    IndexSpec, MpcTcpEndpoint, PartyOutput,
};
use shachain2pc_types::{Index48, Role, Value32, INDEX_BITS, MAX_INDEX};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

const DB_MAGIC: &[u8; 8] = b"S2PCDB1\0";
const DB_AAD: &[u8] = b"shachain2pc daemon db v1";
const DB_SALT_LEN: usize = 32;
const DB_NONCE_LEN: usize = 12;
const DB_TAG_LEN: usize = 16;
const DEFAULT_SSP_TARGET: u32 = 40;
const DEFAULT_DELTA_CAP: u64 = 1u64 << 32;
const PROTOCOL_VERSION: u32 = 1;

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

pub type Result<T> = std::result::Result<T, DaemonError>;

#[derive(Clone, Debug)]
pub struct DaemonConfig {
    pub role: Role,
    pub db_path: PathBuf,
    pub control_addr: SocketAddr,
    pub peer_addr: SocketAddr,
    pub peer_url: Option<String>,
    pub mpc_port: u16,
    pub max_ram_bytes: u64,
    pub workers: u32,
    pub precompute: u64,
    pub control_file: Option<PathBuf>,
    pub cookie_file: Option<PathBuf>,
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
}

struct Inner {
    cfg: DaemonConfig,
    master_secret: SecretBytes,
    cookie: String,
    store: EncryptedStore,
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

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct PlainDb {
    channels: BTreeMap<String, ChannelRecord>,
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
    worker_slot: u32,
}

#[derive(Clone, Copy, Debug)]
struct PeerFrontierConfig {
    channel_enabled: bool,
    precompute: u64,
    workers: u32,
    ssp_target: u32,
    delta_lifetime_checked_units_cap: u64,
}

struct PrecomputeJob {
    job_id: String,
    endpoint: MpcTcpEndpoint,
    delta: Block,
    ssp: usize,
    share: Value32,
    planned_checked_units: u64,
}

enum PrecomputeStart {
    AlreadyStored,
    Run(PrecomputeJob),
}

struct EncryptedStore {
    path: PathBuf,
    salt: [u8; DB_SALT_LEN],
}

impl EncryptedStore {
    fn open(path: PathBuf, master_secret: &[u8]) -> Result<(Self, PlainDb)> {
        if !path.exists() {
            let mut salt = [0u8; DB_SALT_LEN];
            rand_bytes(&mut salt).map_err(|e| DaemonError::Crypto(e.to_string()))?;
            return Ok((Self { path, salt }, PlainDb::default()));
        }

        let bytes = fs::read(&path)?;
        if bytes.len() < DB_MAGIC.len() + DB_SALT_LEN + DB_NONCE_LEN + DB_TAG_LEN
            || &bytes[..DB_MAGIC.len()] != DB_MAGIC
        {
            return Err(DaemonError::Crypto(
                "encrypted DB has an invalid header".to_owned(),
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
        let db = serde_json::from_slice(&plaintext)?;
        Ok((Self { path, salt }, db))
    }

    fn save(&self, master_secret: &[u8], db: &PlainDb) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let plaintext = serde_json::to_vec_pretty(db)?;
        let key = derive_db_key(master_secret, &self.salt);
        let mut nonce = [0u8; DB_NONCE_LEN];
        let mut tag = [0u8; DB_TAG_LEN];
        rand_bytes(&mut nonce).map_err(|e| DaemonError::Crypto(e.to_string()))?;
        let ciphertext = encrypt_aead(
            Cipher::aes_256_gcm(),
            &key,
            Some(&nonce),
            DB_AAD,
            &plaintext,
            &mut tag,
        )
        .map_err(|e| DaemonError::Crypto(e.to_string()))?;
        let mut out = Vec::with_capacity(
            DB_MAGIC.len() + DB_SALT_LEN + DB_NONCE_LEN + DB_TAG_LEN + ciphertext.len(),
        );
        out.extend_from_slice(DB_MAGIC);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&tag);
        out.extend_from_slice(&ciphertext);
        fs::write(&self.path, out)?;
        Ok(())
    }
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
    let peer_server = Server::builder()
        .add_service(PeerServiceServer::new(peer))
        .serve(peer_addr);
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
    let (store, db) = EncryptedStore::open(cfg.db_path.clone(), &master_secret)?;
    let cookie = load_or_create_cookie(&cfg)?;
    Ok(DaemonState {
        inner: Arc::new(Mutex::new(Inner {
            cfg,
            master_secret: SecretBytes(master_secret),
            cookie,
            store,
            db,
            active_jobs: BTreeMap::new(),
            next_job_id: 0,
        })),
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
            workers: inner.cfg.workers,
            precompute: inner.cfg.precompute,
            channel_count: inner.db.channels.len() as u64,
            active_job_count: inner.active_jobs.len() as u64,
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
        Ok(Response::new(pb::SetConfigResponse {
            max_ram_bytes: inner.cfg.max_ram_bytes,
            workers: inner.cfg.workers,
            precompute: inner.cfg.precompute,
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
        inner.save().map_err(to_status)?;
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
        let channel = inner
            .db
            .channels
            .get_mut(&key)
            .ok_or_else(|| Status::not_found("channel is not enabled"))?;
        channel.enabled = false;
        let response = channel_response(req.channel_index, channel);
        inner.save().map_err(to_status)?;
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
        let inner = self.state.inner.lock().await;
        Ok(Response::new(pb::ConfigUpdate {
            max_ram_bytes: inner.cfg.max_ram_bytes,
            workers: inner.cfg.workers,
            precompute: inner.cfg.precompute,
            ssp_target: DEFAULT_SSP_TARGET,
            delta_lifetime_checked_units_cap: DEFAULT_DELTA_CAP,
        }))
    }

    async fn get_frontier(
        &self,
        request: Request<pb::GetFrontierRequest>,
    ) -> std::result::Result<Response<pb::GetFrontierResponse>, Status> {
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
        }))
    }
}

impl DaemonState {
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
                .reveal_persisted_node(channel_index, index, &node)
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
                .reveal_persisted_node(channel_index, index, &node)
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
                    let _ = state.precompute_path(channel_index, target).await;
                });
            }
        }
        Ok(())
    }

    async fn scheduler_candidates(&self) -> Vec<u64> {
        let inner = self.inner.lock().await;
        if inner.cfg.workers == 0 || inner.cfg.precompute == 0 {
            return Vec::new();
        }
        if inner.active_jobs.len() >= inner.cfg.workers as usize {
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
        let index = Index48::new(target_index).map_err(|e| DaemonError::Parse(e.to_string()))?;
        let peer = match self.peer_frontier(channel_index).await {
            Ok(Some(peer)) => {
                if !peer.channel_enabled {
                    return Err(DaemonError::Refused(
                        "peer has not enabled this channel".to_owned(),
                    ));
                }
                Some(peer)
            }
            Ok(None) => None,
            Err(e) => return Err(e),
        };
        let job = match self
            .begin_precompute_job(channel_index, index, peer)
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
        if let Some(peer) = peer {
            if let Err(e) = self
                .validate_peer_security_params(channel_index, peer)
                .await
            {
                self.finish_job(&job.job_id, true).await;
                return Err(e);
            }
        }
        if let Err(e) = self.reconcile_with_peer(channel_index).await {
            self.finish_job(&job.job_id, true).await;
            return Err(e);
        }
        let digest = job_digest(
            channel_index,
            "precompute-path",
            0,
            index.get(),
            job.ssp as u32,
        );
        let nodes = match run_precompute_path_job(
            job.endpoint,
            job.share,
            index,
            job.delta,
            digest,
            job.ssp,
        )
        .await
        {
            Ok(nodes) => nodes,
            Err(e) => {
                self.finish_job(&job.job_id, true).await;
                return Err(e.into());
            }
        };
        let nodes_stored = nodes.len() as u64;
        if let Err(e) = self
            .store_precomputed_nodes_and_finish_job(channel_index, &job, nodes)
            .await
        {
            self.finish_job(&job.job_id, true).await;
            return Err(e);
        }
        Ok(pb::PrecomputeResponse {
            channel_index,
            target_index: index.get(),
            nodes_stored,
            checked_units: job.planned_checked_units,
        })
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
        reveal_node_job(endpoint, node, delta, digest, ssp)
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
        channel
            .known_secrets
            .insert(index.get().to_string(), secret.to_hex());
        channel.last_observed_next_reveal_index = Some(expected_next_index.saturating_sub(1));
        inner.save()
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
        let root = run_seed_root_job(endpoint, share, delta, digest, ssp).await?;
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

    async fn begin_precompute_job(
        &self,
        channel_index: u64,
        index: Index48,
        peer: Option<PeerFrontierConfig>,
    ) -> Result<PrecomputeStart> {
        let planned_checked_units = set_bits_desc(index.get()).len() as u64;
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
        let peer_workers = peer.map_or(inner.cfg.workers, |peer| peer.workers);
        let worker_count =
            effective_precompute_workers(inner.cfg.mpc_port, inner.cfg.workers, peer_workers);
        if worker_count == 0 {
            return Err(DaemonError::Refused(
                "no precompute worker port is available".to_owned(),
            ));
        }
        let worker_slot = precompute_worker_slot(channel_index, index.get(), worker_count);
        if inner
            .active_jobs
            .values()
            .any(|job| job.worker_slot == worker_slot)
        {
            return Err(DaemonError::Refused(format!(
                "precompute worker slot {worker_slot} is busy"
            )));
        }
        let port = precompute_worker_port(inner.cfg.mpc_port, worker_slot)?;
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
        let peer_ip = inner
            .cfg
            .peer_url
            .as_deref()
            .and_then(peer_ip_from_url)
            .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let endpoint = MpcTcpEndpoint {
            role: inner.cfg.role,
            port,
            peer_ip,
        };
        let delta = channel_delta(&inner.master_secret.0, channel_index, inner.cfg.role);
        let ssp = ssp_effective(channel.ssp_target, channel.delta_lifetime_checked_units_cap);
        let share = channel_seed_share(&inner.master_secret.0, channel_index);
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
                state: format!("target={} slot={} port={}", index.get(), worker_slot, port),
                planned_checked_units,
                worker_slot,
            },
        );
        inner.save()?;
        Ok(PrecomputeStart::Run(PrecomputeJob {
            job_id,
            endpoint,
            delta,
            ssp,
            share,
            planned_checked_units,
        }))
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
        channel.frontier_nodes.insert(
            node_key(mask),
            WireRecord {
                public_binding_hex: to_hex(&public),
                local_binding_hex: to_hex(&local),
                wires: SerializableWires::from_secure_wires(wires),
            },
        );
        inner.save()
    }

    async fn store_precomputed_nodes_and_finish_job(
        &self,
        channel_index: u64,
        job: &PrecomputeJob,
        nodes: Vec<(u64, Ag2pcSecureWires)>,
    ) -> Result<()> {
        let mut inner = self.inner.lock().await;
        let key = channel_key(channel_index);
        for (mask, wires) in nodes {
            let (public, local) = binding_pair(&inner, channel_index, mask);
            let channel = inner
                .db
                .channels
                .get_mut(&key)
                .ok_or_else(|| DaemonError::NotFound("channel is not enabled".to_owned()))?;
            channel.frontier_nodes.insert(
                node_key(mask),
                WireRecord {
                    public_binding_hex: to_hex(&public),
                    local_binding_hex: to_hex(&local),
                    wires: SerializableWires::from_secure_wires(&wires),
                },
            );
        }
        if let Some(channel) = inner.db.channels.get_mut(&key) {
            channel.estimated_checked_units = channel
                .estimated_checked_units
                .saturating_add(job.planned_checked_units);
        }
        inner.active_jobs.remove(&job.job_id);
        inner.save()
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
        let peer_url = {
            let inner = self.inner.lock().await;
            inner.cfg.peer_url.clone()
        };
        let Some(peer_url) = peer_url else {
            return Ok(None);
        };
        let mut client = pb::peer_service_client::PeerServiceClient::connect(peer_url).await?;
        let response = client
            .get_frontier(pb::GetFrontierRequest { channel_index })
            .await?
            .into_inner();
        let config = PeerFrontierConfig {
            channel_enabled: response.channel_enabled,
            precompute: response.precompute,
            workers: response.workers,
            ssp_target: response.ssp_target,
            delta_lifetime_checked_units_cap: response.delta_lifetime_checked_units_cap,
        };
        Ok(Some((response, config)))
    }

    async fn finish_job(&self, job_id: &str, failed: bool) {
        let mut inner = self.inner.lock().await;
        if let Some(job) = inner.active_jobs.remove(job_id) {
            if failed {
                if let Some(channel) = inner.db.channels.get_mut(&channel_key(job.channel_index)) {
                    channel.failed_precompute_jobs =
                        channel.failed_precompute_jobs.saturating_add(1);
                }
            }
            let _ = inner.save();
        }
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
        for mask in drop_masks {
            channel.frontier_nodes.remove(&mask);
        }
        inner.save()
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

impl Inner {
    fn save(&self) -> Result<()> {
        self.store.save(&self.master_secret.0, &self.db)
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

fn effective_precompute_workers(base_port: u16, local_workers: u32, peer_workers: u32) -> u32 {
    let available_ports = u16::MAX as u32 - base_port as u32;
    local_workers.min(peer_workers).min(available_ports)
}

fn precompute_worker_slot(channel_index: u64, target_index: u64, worker_count: u32) -> u32 {
    debug_assert!(worker_count > 0);
    ((channel_index ^ target_index) % worker_count as u64) as u32
}

fn precompute_worker_port(base_port: u16, worker_slot: u32) -> Result<u16> {
    let port = base_port as u32 + 1 + worker_slot;
    if port > u16::MAX as u32 {
        return Err(DaemonError::Refused(
            "precompute worker port exceeds 65535".to_owned(),
        ));
    }
    Ok(port as u16)
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

    #[test]
    fn encrypted_store_round_trips_and_rejects_wrong_secret() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("db.enc");
        let master = vec![1u8; 32];
        let (store, mut db) = EncryptedStore::open(path.clone(), &master).unwrap();
        db.channels.insert(
            "1".to_owned(),
            ChannelRecord {
                enabled: true,
                last_observed_next_reveal_index: None,
                precompute_target: 1,
                ssp_target: 40,
                delta_lifetime_checked_units_cap: 100,
                frontier_nodes: BTreeMap::new(),
                known_secrets: BTreeMap::new(),
                estimated_checked_units: 0,
                attempted_checked_units: 0,
                failed_precompute_jobs: 0,
            },
        );
        store.save(&master, &db).unwrap();
        let (_, loaded) = EncryptedStore::open(path.clone(), &master).unwrap();
        assert!(loaded.channels.contains_key("1"));
        assert!(EncryptedStore::open(path, &[2u8; 32]).is_err());
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
}
