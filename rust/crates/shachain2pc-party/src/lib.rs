use shachain2pc_circuit::{
    batch_digest, build_chunk_circuit, build_circuit_for_index, build_tile_circuit, cache_digest,
    check_chunk_circuit, check_tile_circuit, chunk_spec_digest, plan_tile_levels,
    sha256_compress_gadget, split_chain_bits, tree_digest, Circuit, GateType, CACHE_TILE_HEIGHT,
    CACHE_TILE_LEAVES,
};
use shachain2pc_emp_compat::{
    Ag2pcProgram, Ag2pcSecureWires, Ag2pcSession, CompatError, HASH_DIGEST_BYTES,
};
use shachain2pc_emp_wire::{Ag2pcStreams, Block, EmpStream, IdleTrim, TranscriptIo, WireError};
use shachain2pc_mpc_core::{reveal_local_share, reveal_recipient_bits, RevealError};
use shachain2pc_types::{Index48, Role, Value32, INDEX_BITS, MAX_INDEX, VALUE_BITS};
use std::collections::{BTreeMap, HashMap};
use std::env;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Instant;
use tokio::net::TcpListener;
use tokio::time::{sleep, Duration};
use zeroize::Zeroize;

#[derive(Debug)]
pub enum PartyError {
    Usage(String),
    Parse(String),
    Circuit(shachain2pc_circuit::CircuitError),
    Compat(CompatError),
    Wire(WireError),
    Io(std::io::Error),
    CircuitMismatch,
    SeedRevealRefused,
    UnsupportedMode(&'static str),
}

impl fmt::Display for PartyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(msg) | Self::Parse(msg) => f.write_str(msg),
            Self::Circuit(e) => write!(f, "{e}"),
            Self::Compat(e) => write!(f, "{e}"),
            Self::Wire(e) => write!(f, "{e}"),
            Self::Io(e) => write!(f, "{e}"),
            Self::CircuitMismatch => write!(
                f,
                "shachain2pc: circuit mismatch -- the two parties are not running the same agreed circuit (same index?)"
            ),
            Self::SeedRevealRefused => write!(
                f,
                "I=0 reveals the seed (root of all revocation secrets); re-run with --allow-seed-reveal to proceed"
            ),
            Self::UnsupportedMode(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for PartyError {}

impl From<shachain2pc_circuit::CircuitError> for PartyError {
    fn from(value: shachain2pc_circuit::CircuitError) -> Self {
        Self::Circuit(value)
    }
}

impl From<CompatError> for PartyError {
    fn from(value: CompatError) -> Self {
        Self::Compat(value)
    }
}

impl From<WireError> for PartyError {
    fn from(value: WireError) -> Self {
        Self::Wire(value)
    }
}

impl From<std::io::Error> for PartyError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Debug)]
pub struct Args {
    pub role: Role,
    pub port: u16,
    pub index_spec: IndexSpec,
    pub share: Value32,
    pub peer_ip: IpAddr,
    pub allow_seed_reveal: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IndexSpec {
    Single(Index48),
    Range { lo: Index48, hi: Index48 },
}

impl IndexSpec {
    fn is_range(&self) -> bool {
        matches!(self, Self::Range { .. })
    }

    fn indices(&self) -> Option<Vec<Index48>> {
        match self {
            Self::Single(_) => None,
            Self::Range { lo, hi } => Some(
                (lo.get()..=hi.get())
                    .map(|value| Index48::new(value).expect("range parser enforced 48-bit index"))
                    .collect(),
            ),
        }
    }

    fn contains_seed(&self) -> bool {
        match self {
            Self::Single(index) => index.get() == 0,
            Self::Range { lo, hi } => lo.get() == 0 && hi.get() >= lo.get(),
        }
    }

    fn single_index(&self) -> Result<Index48, PartyError> {
        match self {
            Self::Single(index) => Ok(*index),
            Self::Range { .. } => Err(PartyError::UnsupportedMode(
                "this operation requires a single index, not a range",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestedMode {
    Full,
    Chunked,
    Tree,
    Cache,
}

pub enum PartyOutput {
    Single(Value32),
    Range(Vec<(Index48, Value32)>),
}

pub const AG2PC_SSP: usize = 40;

static SHARED_SHA_CIRCUIT: OnceLock<Arc<Circuit>> = OnceLock::new();

fn shared_sha_circuit() -> Arc<Circuit> {
    SHARED_SHA_CIRCUIT
        .get_or_init(|| {
            Arc::new(
                sha256_compress_gadget()
                    .expect("embedded SHA-256 compression circuit should parse"),
            )
        })
        .clone()
}

#[derive(Clone, Copy, Debug)]
pub struct MpcTcpEndpoint {
    pub role: Role,
    pub port: u16,
    pub peer_ip: IpAddr,
}

#[cfg(test)]
async fn run_derivation(args: Args) -> Result<Value32, PartyError> {
    match run_party(args).await? {
        PartyOutput::Single(out) => Ok(out),
        PartyOutput::Range(_) => Err(PartyError::UnsupportedMode(
            "run_derivation returns one value; use run_party for ranges",
        )),
    }
}

pub async fn run_party(args: Args) -> Result<PartyOutput, PartyError> {
    ensure_index_allowed(&args.index_spec, args.allow_seed_reveal)?;
    let requested_mode = requested_mode_from_env(args.index_spec.is_range());
    ensure_mode_supported_for_now(&args.index_spec, requested_mode)?;
    if let Some(indices) = args.index_spec.indices() {
        let outputs = match requested_mode {
            RequestedMode::Full => {
                run_derivation_batch(args.role, args.port, &indices, args.share, args.peer_ip)
                    .await?
            }
            RequestedMode::Tree => {
                let trunk_chunk_blocks = trunk_chunk_blocks_from_env(0);
                run_derivation_tree(
                    args.role,
                    args.port,
                    &indices,
                    args.share,
                    args.peer_ip,
                    trunk_chunk_blocks,
                )
                .await?
            }
            RequestedMode::Cache => {
                let trunk_chunk_blocks = trunk_chunk_blocks_from_env(16);
                let tile_fanout = tile_fanout_from_env()?;
                run_derivation_cache(
                    args.role,
                    args.port,
                    &indices,
                    args.share,
                    args.peer_ip,
                    trunk_chunk_blocks,
                    tile_fanout,
                )
                .await?
            }
            RequestedMode::Chunked => unreachable!("checked above"),
        };
        return Ok(PartyOutput::Range(outputs));
    }

    let index = args.index_spec.single_index()?;
    if requested_mode == RequestedMode::Chunked {
        let blocks_per_chunk = chunk_blocks_from_env().ok_or(PartyError::UnsupportedMode(
            "Rust SHACHAIN2PC_CHUNK_BLOCKS mode requires a positive chunk size",
        ))?;
        return run_derivation_chunked(
            args.role,
            args.port,
            index,
            args.share,
            args.peer_ip,
            blocks_per_chunk,
        )
        .await
        .map(PartyOutput::Single);
    }

    let mut timing = PhaseTiming::new(args.role, index);
    let sha = shared_sha_circuit();
    let circuit = build_circuit_for_index(index, &sha)?;
    let digest = batch_digest(&[index.get()], &sha);
    let program = Ag2pcProgram::from_circuit(&circuit)?;
    drop(circuit);
    timing.mark("build_circuit");

    let mut streams =
        open_ag2pc_streams_after_digest(args.role, args.port, args.peer_ip, digest).await?;
    timing.mark("open_streams");
    let mut session = Ag2pcSession::setup(&mut streams, args.role, AG2PC_SSP).await?;
    streams.main.flush().await?;
    timing.mark("ag2pc_setup");
    let seed_inputs =
        authenticate_seed_inputs(&mut session, &mut streams, args.role, args.share).await?;
    timing.mark("input_auth");
    let mut authenticated = session
        .run_program(&mut streams, &program, &seed_inputs)
        .await?;
    authenticated.strip_labels_for_reveal();
    timing.mark("compute");
    let output = session.reveal_public(&mut streams, &authenticated).await?;
    session.end(&mut streams).await?;
    streams.main.flush().await?;
    timing.mark("reveal");
    value_from_bits(&output).map(PartyOutput::Single)
}

// Embeddable seed, one-H, precompute, and reveal jobs.
include!("jobs.rs");

// Standalone batch/tree/cache/chunked CLI derivation modes.
include!("standalone_modes.rs");

// Shared party helpers, CLI parsing, and transport setup.
include!("helpers.rs");

#[cfg(test)]
mod tests;
