use shachain2pc_circuit::{
    batch_digest, build_chunk_circuit, build_circuit_for_index, build_tile_circuit, cache_digest,
    check_chunk_circuit, check_tile_circuit, chunk_spec_digest, plan_tile_levels,
    sha256_compress_gadget, split_chain_bits, tree_digest, Circuit, GateType, CACHE_TILE_HEIGHT,
    CACHE_TILE_LEAVES,
};
use shachain2pc_emp_compat::{Ag2pcProgram, Ag2pcSecureWires, Ag2pcSession, CompatError};
use shachain2pc_emp_wire::{Ag2pcStreams, EmpStream, WireError};
use shachain2pc_types::{Index48, Role, Value32, INDEX_BITS, MAX_INDEX, VALUE_BITS};
use std::collections::HashMap;
use std::env;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Instant;
use tokio::net::TcpListener;
use tokio::time::{sleep, Duration};
use zeroize::Zeroize;

#[derive(Debug)]
enum PartyError {
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
struct Args {
    role: Role,
    port: u16,
    index_spec: IndexSpec,
    share: Value32,
    peer_ip: IpAddr,
    allow_seed_reveal: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum IndexSpec {
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

enum PartyOutput {
    Single(Value32),
    Range(Vec<(Index48, Value32)>),
}

const AG2PC_SSP: usize = 40;

// The derivation is a single sequential request/response task (Alice<->Bob round
// trips). A multi_thread runtime would spawn one worker per core that idle-park
// and bounce the task across run queues at every .await -- pure scheduler/mmap
// lock-contention overhead with no parallelism to gain. current_thread runs it on
// one thread, matching the C++ blocking-socket model.
#[tokio::main(flavor = "current_thread")]
async fn main() {
    match parse_args(env::args().collect()) {
        Ok(args) => match run_party(args).await {
            Ok(PartyOutput::Single(out)) => {
                println!("RESULT {}", out.to_hex());
            }
            Ok(PartyOutput::Range(outputs)) => {
                for (index, out) in outputs {
                    println!("RESULT {} {}", index.to_hex12(), out.to_hex());
                }
            }
            Err(e) => {
                eprintln!("ABORT: {e}");
                std::process::exit(1);
            }
        },
        Err(e) => {
            eprintln!("ABORT: {e}");
            std::process::exit(1);
        }
    }
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

async fn run_party(args: Args) -> Result<PartyOutput, PartyError> {
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
    let sha = sha256_compress_gadget()?;
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
    let authenticated = session
        .run_program(&mut streams, &program, &seed_inputs)
        .await?;
    timing.mark("compute");
    let output = session.reveal_public(&mut streams, &authenticated).await?;
    session.end(&mut streams).await?;
    streams.main.flush().await?;
    timing.mark("reveal");
    value_from_bits(&output).map(PartyOutput::Single)
}

async fn run_derivation_batch(
    role: Role,
    port: u16,
    indices: &[Index48],
    share: Value32,
    peer_ip: IpAddr,
) -> Result<Vec<(Index48, Value32)>, PartyError> {
    let first_index = *indices
        .first()
        .ok_or(PartyError::UnsupportedMode("range must not be empty"))?;
    let mut timing = PhaseTiming::new(role, first_index);
    let sha = sha256_compress_gadget()?;
    let mut programs = Vec::with_capacity(indices.len());
    for &index in indices {
        let circuit = build_circuit_for_index(index, &sha)?;
        programs.push(Ag2pcProgram::from_circuit(&circuit)?);
    }
    let index_values: Vec<u64> = indices.iter().map(|index| index.get()).collect();
    let digest = batch_digest(&index_values, &sha);
    timing.mark("build_batch_circuits");

    let mut streams = open_ag2pc_streams_after_digest(role, port, peer_ip, digest).await?;
    timing.mark("open_streams");
    let mut session = Ag2pcSession::setup(&mut streams, role, AG2PC_SSP).await?;
    streams.main.flush().await?;
    timing.mark("ag2pc_setup");

    let seed_inputs = authenticate_seed_inputs(&mut session, &mut streams, role, share).await?;
    timing.mark("input_auth");
    let mut authenticated = Vec::with_capacity(indices.len());
    for (i, program) in programs.into_iter().enumerate() {
        let out = session
            .run_program(&mut streams, &program, &seed_inputs)
            .await?;
        authenticated.push((indices[i], out));
        timing.mark("batch_item");
    }

    let outputs = reveal_authenticated_values(&mut session, &mut streams, &authenticated)
        .await
        .inspect(|_| timing.mark("batch_reveal"))?;
    session.end(&mut streams).await?;
    Ok(outputs)
}

async fn run_derivation_tree(
    role: Role,
    port: u16,
    indices: &[Index48],
    share: Value32,
    peer_ip: IpAddr,
    trunk_chunk_blocks: i32,
) -> Result<Vec<(Index48, Value32)>, PartyError> {
    let first_index = *indices
        .first()
        .ok_or(PartyError::UnsupportedMode("range must not be empty"))?;
    let mut timing = PhaseTiming::new(role, first_index);
    let sha = sha256_compress_gadget()?;
    let (_, low_mask, high_mask) = range_split_masks(indices)?;
    let trunk_groups = split_chain_bits(
        first_index.get() & high_mask,
        effective_chunk_size(trunk_chunk_blocks)?,
    )?;
    if trunk_groups.iter().map(Vec::len).sum::<usize>() == 0 {
        return Err(PartyError::UnsupportedMode(
            "shachain2pc: shared-trunk needs >=1 common high set bit (no shared hash in this range); use batch mode",
        ));
    }
    let tamper_branch = tamper_step_from_env();

    let mut trunk_programs = Vec::with_capacity(trunk_groups.len());
    let mut branch_programs = Vec::with_capacity(indices.len());
    for (chunk, bits) in trunk_groups.iter().enumerate() {
        trunk_programs.push(chunk_program(&sha, bits, chunk == 0, false)?);
    }
    for (branch, &index) in indices.iter().enumerate() {
        let bits = set_bits_desc(index.get() & low_mask);
        branch_programs.push(chunk_program(
            &sha,
            &bits,
            false,
            branch as i64 == tamper_branch,
        )?);
    }
    let index_values: Vec<u64> = indices.iter().map(|index| index.get()).collect();
    let digest = tree_digest(&index_values, trunk_chunk_blocks, &sha);
    timing.mark("build_tree_circuits");

    let mut streams = open_ag2pc_streams_after_digest(role, port, peer_ip, digest).await?;
    timing.mark("open_streams");
    let mut session = Ag2pcSession::setup(&mut streams, role, AG2PC_SSP).await?;
    streams.main.flush().await?;
    timing.mark("ag2pc_setup");

    let seed_inputs = authenticate_seed_inputs(&mut session, &mut streams, role, share).await?;
    timing.mark("input_auth");
    let mut trunk = session
        .run_program(&mut streams, &trunk_programs[0], &seed_inputs)
        .await?;
    timing.mark("tree_trunk_0");

    for (chunk, program) in trunk_programs.into_iter().enumerate().skip(1) {
        trunk = session.run_program(&mut streams, &program, &trunk).await?;
        timing.mark(match chunk {
            1 => "tree_trunk_1",
            2 => "tree_trunk_2",
            3 => "tree_trunk_3",
            _ => "tree_trunk",
        });
    }

    let mut authenticated = Vec::with_capacity(indices.len());
    for (i, program) in branch_programs.into_iter().enumerate() {
        let out = session.run_program(&mut streams, &program, &trunk).await?;
        authenticated.push((indices[i], out));
        timing.mark("tree_branch");
    }

    let outputs = reveal_authenticated_values(&mut session, &mut streams, &authenticated)
        .await
        .inspect(|_| timing.mark("tree_reveal"))?;
    session.end(&mut streams).await?;
    Ok(outputs)
}

async fn run_derivation_cache(
    role: Role,
    port: u16,
    indices: &[Index48],
    share: Value32,
    peer_ip: IpAddr,
    trunk_chunk_blocks: i32,
    tile_fanout: usize,
) -> Result<Vec<(Index48, Value32)>, PartyError> {
    let lo = indices
        .first()
        .ok_or(PartyError::UnsupportedMode("range must not be empty"))?
        .get();
    let hi = indices
        .last()
        .ok_or(PartyError::UnsupportedMode("range must not be empty"))?
        .get();
    let mut timing = PhaseTiming::new(role, Index48::new(lo).expect("parser checked index"));
    let sha = sha256_compress_gadget()?;
    let tile_height = tile_height_for_fanout(tile_fanout)?;
    let (split, low_mask, high_mask) = range_split_masks(&[
        Index48::new(lo).expect("parser checked index"),
        Index48::new(hi).expect("parser checked index"),
    ])?;
    let trunk_groups = split_chain_bits(lo & high_mask, effective_chunk_size(trunk_chunk_blocks)?)?;
    if trunk_groups.iter().map(Vec::len).sum::<usize>() == 0 {
        return Err(PartyError::UnsupportedMode(
            "shachain2pc: cache needs >=1 common high set bit (no shared trunk hash); use batch mode for this range",
        ));
    }
    let mut tamper = TamperCursor::from_env();

    let mut trunk_programs = Vec::with_capacity(trunk_groups.len());
    for (chunk, bits) in trunk_groups.iter().enumerate() {
        trunk_programs.push(chunk_program(&sha, bits, chunk == 0, false)?);
    }

    let depth = if split < 0 {
        0usize
    } else {
        split as usize + 1
    };
    let aligned = split >= 0 && (lo & low_mask) == 0 && (hi & low_mask) == low_mask;
    let recursive_levels = if tile_height >= 1 && aligned && depth >= tile_height {
        Some(plan_tile_levels(depth, tile_height)?)
    } else {
        None
    };
    // Recursive-level tile circuits are built lazily, one level at a time, inside
    // the tiling loop below (see the level loop), so only the current level's
    // circuit is resident rather than all levels at once.

    // tile_program / one_step_program are built lazily below, after the recursive
    // path has had its chance to return -- the recursive case never uses them, so
    // building them up front just wastes a large unused circuit.

    let digest = cache_digest(
        lo,
        hi,
        trunk_chunk_blocks,
        i32::try_from(tile_fanout).map_err(|_| {
            PartyError::UnsupportedMode("SHACHAIN2PC_TILE_FANOUT is too large for this platform")
        })?,
        &sha,
    );
    timing.mark("build_cache_circuits");

    let mut streams = open_ag2pc_streams_after_digest(role, port, peer_ip, digest).await?;
    timing.mark("open_streams");
    let mut session = Ag2pcSession::setup(&mut streams, role, AG2PC_SSP).await?;
    streams.main.flush().await?;
    timing.mark("ag2pc_setup");

    let seed_inputs = authenticate_seed_inputs(&mut session, &mut streams, role, share).await?;
    timing.mark("input_auth");
    let mut trunk = session
        .run_program(&mut streams, &trunk_programs[0], &seed_inputs)
        .await?;
    timing.mark("cache_trunk_0");

    for (chunk, program) in trunk_programs.into_iter().enumerate().skip(1) {
        trunk = session.run_program(&mut streams, &program, &trunk).await?;
        timing.mark(match chunk {
            1 => "cache_trunk_1",
            2 => "cache_trunk_2",
            3 => "cache_trunk_3",
            _ => "cache_trunk",
        });
    }

    if let Some(levels) = &recursive_levels {
        let mut roots = vec![trunk.clone()];
        let n_levels = levels.len();
        for (level_index, &level) in levels.iter().enumerate() {
            // Build this level's tile circuit lazily; it is dropped at the end of
            // the iteration, so only one level's circuit is resident at a time.
            let program = build_tile_program(&sha, level.bit_offset, level.height, false)?;
            let is_bottom = level_index + 1 == n_levels;
            if is_bottom {
                let mut tiles = Vec::with_capacity(roots.len());
                for root in roots {
                    let tampered_program;
                    let program_ref = if tamper.matches_current() {
                        tampered_program = Some(build_tile_program(
                            &sha,
                            level.bit_offset,
                            level.height,
                            true,
                        )?);
                        tampered_program.as_ref().expect("tampered program set")
                    } else {
                        &program
                    };
                    let tile = session
                        .run_program(&mut streams, program_ref, &root)
                        .await?;
                    tiles.push(tile);
                    timing.mark("cache_tile");
                    tamper.advance();
                }

                let leaf_mask = (1u64 << level.height) - 1;
                let mut results = vec![None; (hi - lo + 1) as usize];
                let mut reveal_index = hi;
                loop {
                    let suffix = reveal_index & low_mask;
                    let tile_index = (suffix >> level.height) as usize;
                    let slot = (suffix & leaf_mask) as usize;
                    let tile = tiles.get(tile_index).ok_or(PartyError::UnsupportedMode(
                        "shachain2pc: missing recursive cached tile",
                    ))?;
                    let leaf = tile.slice(slot * VALUE_BITS, (slot + 1) * VALUE_BITS)?;
                    let bits = session.reveal_public(&mut streams, &leaf).await?;
                    results[(reveal_index - lo) as usize] = Some(value_from_bits(&bits)?);
                    if reveal_index == lo {
                        break;
                    }
                    reveal_index -= 1;
                }
                streams.main.flush().await?;
                timing.mark("cache_reveal");

                let outputs = indices
                    .iter()
                    .map(|index| {
                        let offset = (index.get() - lo) as usize;
                        Ok((
                            *index,
                            results[offset].ok_or(PartyError::UnsupportedMode(
                                "shachain2pc: missing recursive cached result",
                            ))?,
                        ))
                    })
                    .collect();
                session.end(&mut streams).await?;
                return outputs;
            }

            let mut next = Vec::with_capacity(roots.len() * (1usize << level.height));
            for root in roots {
                let tampered_program;
                let program_ref = if tamper.matches_current() {
                    tampered_program = Some(build_tile_program(
                        &sha,
                        level.bit_offset,
                        level.height,
                        true,
                    )?);
                    tampered_program.as_ref().expect("tampered program set")
                } else {
                    &program
                };
                let tile = session
                    .run_program(&mut streams, program_ref, &root)
                    .await?;
                for slot in 0..(1usize << level.height) {
                    next.push(tile.slice(slot * VALUE_BITS, (slot + 1) * VALUE_BITS)?);
                }
                timing.mark("cache_tile");
                tamper.advance();
            }
            roots = next;
        }
    }

    // Only reached when the recursive tiling did not apply; build the fallback
    // programs now (kept out of the recursive case to save that RAM).
    let tile_program = if tile_fanout >= 2 {
        Some(build_tile_program(&sha, 0, CACHE_TILE_HEIGHT, false)?)
    } else {
        None
    };
    let one_step_program = chunk_program(&sha, &[0], false, false)?;

    let mut stack = CacheStack::new(trunk);
    let mut tile_outs: HashMap<u64, Ag2pcSecureWires> = HashMap::new();
    let mut single_outs: HashMap<u64, Ag2pcSecureWires> = HashMap::new();
    let tile_mask = (CACHE_TILE_LEAVES as u64) - 1;
    let can_tile = tile_fanout >= 2 && split >= (CACHE_TILE_HEIGHT as i32 - 1);

    let mut index = hi;
    loop {
        let tile_base = index & !tile_mask;
        let full_tile = can_tile
            && (index & tile_mask) == tile_mask
            && tile_base >= lo
            && tile_base + tile_mask <= hi;
        if full_tile {
            let prefix = set_bits_desc((tile_base & low_mask) & !tile_mask);
            align_cache_stack(
                &mut session,
                &mut streams,
                &sha,
                &one_step_program,
                &mut stack,
                &prefix,
                &mut tamper,
            )
            .await?;
            let tampered_program;
            let tile_program_ref = if tamper.matches_current() {
                tampered_program = Some(build_tile_program(&sha, 0, CACHE_TILE_HEIGHT, true)?);
                tampered_program.as_ref().expect("tampered program set")
            } else {
                tile_program
                    .as_ref()
                    .expect("full_tile requires tile_program")
            };
            let tile = session
                .run_program(&mut streams, tile_program_ref, stack.last())
                .await?;
            tile_outs.insert(tile_base, tile);
            timing.mark("cache_tile");
            tamper.advance();

            if tile_base == lo {
                break;
            }
            index = tile_base - 1;
            continue;
        }

        let low = set_bits_desc(index & low_mask);
        align_cache_stack(
            &mut session,
            &mut streams,
            &sha,
            &one_step_program,
            &mut stack,
            &low,
            &mut tamper,
        )
        .await?;
        single_outs.insert(index, stack.last().clone());
        timing.mark("cache_single");
        if index == lo {
            break;
        }
        index -= 1;
    }

    let mut results = vec![None; (hi - lo + 1) as usize];
    let mut reveal_index = hi;
    loop {
        let tile_base = reveal_index & !tile_mask;
        if let Some(tile) = tile_outs.get(&tile_base) {
            let slot = (reveal_index & tile_mask) as usize;
            let leaf = tile.slice(slot * VALUE_BITS, (slot + 1) * VALUE_BITS)?;
            let bits = session.reveal_public(&mut streams, &leaf).await?;
            results[(reveal_index - lo) as usize] = Some(value_from_bits(&bits)?);
        } else {
            let wires = single_outs
                .get(&reveal_index)
                .ok_or(PartyError::UnsupportedMode(
                    "shachain2pc: missing cached output",
                ))?;
            let bits = session.reveal_public(&mut streams, wires).await?;
            results[(reveal_index - lo) as usize] = Some(value_from_bits(&bits)?);
        }
        if reveal_index == lo {
            break;
        }
        reveal_index -= 1;
    }
    streams.main.flush().await?;
    timing.mark("cache_reveal");

    let outputs = indices
        .iter()
        .map(|index| {
            let offset = (index.get() - lo) as usize;
            Ok((
                *index,
                results[offset].ok_or(PartyError::UnsupportedMode(
                    "shachain2pc: missing cached result",
                ))?,
            ))
        })
        .collect();
    session.end(&mut streams).await?;
    outputs
}

struct CacheStack {
    bits: Vec<usize>,
    vals: Vec<Ag2pcSecureWires>,
}

impl CacheStack {
    fn new(root: Ag2pcSecureWires) -> Self {
        Self {
            bits: Vec::new(),
            vals: vec![root],
        }
    }

    fn last(&self) -> &Ag2pcSecureWires {
        self.vals.last().expect("stack has trunk")
    }
}

struct TamperCursor {
    target: i64,
    current: i64,
}

impl TamperCursor {
    fn from_env() -> Self {
        Self {
            target: tamper_step_from_env(),
            current: 0,
        }
    }

    fn matches_current(&self) -> bool {
        self.current == self.target
    }

    fn advance(&mut self) {
        self.current += 1;
    }
}

async fn align_cache_stack(
    session: &mut Ag2pcSession,
    streams: &mut Ag2pcStreams,
    sha: &Circuit,
    one_step_template: &Ag2pcProgram,
    stack: &mut CacheStack,
    target: &[usize],
    tamper: &mut TamperCursor,
) -> Result<(), PartyError> {
    let mut prefix = 0usize;
    while prefix < stack.bits.len() && prefix < target.len() && stack.bits[prefix] == target[prefix]
    {
        prefix += 1;
    }
    stack.bits.truncate(prefix);
    stack.vals.truncate(prefix + 1);
    for &bit in &target[prefix..] {
        let should_tamper = tamper.matches_current();
        let program = if bit == 0 && !should_tamper {
            one_step_template.clone()
        } else {
            chunk_program(sha, &[bit], false, should_tamper)?
        };
        let next = session.run_program(streams, &program, stack.last()).await?;
        stack.vals.push(next);
        stack.bits.push(bit);
        tamper.advance();
    }
    Ok(())
}

async fn run_derivation_chunked(
    role: Role,
    port: u16,
    index: Index48,
    share: Value32,
    peer_ip: IpAddr,
    blocks_per_chunk: usize,
) -> Result<Value32, PartyError> {
    let mut timing = PhaseTiming::new(role, index);
    let sha = sha256_compress_gadget()?;
    let groups = split_chain_bits(index.get(), blocks_per_chunk)?;
    let tamper_chunk = tamper_step_from_env();
    let mut programs = Vec::with_capacity(groups.len());
    for (chunk, bits) in groups.iter().enumerate() {
        programs.push(chunk_program(
            &sha,
            bits,
            chunk == 0,
            chunk as i64 == tamper_chunk,
        )?);
    }
    let digest = chunk_spec_digest(index.get(), blocks_per_chunk as i32, &sha);
    timing.mark("build_chunk_circuits");

    let mut streams = open_ag2pc_streams_after_digest(role, port, peer_ip, digest).await?;
    timing.mark("open_streams");
    let mut session = Ag2pcSession::setup(&mut streams, role, AG2PC_SSP).await?;
    streams.main.flush().await?;
    timing.mark("ag2pc_setup");

    let seed_inputs = authenticate_seed_inputs(&mut session, &mut streams, role, share).await?;
    timing.mark("input_auth");
    let mut carried = session
        .run_program(&mut streams, &programs[0], &seed_inputs)
        .await?;
    timing.mark("chunk_0");

    for (chunk, program) in programs.into_iter().enumerate().skip(1) {
        carried = session
            .run_program(&mut streams, &program, &carried)
            .await?;
        timing.mark(match chunk {
            1 => "chunk_1",
            2 => "chunk_2",
            3 => "chunk_3",
            _ => "chunk",
        });
    }

    let output = session.reveal_public(&mut streams, &carried).await?;
    session.end(&mut streams).await?;
    streams.main.flush().await?;
    timing.mark("reveal");
    value_from_bits(&output)
}

async fn reveal_authenticated_values(
    session: &mut Ag2pcSession,
    streams: &mut Ag2pcStreams,
    authenticated: &[(Index48, Ag2pcSecureWires)],
) -> Result<Vec<(Index48, Value32)>, PartyError> {
    let mut outputs = Vec::with_capacity(authenticated.len());
    for (index, wires) in authenticated {
        let bits = session.reveal_public(streams, wires).await?;
        outputs.push((*index, value_from_bits(&bits)?));
    }
    streams.main.flush().await?;
    Ok(outputs)
}

async fn authenticate_seed_inputs(
    session: &mut Ag2pcSession,
    streams: &mut Ag2pcStreams,
    role: Role,
    share: Value32,
) -> Result<Ag2pcSecureWires, PartyError> {
    let mut bob_bits = vec![0u8; VALUE_BITS];
    let mut alice_bits = vec![0u8; VALUE_BITS];
    let mut share_bits = share.to_bits_msb();
    match role {
        Role::Alice => alice_bits.copy_from_slice(&share_bits),
        Role::Bob => bob_bits.copy_from_slice(&share_bits),
    }
    share_bits.zeroize();
    let mut bob_owner_bits = vec![bob_bits];
    let bob_inputs = session
        .process_inputs(streams, &[Role::Bob], &bob_owner_bits)
        .await?;
    for bits in &mut bob_owner_bits {
        bits.zeroize();
    }
    let mut alice_owner_bits = vec![alice_bits];
    let alice_inputs = session
        .process_inputs(streams, &[Role::Alice], &alice_owner_bits)
        .await?;
    for bits in &mut alice_owner_bits {
        bits.zeroize();
    }
    Ok(Ag2pcSecureWires::concat(&[
        bob_inputs[0].clone(),
        alice_inputs[0].clone(),
    ]))
}

fn value_from_bits(bits: &[u8]) -> Result<Value32, PartyError> {
    Value32::from_bits_msb(bits).map_err(|e| PartyError::Parse(e.to_string()))
}

struct PhaseTiming {
    enabled: bool,
    role: Role,
    index: Index48,
    start: Instant,
    last: Instant,
}

impl PhaseTiming {
    fn new(role: Role, index: Index48) -> Self {
        let enabled = env::var("SHACHAIN2PC_PHASE_TIMING")
            .map(|value| !value.is_empty() && value != "0")
            .unwrap_or(false);
        let now = Instant::now();
        Self {
            enabled,
            role,
            index,
            start: now,
            last: now,
        }
    }

    fn mark(&mut self, phase: &str) {
        if !self.enabled {
            return;
        }
        let now = Instant::now();
        let phase_ms = now.duration_since(self.last).as_secs_f64() * 1000.0;
        let total_ms = now.duration_since(self.start).as_secs_f64() * 1000.0;
        eprintln!(
            "TIMING role={} index={} phase={} phase_ms={:.3} total_ms={:.3}",
            self.role.party_id(),
            self.index.to_hex12(),
            phase,
            phase_ms,
            total_ms
        );
        self.last = now;
    }
}

fn ensure_index_allowed(index: &IndexSpec, allow_seed_reveal: bool) -> Result<(), PartyError> {
    // Index 0 is the shachain seed (generate_from_seed runs no SHA round at I=0),
    // not a normal per-commitment reveal, so require an explicit local override.
    // The C++ party (demo/party.cpp) enforces the same guard, including ranges
    // that contain 0.
    if index.contains_seed() && !allow_seed_reveal {
        Err(PartyError::SeedRevealRefused)
    } else {
        Ok(())
    }
}

fn requested_mode_from_env(is_range: bool) -> RequestedMode {
    if is_range && env_nonzero("SHACHAIN2PC_CACHE") {
        return RequestedMode::Cache;
    }
    if is_range && env_nonzero("SHACHAIN2PC_TREE") {
        return RequestedMode::Tree;
    }
    if env_positive("SHACHAIN2PC_CHUNK_BLOCKS") {
        return RequestedMode::Chunked;
    }
    RequestedMode::Full
}

fn env_nonzero(name: &str) -> bool {
    env::var(name)
        .ok()
        .and_then(|value| value.parse::<i32>().ok())
        .is_some_and(|value| value != 0)
}

fn env_positive(name: &str) -> bool {
    env::var(name)
        .ok()
        .and_then(|value| value.parse::<i32>().ok())
        .is_some_and(|value| value > 0)
}

fn chunk_blocks_from_env() -> Option<usize> {
    env::var("SHACHAIN2PC_CHUNK_BLOCKS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
}

fn trunk_chunk_blocks_from_env(default: i32) -> i32 {
    env::var("SHACHAIN2PC_CHUNK_BLOCKS")
        .ok()
        .and_then(|value| value.parse::<i32>().ok())
        .unwrap_or(default)
}

fn tile_fanout_from_env() -> Result<usize, PartyError> {
    let value = env::var("SHACHAIN2PC_TILE_FANOUT")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(CACHE_TILE_LEAVES);
    validate_tile_fanout(value)
}

fn validate_tile_fanout(value: usize) -> Result<usize, PartyError> {
    if value < 1 || !value.is_power_of_two() {
        return Err(PartyError::UnsupportedMode(
            "shachain2pc: tile_fanout must be a power of two",
        ));
    }
    if value > CACHE_TILE_LEAVES {
        return Err(PartyError::UnsupportedMode(
            "shachain2pc: tile_fanout > 16 not supported",
        ));
    }
    Ok(value)
}

fn tile_height_for_fanout(tile_fanout: usize) -> Result<usize, PartyError> {
    validate_tile_fanout(tile_fanout)?;
    Ok(tile_fanout.trailing_zeros() as usize)
}

fn effective_chunk_size(trunk_chunk_blocks: i32) -> Result<usize, PartyError> {
    if trunk_chunk_blocks > 0 {
        usize::try_from(trunk_chunk_blocks).map_err(|_| {
            PartyError::UnsupportedMode("SHACHAIN2PC_CHUNK_BLOCKS is too large for this platform")
        })
    } else {
        Ok(INDEX_BITS as usize)
    }
}

fn tamper_step_from_env() -> i64 {
    env::var("SHACHAIN2PC_TAMPER")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(-1)
}

// TEST ONLY: mirror C++ TamperFirstFlip. This keeps the circuit shape and digest
// unchanged but redirects the first real bit-flip INV gate to input wire 0,
// simulating a malicious garbler trying to steer the chain to a different index.
fn tamper_first_flip(circuit: &mut Circuit) {
    let c0_wire = circuit.gates.first().map(|gate| gate.out).unwrap_or(-1);
    for gate in &mut circuit.gates {
        if gate.typ == GateType::Inv && gate.in0 != c0_wire {
            gate.in0 = 0;
            return;
        }
    }
}

fn chunk_program(
    sha: &Circuit,
    bits: &[usize],
    first: bool,
    tamper: bool,
) -> Result<Ag2pcProgram, PartyError> {
    let mut circuit = build_chunk_circuit(sha, bits, first)?;
    if tamper {
        tamper_first_flip(&mut circuit);
    }
    check_chunk_circuit(&circuit)?;
    Ag2pcProgram::from_circuit(&circuit).map_err(PartyError::from)
}

fn build_tile_program(
    sha: &Circuit,
    bit_offset: usize,
    tile_height: usize,
    tamper: bool,
) -> Result<Ag2pcProgram, PartyError> {
    let mut circuit = build_tile_circuit(sha, bit_offset, tile_height)?;
    if tamper {
        tamper_first_flip(&mut circuit);
    }
    check_tile_circuit(&circuit, tile_height)?;
    Ag2pcProgram::from_circuit(&circuit).map_err(PartyError::from)
}

fn range_split_masks(indices: &[Index48]) -> Result<(i32, u64, u64), PartyError> {
    let first = indices
        .first()
        .ok_or(PartyError::UnsupportedMode("range must not be empty"))?
        .get();
    let mut diff = 0u64;
    for index in indices {
        diff |= index.get() ^ first;
    }
    let mut split = -1;
    for bit in (0..INDEX_BITS).rev() {
        if ((diff >> bit) & 1) != 0 {
            split = bit as i32;
            break;
        }
    }
    let low_mask = if split < 0 {
        0
    } else {
        (1u64 << (split as u32 + 1)) - 1
    };
    let high_mask = MAX_INDEX & !low_mask;
    Ok((split, low_mask, high_mask))
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

fn ensure_mode_supported_for_now(
    index_spec: &IndexSpec,
    mode: RequestedMode,
) -> Result<(), PartyError> {
    match (index_spec.is_range(), mode) {
        (false, RequestedMode::Full) => Ok(()),
        (true, RequestedMode::Full) => Ok(()),
        (false, RequestedMode::Chunked) => Ok(()),
        (_, RequestedMode::Chunked) => Err(PartyError::UnsupportedMode(
            "Rust SHACHAIN2PC_CHUNK_BLOCKS mode is single-index only",
        )),
        (true, RequestedMode::Tree) => Ok(()),
        (false, RequestedMode::Tree) => Err(PartyError::UnsupportedMode(
            "Rust SHACHAIN2PC_TREE mode requires a range",
        )),
        (true, RequestedMode::Cache) => Ok(()),
        (false, RequestedMode::Cache) => Err(PartyError::UnsupportedMode(
            "Rust SHACHAIN2PC_CACHE mode requires a range",
        )),
    }
}

async fn open_ag2pc_streams_after_digest(
    role: Role,
    port: u16,
    peer_ip: IpAddr,
    digest: [u8; 32],
) -> Result<Ag2pcStreams, PartyError> {
    // The C++ party exchanges the circuit digest on the main stream before it
    // constructs AG2PCSession, so the sibling stream must be opened after it.
    match role {
        Role::Alice => {
            let listener =
                TcpListener::bind(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), port)).await?;
            let mut main = accept_emp(&listener).await?;
            exchange_circuit_digest(&mut main, role, digest).await?;
            let sibling = accept_emp(&listener).await?;
            Ok(Ag2pcStreams { main, sibling })
        }
        Role::Bob => {
            let mut main = EmpStream::connect(peer_ip, port).await?;
            exchange_circuit_digest(&mut main, role, digest).await?;
            sleep(Duration::from_millis(1)).await;
            let sibling = EmpStream::connect(peer_ip, port).await?;
            Ok(Ag2pcStreams { main, sibling })
        }
    }
}

async fn accept_emp(listener: &TcpListener) -> Result<EmpStream, PartyError> {
    loop {
        let (stream, _) = listener.accept().await?;
        match EmpStream::new(stream) {
            Ok(stream) => return Ok(stream),
            Err(_) => sleep(Duration::from_millis(1)).await,
        }
    }
}

async fn exchange_circuit_digest(
    stream: &mut EmpStream,
    role: Role,
    digest: [u8; 32],
) -> Result<(), PartyError> {
    let peer = match role {
        Role::Alice => {
            stream.send_data(&digest).await?;
            stream.flush().await?;
            recv_digest(stream).await?
        }
        Role::Bob => {
            let peer = recv_digest(stream).await?;
            stream.send_data(&digest).await?;
            stream.flush().await?;
            peer
        }
    };
    if peer == digest {
        Ok(())
    } else {
        Err(PartyError::CircuitMismatch)
    }
}

async fn recv_digest(stream: &mut EmpStream) -> Result<[u8; 32], PartyError> {
    Ok(stream
        .recv_data(32)
        .await?
        .try_into()
        .expect("digest length"))
}

fn parse_args(args: Vec<String>) -> Result<Args, PartyError> {
    let program = args.first().cloned().unwrap_or_else(|| "party".to_owned());
    let mut allow_seed_reveal = false;
    let mut positional = Vec::new();
    for arg in args.into_iter().skip(1) {
        if arg == "--allow-seed-reveal" {
            allow_seed_reveal = true;
        } else if arg.starts_with("--") {
            return Err(PartyError::Parse(format!("unknown flag: {arg}")));
        } else {
            positional.push(arg);
        }
    }
    if positional.len() < 4 || positional.len() > 5 {
        return Err(PartyError::Usage(usage(&program)));
    }
    let role_id = positional[0]
        .parse::<u8>()
        .map_err(|_| PartyError::Parse(format!("party must be 1 or 2, got {}", positional[0])))?;
    let role = Role::from_party_id(role_id).map_err(|e| PartyError::Parse(e.to_string()))?;
    let port = positional[1]
        .parse::<u16>()
        .map_err(|_| PartyError::Parse("port must be in 1..65535".to_owned()))?;
    if port == 0 {
        return Err(PartyError::Parse("port must be in 1..65535".to_owned()));
    }
    let index_spec = parse_index_spec(&positional[2])?;
    let share = Value32::from_hex(&positional[3]).map_err(|e| PartyError::Parse(e.to_string()))?;
    ensure_index_allowed(&index_spec, allow_seed_reveal)?;
    let peer_ip = if let Some(peer) = positional.get(4) {
        peer.parse()
            .map_err(|_| PartyError::Parse(format!("bad peer ip: {peer}")))?
    } else {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    };
    Ok(Args {
        role,
        port,
        index_spec,
        share,
        peer_ip,
        allow_seed_reveal,
    })
}

fn parse_index_spec(spec: &str) -> Result<IndexSpec, PartyError> {
    if let Some(dash) = spec.find('-') {
        let lo_s = &spec[..dash];
        let hi_s = &spec[dash + 1..];
        if lo_s.is_empty() || hi_s.is_empty() {
            return Err(PartyError::Parse(
                "range must be LO-HI (both hex)".to_owned(),
            ));
        }
        let lo = Index48::from_hex(lo_s).map_err(|e| PartyError::Parse(e.to_string()))?;
        let hi = Index48::from_hex(hi_s).map_err(|e| PartyError::Parse(e.to_string()))?;
        if lo > hi {
            return Err(PartyError::Parse("range LO must be <= HI".to_owned()));
        }
        let count = hi.get() - lo.get() + 1;
        const MAX_BATCH: u64 = 100_000;
        if count > MAX_BATCH {
            return Err(PartyError::Parse(
                "range too large (max 100000 indices)".to_owned(),
            ));
        }
        Ok(IndexSpec::Range { lo, hi })
    } else {
        let index = Index48::from_hex(spec).map_err(|e| PartyError::Parse(e.to_string()))?;
        Ok(IndexSpec::Single(index))
    }
}

fn usage(program: &str) -> String {
    format!(
        "usage: {program} [--allow-seed-reveal] <1|2> <port> <I_spec> <share_hex> [peer_ip]\n  I_spec = single hex index (\"64\") or inclusive hex range (\"64-c8\")\n  1 = ALICE (garbler, listens), 2 = BOB (evaluator, connects)"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use shachain2pc_circuit::generate_from_seed;
    use std::net::TcpListener as StdTcpListener;
    use std::sync::OnceLock;
    use tokio::sync::Mutex;
    use tokio::time::timeout;

    const SHARE_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SHARE_B: &str = "abababababababababababababababababababababababababababababababab";
    const INDEX_ZERO_RESULT: &str =
        "0101010101010101010101010101010101010101010101010101010101010101";
    static PARTY_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rust_party_i0_honest_matches_reference() {
        let (alice, bob) = run_pair(
            Index48::from_hex("0").unwrap(),
            Index48::from_hex("0").unwrap(),
            true,
            true,
            Duration::from_secs(60),
        )
        .await;
        let expected = Value32::from_hex(INDEX_ZERO_RESULT).unwrap();
        assert_eq!(alice.unwrap(), expected);
        assert_eq!(bob.unwrap(), expected);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rust_party_i0_without_allow_seed_reveal_refuses_before_socket() {
        let port = free_port();
        let err = run_derivation(test_args(
            Role::Alice,
            port,
            Index48::from_hex("0").unwrap(),
            SHARE_A,
            false,
        ))
        .await
        .unwrap_err();
        assert!(matches!(err, PartyError::SeedRevealRefused));
        StdTcpListener::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rust_party_rejects_index_mismatch_before_output() {
        let (alice, bob) = run_pair(
            Index48::from_hex("1").unwrap(),
            Index48::from_hex("3").unwrap(),
            false,
            false,
            Duration::from_secs(120),
        )
        .await;
        assert!(matches!(alice, Err(PartyError::CircuitMismatch)));
        assert!(matches!(bob, Err(PartyError::CircuitMismatch)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rust_party_real_circuits_match_reference() {
        assert_party_pair_matches_reference("1", Duration::from_secs(300)).await;
        assert_party_pair_matches_reference("3", Duration::from_secs(600)).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rust_party_chunked_i0_matches_reference() {
        let index = Index48::from_hex("0").unwrap();
        let (alice, bob) = run_pair_chunked(index, 1, Duration::from_secs(300)).await;
        let expected = generate_from_seed(combined_seed(), index);
        assert_eq!(alice.unwrap(), expected);
        assert_eq!(bob.unwrap(), expected);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "48 SHA blocks are too slow for the default debug test run"]
    async fn rust_party_full_start_index_matches_reference() {
        assert_party_pair_matches_reference("ffffffffffff", Duration::from_secs(7200)).await;
    }

    #[test]
    fn parse_allow_seed_reveal_position_independently() {
        for args in [
            vec!["party", "--allow-seed-reveal", "1", "1234", "0", SHARE_A],
            vec!["party", "1", "--allow-seed-reveal", "1234", "0", SHARE_A],
            vec!["party", "1", "1234", "0", SHARE_A, "--allow-seed-reveal"],
        ] {
            let parsed = parse_args(args.into_iter().map(str::to_owned).collect()).unwrap();
            assert!(parsed.allow_seed_reveal);
            assert_eq!(
                parsed.index_spec,
                IndexSpec::Single(Index48::new(0).unwrap())
            );
        }
    }

    #[test]
    fn parse_i0_without_allow_seed_reveal_refuses() {
        let err = parse_args(
            ["party", "1", "1234", "0", SHARE_A]
                .into_iter()
                .map(str::to_owned)
                .collect(),
        )
        .unwrap_err();
        assert!(matches!(err, PartyError::SeedRevealRefused));
    }

    #[test]
    fn parses_range_index_spec() {
        let parsed = parse_args(
            ["party", "1", "1234", "64-c8", SHARE_A]
                .into_iter()
                .map(str::to_owned)
                .collect(),
        )
        .unwrap();
        assert_eq!(
            parsed.index_spec,
            IndexSpec::Range {
                lo: Index48::from_hex("64").unwrap(),
                hi: Index48::from_hex("c8").unwrap(),
            }
        );

        let err = parse_index_spec("c8-64").unwrap_err();
        assert!(matches!(err, PartyError::Parse(msg) if msg == "range LO must be <= HI"));

        let err = parse_index_spec("1-").unwrap_err();
        assert!(matches!(err, PartyError::Parse(msg) if msg == "range must be LO-HI (both hex)"));

        let err = parse_index_spec("0-186a0").unwrap_err();
        assert!(
            matches!(err, PartyError::Parse(msg) if msg == "range too large (max 100000 indices)")
        );
    }

    #[test]
    fn parse_range_containing_seed_requires_flag() {
        let err = parse_args(
            ["party", "1", "1234", "0-5", SHARE_A]
                .into_iter()
                .map(str::to_owned)
                .collect(),
        )
        .unwrap_err();
        assert!(matches!(err, PartyError::SeedRevealRefused));

        let parsed = parse_args(
            ["party", "--allow-seed-reveal", "1", "1234", "0-5", SHARE_A]
                .into_iter()
                .map(str::to_owned)
                .collect(),
        )
        .unwrap();
        assert_eq!(
            parsed.index_spec,
            IndexSpec::Range {
                lo: Index48::new(0).unwrap(),
                hi: Index48::new(5).unwrap(),
            }
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rust_range_i0_honest_matches_reference() {
        let index = Index48::from_hex("0").unwrap();
        let (alice, bob) = run_pair_range(index, index, true, Duration::from_secs(60)).await;
        let expected = vec![(index, generate_from_seed(combined_seed(), index))];
        assert_eq!(alice.unwrap(), expected);
        assert_eq!(bob.unwrap(), expected);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rust_tree_range_matches_reference() {
        let lo = Index48::from_hex("800000000000").unwrap();
        let hi = Index48::from_hex("800000000001").unwrap();
        let (alice, bob) = run_pair_tree(lo, hi, 0, Duration::from_secs(900)).await;
        let expected = expected_range(lo, hi);
        assert_eq!(alice.unwrap(), expected);
        assert_eq!(bob.unwrap(), expected);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rust_cache_fallback_range_matches_reference() {
        let lo = Index48::from_hex("800000000000").unwrap();
        let hi = Index48::from_hex("800000000001").unwrap();
        let (alice, bob) = run_pair_cache(lo, hi, 16, 1, Duration::from_secs(900)).await;
        let expected = expected_range(lo, hi);
        assert_eq!(alice.unwrap(), expected);
        assert_eq!(bob.unwrap(), expected);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "16-leaf cache tile is too slow for the default debug test run"]
    async fn rust_cache_tile_range_matches_reference() {
        let lo = Index48::from_hex("800000000000").unwrap();
        let hi = Index48::from_hex("80000000000f").unwrap();
        let (alice, bob) = run_pair_cache(lo, hi, 16, 16, Duration::from_secs(7200)).await;
        let expected = expected_range(lo, hi);
        assert_eq!(alice.unwrap(), expected);
        assert_eq!(bob.unwrap(), expected);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "recursive cache tile tree is too slow for the default debug test run"]
    async fn rust_cache_recursive_tile_range_matches_reference() {
        let lo = Index48::from_hex("800000000000").unwrap();
        let hi = Index48::from_hex("800000000003").unwrap();
        let (alice, bob) = run_pair_cache(lo, hi, 16, 2, Duration::from_secs(7200)).await;
        let expected = expected_range(lo, hi);
        assert_eq!(alice.unwrap(), expected);
        assert_eq!(bob.unwrap(), expected);
    }

    #[test]
    fn mode_support_boundary_is_explicit() {
        let single = IndexSpec::Single(Index48::from_hex("1").unwrap());
        let range = IndexSpec::Range {
            lo: Index48::from_hex("64").unwrap(),
            hi: Index48::from_hex("65").unwrap(),
        };

        assert!(ensure_mode_supported_for_now(&single, RequestedMode::Full).is_ok());
        assert!(ensure_mode_supported_for_now(&range, RequestedMode::Full).is_ok());
        assert!(ensure_mode_supported_for_now(&single, RequestedMode::Chunked).is_ok());
        assert!(matches!(
            ensure_mode_supported_for_now(&range, RequestedMode::Chunked),
            Err(PartyError::UnsupportedMode(msg)) if msg.contains("single-index")
        ));
        assert!(ensure_mode_supported_for_now(&range, RequestedMode::Tree).is_ok());
        assert!(ensure_mode_supported_for_now(&range, RequestedMode::Cache).is_ok());
    }

    #[test]
    fn range_split_masks_match_high_trunk_low_branch() {
        let indices = [
            Index48::from_hex("800000000010").unwrap(),
            Index48::from_hex("80000000001f").unwrap(),
        ];
        let (split, low_mask, high_mask) = range_split_masks(&indices).unwrap();
        assert_eq!(split, 3);
        assert_eq!(low_mask, 0x0f);
        assert_eq!(high_mask, 0xffff_ffff_fff0);
        assert_eq!(set_bits_desc(indices[0].get() & high_mask), vec![47, 4]);
        assert_eq!(set_bits_desc(indices[1].get() & low_mask), vec![3, 2, 1, 0]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rust_tree_without_shared_hash_refuses_before_socket() {
        let port = free_port();
        let lo = Index48::from_hex("1").unwrap();
        let hi = Index48::from_hex("2").unwrap();
        let err = run_derivation_tree(
            Role::Alice,
            port,
            &[lo, hi],
            Value32::from_hex(SHARE_A).unwrap(),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, PartyError::UnsupportedMode(msg) if msg.contains("shared-trunk")));
        StdTcpListener::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rust_cache_without_shared_hash_refuses_before_socket() {
        let port = free_port();
        let lo = Index48::from_hex("1").unwrap();
        let hi = Index48::from_hex("2").unwrap();
        let err = run_derivation_cache(
            Role::Alice,
            port,
            &[lo, hi],
            Value32::from_hex(SHARE_A).unwrap(),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            16,
            16,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, PartyError::UnsupportedMode(msg) if msg.contains("cache needs")));
        StdTcpListener::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
    }

    async fn assert_party_pair_matches_reference(index_hex: &str, timeout_duration: Duration) {
        let index = Index48::from_hex(index_hex).unwrap();
        let (alice, bob) = run_pair(index, index, false, false, timeout_duration).await;
        let expected = generate_from_seed(combined_seed(), index);
        assert_eq!(alice.unwrap(), expected);
        assert_eq!(bob.unwrap(), expected);
    }

    async fn run_pair(
        alice_index: Index48,
        bob_index: Index48,
        alice_allow_seed_reveal: bool,
        bob_allow_seed_reveal: bool,
        timeout_duration: Duration,
    ) -> (Result<Value32, PartyError>, Result<Value32, PartyError>) {
        let _guard = party_test_lock().lock().await;
        let port = free_port();
        let alice = tokio::spawn(run_derivation(test_args(
            Role::Alice,
            port,
            alice_index,
            SHARE_A,
            alice_allow_seed_reveal,
        )));
        sleep(Duration::from_millis(50)).await;
        let bob = tokio::spawn(run_derivation(test_args(
            Role::Bob,
            port,
            bob_index,
            SHARE_B,
            bob_allow_seed_reveal,
        )));
        timeout(timeout_duration, async {
            let alice = alice.await.unwrap();
            let bob = bob.await.unwrap();
            (alice, bob)
        })
        .await
        .unwrap()
    }

    async fn run_pair_chunked(
        index: Index48,
        blocks_per_chunk: usize,
        timeout_duration: Duration,
    ) -> (Result<Value32, PartyError>, Result<Value32, PartyError>) {
        let _guard = party_test_lock().lock().await;
        let port = free_port();
        let alice = tokio::spawn(run_derivation_chunked(
            Role::Alice,
            port,
            index,
            Value32::from_hex(SHARE_A).unwrap(),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            blocks_per_chunk,
        ));
        sleep(Duration::from_millis(50)).await;
        let bob = tokio::spawn(run_derivation_chunked(
            Role::Bob,
            port,
            index,
            Value32::from_hex(SHARE_B).unwrap(),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            blocks_per_chunk,
        ));
        timeout(timeout_duration, async {
            let alice = alice.await.unwrap();
            let bob = bob.await.unwrap();
            (alice, bob)
        })
        .await
        .unwrap()
    }

    async fn run_pair_tree(
        lo: Index48,
        hi: Index48,
        trunk_chunk_blocks: i32,
        timeout_duration: Duration,
    ) -> (
        Result<Vec<(Index48, Value32)>, PartyError>,
        Result<Vec<(Index48, Value32)>, PartyError>,
    ) {
        let _guard = party_test_lock().lock().await;
        let port = free_port();
        let alice_indices = indices_between(lo, hi);
        let bob_indices = alice_indices.clone();
        let alice = tokio::spawn(async move {
            run_derivation_tree(
                Role::Alice,
                port,
                &alice_indices,
                Value32::from_hex(SHARE_A).unwrap(),
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                trunk_chunk_blocks,
            )
            .await
        });
        sleep(Duration::from_millis(50)).await;
        let bob = tokio::spawn(async move {
            run_derivation_tree(
                Role::Bob,
                port,
                &bob_indices,
                Value32::from_hex(SHARE_B).unwrap(),
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                trunk_chunk_blocks,
            )
            .await
        });
        timeout(timeout_duration, async {
            let alice = alice.await.unwrap();
            let bob = bob.await.unwrap();
            (alice, bob)
        })
        .await
        .unwrap()
    }

    async fn run_pair_cache(
        lo: Index48,
        hi: Index48,
        trunk_chunk_blocks: i32,
        tile_fanout: usize,
        timeout_duration: Duration,
    ) -> (
        Result<Vec<(Index48, Value32)>, PartyError>,
        Result<Vec<(Index48, Value32)>, PartyError>,
    ) {
        let _guard = party_test_lock().lock().await;
        let port = free_port();
        let alice_indices = indices_between(lo, hi);
        let bob_indices = alice_indices.clone();
        let alice = tokio::spawn(async move {
            run_derivation_cache(
                Role::Alice,
                port,
                &alice_indices,
                Value32::from_hex(SHARE_A).unwrap(),
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                trunk_chunk_blocks,
                tile_fanout,
            )
            .await
        });
        sleep(Duration::from_millis(50)).await;
        let bob = tokio::spawn(async move {
            run_derivation_cache(
                Role::Bob,
                port,
                &bob_indices,
                Value32::from_hex(SHARE_B).unwrap(),
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                trunk_chunk_blocks,
                tile_fanout,
            )
            .await
        });
        timeout(timeout_duration, async {
            let alice = alice.await.unwrap();
            let bob = bob.await.unwrap();
            (alice, bob)
        })
        .await
        .unwrap()
    }

    async fn run_pair_range(
        lo: Index48,
        hi: Index48,
        allow_seed_reveal: bool,
        timeout_duration: Duration,
    ) -> (
        Result<Vec<(Index48, Value32)>, PartyError>,
        Result<Vec<(Index48, Value32)>, PartyError>,
    ) {
        let _guard = party_test_lock().lock().await;
        let port = free_port();
        let alice = tokio::spawn(run_party(test_range_args(
            Role::Alice,
            port,
            lo,
            hi,
            SHARE_A,
            allow_seed_reveal,
        )));
        sleep(Duration::from_millis(50)).await;
        let bob = tokio::spawn(run_party(test_range_args(
            Role::Bob,
            port,
            lo,
            hi,
            SHARE_B,
            allow_seed_reveal,
        )));
        timeout(timeout_duration, async {
            let alice = match alice.await.unwrap() {
                Ok(PartyOutput::Range(outputs)) => Ok(outputs),
                Ok(PartyOutput::Single(_)) => Err(PartyError::UnsupportedMode(
                    "test expected range output, got single output",
                )),
                Err(e) => Err(e),
            };
            let bob = match bob.await.unwrap() {
                Ok(PartyOutput::Range(outputs)) => Ok(outputs),
                Ok(PartyOutput::Single(_)) => Err(PartyError::UnsupportedMode(
                    "test expected range output, got single output",
                )),
                Err(e) => Err(e),
            };
            (alice, bob)
        })
        .await
        .unwrap()
    }

    fn test_args(
        role: Role,
        port: u16,
        index: Index48,
        share: &str,
        allow_seed_reveal: bool,
    ) -> Args {
        Args {
            role,
            port,
            index_spec: IndexSpec::Single(index),
            share: Value32::from_hex(share).unwrap(),
            peer_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            allow_seed_reveal,
        }
    }

    fn test_range_args(
        role: Role,
        port: u16,
        lo: Index48,
        hi: Index48,
        share: &str,
        allow_seed_reveal: bool,
    ) -> Args {
        Args {
            role,
            port,
            index_spec: IndexSpec::Range { lo, hi },
            share: Value32::from_hex(share).unwrap(),
            peer_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            allow_seed_reveal,
        }
    }

    fn party_test_lock() -> &'static Mutex<()> {
        PARTY_TEST_LOCK.get_or_init(|| Mutex::new(()))
    }

    fn combined_seed() -> Value32 {
        Value32::from_hex(SHARE_A)
            .unwrap()
            .xor(Value32::from_hex(SHARE_B).unwrap())
    }

    fn indices_between(lo: Index48, hi: Index48) -> Vec<Index48> {
        (lo.get()..=hi.get())
            .map(|value| Index48::new(value).unwrap())
            .collect()
    }

    fn expected_range(lo: Index48, hi: Index48) -> Vec<(Index48, Value32)> {
        indices_between(lo, hi)
            .into_iter()
            .map(|index| (index, generate_from_seed(combined_seed(), index)))
            .collect()
    }

    fn free_port() -> u16 {
        StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }
}
