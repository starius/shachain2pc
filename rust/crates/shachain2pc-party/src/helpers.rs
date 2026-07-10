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

async fn authenticate_seed_inputs<S: TranscriptIo>(
    session: &mut Ag2pcSession,
    streams: &mut Ag2pcStreams<S>,
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
    last_wire: Option<WireSnapshot>,
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
            last_wire: None,
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

    fn mark_streams(&mut self, phase: &str, streams: &Ag2pcStreams<EmpStream>) {
        if !self.enabled {
            return;
        }
        let current = WireSnapshot::from_streams(streams);
        let delta = self.last_wire.map(|last| current.saturating_sub(last));
        self.last_wire = Some(current);

        let now = Instant::now();
        let phase_ms = now.duration_since(self.last).as_secs_f64() * 1000.0;
        let total_ms = now.duration_since(self.start).as_secs_f64() * 1000.0;
        if let Some(delta) = delta {
            eprintln!(
                "TIMING role={} index={} phase={} phase_ms={:.3} total_ms={:.3} send_bytes={} recv_bytes={} rounds={} flushes={}",
                self.role.party_id(),
                self.index.to_hex12(),
                phase,
                phase_ms,
                total_ms,
                delta.send_bytes,
                delta.recv_bytes,
                delta.rounds,
                delta.flushes
            );
        } else {
            eprintln!(
                "TIMING role={} index={} phase={} phase_ms={:.3} total_ms={:.3} send_bytes={} recv_bytes={} rounds={} flushes={}",
                self.role.party_id(),
                self.index.to_hex12(),
                phase,
                phase_ms,
                total_ms,
                current.send_bytes,
                current.recv_bytes,
                current.rounds,
                current.flushes
            );
        }
        self.last = now;
    }
}

#[derive(Clone, Copy)]
struct WireSnapshot {
    send_bytes: u64,
    recv_bytes: u64,
    rounds: u64,
    flushes: u64,
}

impl WireSnapshot {
    fn from_streams(streams: &Ag2pcStreams<EmpStream>) -> Self {
        Self {
            send_bytes: streams.main.send_counter() + streams.sibling.send_counter(),
            recv_bytes: streams.main.recv_counter() + streams.sibling.recv_counter(),
            rounds: streams.main.rounds() + streams.sibling.rounds(),
            flushes: streams.main.flushes_count() + streams.sibling.flushes_count(),
        }
    }

    fn saturating_sub(self, rhs: Self) -> Self {
        Self {
            send_bytes: self.send_bytes.saturating_sub(rhs.send_bytes),
            recv_bytes: self.recv_bytes.saturating_sub(rhs.recv_bytes),
            rounds: self.rounds.saturating_sub(rhs.rounds),
            flushes: self.flushes.saturating_sub(rhs.flushes),
        }
    }
}

fn ensure_index_allowed(index: &IndexSpec, allow_seed_reveal: bool) -> Result<(), PartyError> {
    // Index 0 is the shachain seed (generate_from_seed runs no SHA round at I=0),
    // not a normal per-commitment reveal, so require an explicit local override.
    // The C++ party (cpp/demo/party.cpp) enforces the same guard, including ranges
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
    if !tamper {
        return Ag2pcProgram::chunk_from_sha(sha, bits, first).map_err(PartyError::from);
    }
    let mut circuit = build_chunk_circuit(sha, bits, first)?;
    tamper_first_flip(&mut circuit);
    check_chunk_circuit(&circuit)?;
    Ag2pcProgram::from_circuit(&circuit).map_err(PartyError::from)
}

fn build_tile_program(
    sha: &Circuit,
    bit_offset: usize,
    tile_height: usize,
    tamper: bool,
) -> Result<Ag2pcProgram, PartyError> {
    if !tamper {
        return Ag2pcProgram::tile_from_sha(sha, bit_offset, tile_height).map_err(PartyError::from);
    }
    let mut circuit = build_tile_circuit(sha, bit_offset, tile_height)?;
    tamper_first_flip(&mut circuit);
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

fn can_derive_mask(from_index: u64, to_index: u64) -> bool {
    if from_index & !to_index != 0 {
        return false;
    }
    let missing = to_index & !from_index;
    if from_index != 0 {
        let lowest_applied = from_index.trailing_zeros();
        if missing >> lowest_applied != 0 {
            return false;
        }
    }
    true
}

fn max_derivable_mask(from_index: u64) -> u64 {
    if from_index == 0 {
        return MAX_INDEX;
    }
    let lowest_applied = from_index.trailing_zeros();
    let lower_bits = if lowest_applied == 0 {
        0
    } else {
        (1u64 << lowest_applied) - 1
    };
    (from_index | lower_bits) & MAX_INDEX
}

fn retain_cache_mask_for_future(mask: u64, current_target: u64) -> bool {
    mask == current_target || max_derivable_mask(mask) > current_target
}

fn prune_cache_for_target(cache: &mut BTreeMap<u32, (u64, Ag2pcSecureWires)>, current_target: u64) {
    cache.retain(|_, (mask, _)| retain_cache_mask_for_future(*mask, current_target));
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

pub fn parse_args(args: Vec<String>) -> Result<Args, PartyError> {
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
