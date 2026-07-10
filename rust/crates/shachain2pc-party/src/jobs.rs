pub async fn run_seed_root_job(
    endpoint: MpcTcpEndpoint,
    share: Value32,
    delta: shachain2pc_emp_wire::Block,
    digest: [u8; 32],
    ssp: usize,
) -> Result<Ag2pcSecureWires, PartyError> {
    let sha = shared_sha_circuit();
    run_seed_root_job_with_circuit(endpoint, share, delta, digest, ssp, &sha).await
}

pub async fn run_seed_root_job_with_circuit(
    endpoint: MpcTcpEndpoint,
    share: Value32,
    delta: shachain2pc_emp_wire::Block,
    digest: [u8; 32],
    ssp: usize,
    sha: &Circuit,
) -> Result<Ag2pcSecureWires, PartyError> {
    let program = Ag2pcProgram::chunk_from_sha(sha, &[], true)?;
    let mut streams =
        open_ag2pc_streams_after_digest(endpoint.role, endpoint.port, endpoint.peer_ip, digest)
            .await?;
    let mut session =
        Ag2pcSession::setup_with_delta(&mut streams, endpoint.role, ssp, delta).await?;
    streams.main.flush().await?;
    let seed_inputs =
        authenticate_seed_inputs(&mut session, &mut streams, endpoint.role, share).await?;
    let root = session
        .run_program(&mut streams, &program, &seed_inputs)
        .await?;
    session.end(&mut streams).await?;
    streams.main.flush().await?;
    Ok(root)
}

pub async fn run_one_hash_job(
    endpoint: MpcTcpEndpoint,
    parent: &Ag2pcSecureWires,
    bit: usize,
    delta: shachain2pc_emp_wire::Block,
    digest: [u8; 32],
    ssp: usize,
) -> Result<Ag2pcSecureWires, PartyError> {
    if bit >= INDEX_BITS as usize {
        return Err(PartyError::UnsupportedMode(
            "one-H job bit is outside the 48-bit shachain index",
        ));
    }
    let sha = shared_sha_circuit();
    run_one_hash_job_with_circuit(endpoint, parent, bit, delta, digest, ssp, &sha).await
}

pub async fn run_one_hash_job_with_circuit(
    endpoint: MpcTcpEndpoint,
    parent: &Ag2pcSecureWires,
    bit: usize,
    delta: shachain2pc_emp_wire::Block,
    digest: [u8; 32],
    ssp: usize,
    sha: &Circuit,
) -> Result<Ag2pcSecureWires, PartyError> {
    if bit >= INDEX_BITS as usize {
        return Err(PartyError::UnsupportedMode(
            "one-H job bit is outside the 48-bit shachain index",
        ));
    }
    let program = Ag2pcProgram::chunk_from_sha(sha, &[bit], false)?;
    let mut streams =
        open_ag2pc_streams_after_digest(endpoint.role, endpoint.port, endpoint.peer_ip, digest)
            .await?;
    let mut session =
        Ag2pcSession::setup_with_delta(&mut streams, endpoint.role, ssp, delta).await?;
    streams.main.flush().await?;
    let child = session.run_program(&mut streams, &program, parent).await?;
    session.end(&mut streams).await?;
    streams.main.flush().await?;
    Ok(child)
}

pub async fn run_precompute_path_job(
    endpoint: MpcTcpEndpoint,
    share: Value32,
    index: Index48,
    delta: shachain2pc_emp_wire::Block,
    digest: [u8; 32],
    ssp: usize,
) -> Result<Vec<(u64, Ag2pcSecureWires)>, PartyError> {
    let mut streams =
        open_ag2pc_streams_after_digest(endpoint.role, endpoint.port, endpoint.peer_ip, digest)
            .await?;
    run_precompute_path_with_streams(&mut streams, endpoint.role, share, index, delta, ssp).await
}

pub struct PrecomputeSession<S: TranscriptIo + IdleTrim> {
    streams: Ag2pcStreams<S>,
    session: Ag2pcSession,
    sha: Arc<Circuit>,
    seed_inputs: Ag2pcSecureWires,
    cache: BTreeMap<u32, (u64, Ag2pcSecureWires)>,
}

impl<S: TranscriptIo + IdleTrim> PrecomputeSession<S> {
    pub async fn setup_with_streams(
        streams: Ag2pcStreams<S>,
        role: Role,
        share: Value32,
        delta: shachain2pc_emp_wire::Block,
        ssp: usize,
    ) -> Result<Self, PartyError> {
        let sha = shared_sha_circuit();
        Self::setup_with_streams_and_circuit(streams, role, share, delta, ssp, sha).await
    }

    pub async fn setup_with_streams_and_circuit(
        mut streams: Ag2pcStreams<S>,
        role: Role,
        share: Value32,
        delta: shachain2pc_emp_wire::Block,
        ssp: usize,
        sha: Arc<Circuit>,
    ) -> Result<Self, PartyError> {
        let mut session = Ag2pcSession::setup_with_delta(&mut streams, role, ssp, delta).await?;
        streams.main.flush().await?;
        let seed_inputs = authenticate_seed_inputs(&mut session, &mut streams, role, share).await?;
        Ok(Self {
            streams,
            session,
            sha,
            seed_inputs,
            cache: BTreeMap::new(),
        })
    }

    pub fn streams_mut(&mut self) -> &mut Ag2pcStreams<S> {
        &mut self.streams
    }

    pub fn circuit(&self) -> &Arc<Circuit> {
        &self.sha
    }

    pub fn planned_checked_units(&self, index: Index48) -> u64 {
        self.missing_bits(index.get()).len() as u64
    }

    pub async fn precompute_target(
        &mut self,
        index: Index48,
    ) -> Result<Ag2pcSecureWires, PartyError> {
        let target = index.get();
        if target == 0 {
            let root_program = Ag2pcProgram::chunk_from_sha(self.sha.as_ref(), &[], true)?;
            let mut root = self
                .session
                .run_program(&mut self.streams, &root_program, &self.seed_inputs)
                .await?;
            self.session.trim_idle_allocations();
            self.streams.trim_idle_allocations();
            root.strip_labels_for_reveal();
            return Ok(root);
        }

        let mut mask = 0u64;
        let mut carried = Ag2pcSecureWires::default();
        let mut have_carried = false;
        if let Some((parent_mask, parent)) = self.best_parent(target) {
            mask = parent_mask;
            carried = parent;
            have_carried = true;
        }
        if mask == target {
            carried.strip_labels_for_reveal();
            return Ok(carried);
        }

        for bit in set_bits_desc(target & !mask) {
            let first = !have_carried;
            let input = if have_carried {
                &carried
            } else {
                &self.seed_inputs
            };
            let program = Ag2pcProgram::chunk_from_sha(self.sha.as_ref(), &[bit], first)?;
            let child = self
                .session
                .run_program(&mut self.streams, &program, input)
                .await?;
            mask |= 1u64 << bit;
            carried = child;
            have_carried = true;
            if retain_cache_mask_for_future(mask, target) {
                self.cache
                    .insert(mask.trailing_zeros(), (mask, carried.clone()));
            }
        }
        prune_cache_for_target(&mut self.cache, target);
        self.session.trim_idle_allocations();
        self.streams.trim_idle_allocations();

        let mut persisted = carried;
        persisted.strip_labels_for_reveal();
        Ok(persisted)
    }

    pub async fn finish(mut self) -> Result<(), PartyError> {
        self.session.end(&mut self.streams).await?;
        self.streams.main.flush().await?;
        Ok(())
    }

    fn missing_bits(&self, target: u64) -> Vec<usize> {
        let Some((parent_mask, _parent)) = self.best_parent(target) else {
            return set_bits_desc(target);
        };
        set_bits_desc(target & !parent_mask)
    }

    fn best_parent(&self, target: u64) -> Option<(u64, Ag2pcSecureWires)> {
        self.cache
            .values()
            .filter(|(mask, _wires)| can_derive_mask(*mask, target))
            .max_by_key(|(mask, _wires)| mask.count_ones())
            .map(|(mask, wires)| (*mask, wires.clone()))
    }
}

pub async fn run_precompute_path_with_streams<S: TranscriptIo>(
    streams: &mut Ag2pcStreams<S>,
    role: Role,
    share: Value32,
    index: Index48,
    delta: shachain2pc_emp_wire::Block,
    ssp: usize,
) -> Result<Vec<(u64, Ag2pcSecureWires)>, PartyError> {
    let sha = shared_sha_circuit();
    run_precompute_path_with_streams_and_circuit(streams, role, share, index, delta, ssp, &sha)
        .await
}

pub async fn run_precompute_path_with_streams_and_circuit<S: TranscriptIo>(
    streams: &mut Ag2pcStreams<S>,
    role: Role,
    share: Value32,
    index: Index48,
    delta: shachain2pc_emp_wire::Block,
    ssp: usize,
    sha: &Circuit,
) -> Result<Vec<(u64, Ag2pcSecureWires)>, PartyError> {
    let mut session = Ag2pcSession::setup_with_delta(streams, role, ssp, delta).await?;
    streams.main.flush().await?;

    let seed_inputs = authenticate_seed_inputs(&mut session, streams, role, share).await?;
    let bits = set_bits_desc(index.get());
    let mut out = Vec::with_capacity(bits.len().max(1));
    if bits.is_empty() {
        let root_program = Ag2pcProgram::chunk_from_sha(sha, &[], true)?;
        let mut root = session
            .run_program(streams, &root_program, &seed_inputs)
            .await?;
        root.strip_labels_for_reveal();
        out.push((0, root));
        session.end(streams).await?;
        streams.main.flush().await?;
        return Ok(out);
    }

    let mut bits_iter = bits.into_iter();
    let first_bit = bits_iter
        .next()
        .expect("non-empty bit vector has a first bit");
    let mut mask = 1u64 << first_bit;
    let first_program = Ag2pcProgram::chunk_from_sha(sha, &[first_bit], true)?;
    let mut carried = session
        .run_program(streams, &first_program, &seed_inputs)
        .await?;
    let mut persisted = carried.clone();
    persisted.strip_labels_for_reveal();
    out.push((mask, persisted));

    for bit in bits_iter {
        mask |= 1u64 << bit;
        let program = Ag2pcProgram::chunk_from_sha(sha, &[bit], false)?;
        carried = session.run_program(streams, &program, &carried).await?;
        let mut persisted = carried.clone();
        persisted.strip_labels_for_reveal();
        out.push((mask, persisted));
    }

    session.end(streams).await?;
    streams.main.flush().await?;
    Ok(out)
}

pub async fn reveal_node_job(
    endpoint: MpcTcpEndpoint,
    node: &Ag2pcSecureWires,
    delta: Block,
    digest: [u8; 32],
    ssp: usize,
) -> Result<Value32, PartyError> {
    let mut streams =
        open_ag2pc_streams_after_digest(endpoint.role, endpoint.port, endpoint.peer_ip, digest)
            .await?;
    let mut session =
        Ag2pcSession::setup_with_delta(&mut streams, endpoint.role, ssp, delta).await?;
    streams.main.flush().await?;
    let mut reveal = node.clone();
    reveal.strip_labels_for_reveal();
    let bits = session.reveal_public(&mut streams, &reveal).await?;
    session.end(&mut streams).await?;
    streams.main.flush().await?;
    value_from_bits(&bits)
}

pub async fn reveal_node_fast_job(
    endpoint: MpcTcpEndpoint,
    node: &Ag2pcSecureWires,
    delta: Block,
    digest: [u8; 32],
) -> Result<Value32, PartyError> {
    let mut streams =
        open_ag2pc_streams_after_digest(endpoint.role, endpoint.port, endpoint.peer_ip, digest)
            .await?;
    let mut reveal = node.clone();
    reveal.strip_labels_for_reveal();
    reveal_node_fast_over_streams(&mut streams, endpoint.role, &reveal, delta).await
}

#[derive(Clone, Debug)]
pub struct RevealNodeShare {
    pub share_bits: Vec<u8>,
    pub mac_digest: [u8; HASH_DIGEST_BYTES],
}

#[derive(Clone, Debug)]
pub struct RevealNodeOpen {
    pub bits: Vec<u8>,
    pub value: Value32,
}

pub fn reveal_node_local_share(node: &Ag2pcSecureWires) -> Result<RevealNodeShare, PartyError> {
    if node.wire_bundle.len() != node.len() {
        return Err(CompatError::BadAg2pcInputShape.into());
    }
    let local = reveal_local_share(&node.wire_bundle);
    Ok(RevealNodeShare {
        share_bits: local.share_bits,
        mac_digest: local.mac_digest,
    })
}

pub fn reveal_node_from_peer_share(
    node: &Ag2pcSecureWires,
    delta: Block,
    peer_share_bits: &[u8],
    peer_mac_digest: [u8; HASH_DIGEST_BYTES],
) -> Result<RevealNodeOpen, PartyError> {
    if node.wire_bundle.len() != node.len() {
        return Err(CompatError::BadAg2pcInputShape.into());
    }
    let bits = reveal_recipient_bits(
        &node.lambda,
        &node.wire_bundle,
        peer_share_bits,
        peer_mac_digest,
        delta,
    )
    .map_err(map_reveal_error_for_party)?;
    let value = value_from_bits(&bits)?;
    Ok(RevealNodeOpen { bits, value })
}

async fn reveal_node_fast_over_streams<S: TranscriptIo>(
    streams: &mut Ag2pcStreams<S>,
    role: Role,
    wires: &Ag2pcSecureWires,
    delta: Block,
) -> Result<Value32, PartyError> {
    match role {
        Role::Alice => {
            let local = reveal_node_local_share(wires)?;
            streams.main.send_data(&local.share_bits).await?;
            streams.main.send_data(&local.mac_digest).await?;
            streams.main.flush().await?;
            let bits = streams
                .main
                .recv_data(wires.len())
                .await?
                .into_iter()
                .map(|bit| bit & 1)
                .collect::<Vec<_>>();
            value_from_bits(&bits)
        }
        Role::Bob => {
            let peer_share = streams.main.recv_data(wires.len()).await?;
            let peer_digest: [u8; HASH_DIGEST_BYTES] = streams
                .main
                .recv_data(HASH_DIGEST_BYTES)
                .await?
                .try_into()
                .expect("digest length");
            let opened = reveal_node_from_peer_share(wires, delta, &peer_share, peer_digest)?;
            streams.main.send_data(&opened.bits).await?;
            streams.main.flush().await?;
            Ok(opened.value)
        }
    }
}

fn map_reveal_error_for_party(error: RevealError) -> PartyError {
    match error {
        RevealError::MacDigestMismatch => CompatError::FeqMismatch.into(),
        RevealError::BadWireShape { .. } | RevealError::PeerShareLength { .. } => {
            CompatError::BadAg2pcInputShape.into()
        }
    }
}
