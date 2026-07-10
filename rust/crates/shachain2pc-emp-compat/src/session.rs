struct Ag2pcRunState {
    party: Role,
    delta: Block,
    num_inputs: usize,
    num_ands: usize,
    num_wires: usize,
    num_slots: usize,
    // Per-wire metadata as u32/i32 (circuits have < 2^32 wires/gates): half the
    // size of usize/isize, and these are num_wires-long.
    phys: Vec<u32>,
    last_use: Vec<i32>,
    persist: Vec<bool>,
    wire_slot: Vec<AShareBundle>,
    mask_input: Vec<u8>,
    label_slot: Vec<Block>,
    eval_slot: Vec<Block>,
    rep_a: Vec<AShareBundle>,
    rep_b: Vec<AShareBundle>,
    sigma: Vec<AShareBundle>,
    lambda_and: Vec<u8>,
    mitc: Mitccrh8,
}

impl Ag2pcRunState {
    fn new(party: Role, delta: Block, inputs: &Ag2pcSecureWires) -> Self {
        Self {
            party,
            delta,
            num_inputs: inputs.len(),
            num_ands: 0,
            num_wires: 0,
            num_slots: inputs.len(),
            phys: Vec::new(),
            last_use: Vec::new(),
            persist: Vec::new(),
            wire_slot: inputs.wire_bundle.clone(),
            mask_input: inputs.lambda.clone(),
            label_slot: inputs.label0.clone(),
            eval_slot: inputs.eval_label.clone(),
            rep_a: Vec::new(),
            rep_b: Vec::new(),
            sigma: Vec::new(),
            lambda_and: Vec::new(),
            mitc: Mitccrh8::new(Block::zero()),
        }
    }

    fn slot(&self, wire: usize) -> usize {
        self.phys[wire] as usize
    }

    fn wslot(&self, wire: usize) -> AShareBundle {
        self.wire_slot[self.slot(wire)]
    }

    fn set_wslot(&mut self, wire: usize, value: AShareBundle) {
        let slot = self.slot(wire);
        self.wire_slot[slot] = value;
    }

    fn minp(&self, wire: usize) -> u8 {
        self.mask_input[self.slot(wire)]
    }

    fn set_minp(&mut self, wire: usize, value: u8) {
        let slot = self.slot(wire);
        self.mask_input[slot] = value & 1;
    }

    fn lbl(&self, wire: usize) -> Block {
        self.label_slot[self.slot(wire)]
    }

    fn set_lbl(&mut self, wire: usize, value: Block) {
        let slot = self.slot(wire);
        self.label_slot[slot] = value;
    }

    fn evl(&self, wire: usize) -> Block {
        self.eval_slot[self.slot(wire)]
    }

    fn set_evl(&mut self, wire: usize, value: Block) {
        let slot = self.slot(wire);
        self.eval_slot[slot] = value;
    }
}

pub struct Ag2pcSession {
    protocol: Ag2pcProtocol,
}

impl Ag2pcSession {
    pub async fn setup<S: TranscriptIo>(
        streams: &mut Ag2pcStreams<S>,
        party: Role,
        ssp: usize,
    ) -> Result<Self> {
        Ok(Self {
            protocol: Ag2pcProtocol::setup(streams, party, ssp).await?,
        })
    }

    pub async fn setup_with_delta<S: TranscriptIo>(
        streams: &mut Ag2pcStreams<S>,
        party: Role,
        ssp: usize,
        delta: Block,
    ) -> Result<Self> {
        Ok(Self {
            protocol: Ag2pcProtocol::setup_with_delta(streams, party, ssp, delta).await?,
        })
    }

    pub fn party(&self) -> Role {
        self.protocol.party()
    }

    pub fn delta(&self) -> Block {
        self.protocol.delta()
    }

    pub fn process_input_calls(&self) -> usize {
        self.protocol.process_input_calls()
    }

    pub async fn process_inputs<S: TranscriptIo>(
        &mut self,
        streams: &mut Ag2pcStreams<S>,
        owners: &[Role],
        bits_per_owner: &[Vec<u8>],
    ) -> Result<Vec<Ag2pcSecureWires>> {
        self.protocol
            .process_inputs(streams, owners, bits_per_owner)
            .await
    }

    pub fn public_wires(&self, bits: &[u8]) -> Ag2pcSecureWires {
        self.protocol.public_wires(bits)
    }

    pub async fn run_program<S: TranscriptIo>(
        &mut self,
        streams: &mut Ag2pcStreams<S>,
        program: &Ag2pcProgram,
        inputs: &Ag2pcSecureWires,
    ) -> Result<Ag2pcSecureWires> {
        self.protocol.check_secure_wires(inputs)?;
        if inputs.len() != program.num_inputs {
            return Err(CompatError::BadAg2pcInputLength {
                expected: program.num_inputs,
                actual: inputs.len(),
            });
        }
        let mut state = Ag2pcRunState::new(self.party(), self.protocol.delta(), inputs);
        ag2pc_liveness_pass(&mut state, program);
        ag2pc_slot_mask_pass(&mut state, program, &mut self.protocol.triple_pool, streams).await?;
        let rep_a = std::mem::take(&mut state.rep_a);
        let rep_b = std::mem::take(&mut state.rep_b);
        state.sigma = self
            .protocol
            .triple_pool
            .compute_inplace_owned(streams, rep_a, rep_b)
            .await?;
        state.lambda_and = vec![0; state.num_ands.max(1)];
        let seed = EmpRo::new("AG2PC half-gate", Block::zero())
            .absorb_block(streams.main.get_digest()?)
            .absorb_block(streams.sibling.get_digest()?)
            .squeeze_block();
        state.mitc = Mitccrh8::new(seed);
        match self.party() {
            Role::Alice => ag2pc_garbler_path(&mut state, program, streams).await?,
            Role::Bob => ag2pc_evaluator_path(&mut state, program, streams).await?,
        }
        self.protocol.flush_cot_check(streams).await?;
        ag2pc_gather_outputs(&state, program)
    }

    pub async fn reveal_public<S: TranscriptIo>(
        &mut self,
        streams: &mut Ag2pcStreams<S>,
        wires: &Ag2pcSecureWires,
    ) -> Result<Vec<u8>> {
        self.protocol
            .decode(streams, wires, Ag2pcRevealRecipient::Public)
            .await
    }

    pub fn trim_idle_allocations(&mut self) {
        self.protocol.trim_idle_allocations();
    }

    pub async fn end<S: TranscriptIo>(&mut self, streams: &mut Ag2pcStreams<S>) -> Result<()> {
        self.protocol.end(streams).await
    }
}

fn ag2pc_liveness_pass(state: &mut Ag2pcRunState, program: &Ag2pcProgram) {
    state.num_wires = program.num_wires;
    state.num_ands = 0;
    state.last_use = vec![-1; program.num_wires];
    state.persist = vec![false; program.num_wires];
    for i in 0..state.num_inputs {
        state.persist[i] = true;
    }
    for (gate_index, gate) in program.gates.iter().enumerate() {
        let out = program.gate_out(gate_index);
        state.persist[out] = gate.typ() == Ag2pcGateType::And;
        state.last_use[gate.in0()] = gate_index as i32;
        if gate.typ() != Ag2pcGateType::Inv {
            state.last_use[gate.in1()] = gate_index as i32;
        }
        if gate.typ() == Ag2pcGateType::And {
            state.num_ands += 1;
        }
    }
    for &out in &program.outputs {
        state.persist[out as usize] = true;
    }
}

async fn ag2pc_slot_mask_pass<S: TranscriptIo>(
    state: &mut Ag2pcRunState,
    program: &Ag2pcProgram,
    triple_pool: &mut Ag2pcTriplePool,
    streams: &mut Ag2pcStreams<S>,
) -> Result<()> {
    let slot_capacity = ag2pc_slot_capacity(state, program);
    state
        .wire_slot
        .reserve_exact(slot_capacity.saturating_sub(state.wire_slot.len()));
    state
        .mask_input
        .reserve_exact(slot_capacity.saturating_sub(state.mask_input.len()));
    state.phys = vec![u32::MAX; program.num_wires];
    for i in 0..state.num_inputs {
        state.phys[i] = i as u32;
    }
    state.rep_a.clear();
    state.rep_b.clear();
    state.rep_a.reserve_exact(state.num_ands);
    state.rep_b.reserve_exact(state.num_ands);

    let mut freelist = Vec::new();
    let mut lg_buf = Vec::new();
    let mut lg_off = 0usize;

    for (gate_index, gate) in program.gates.iter().enumerate() {
        let out = program.gate_out(gate_index);
        match gate.typ() {
            Ag2pcGateType::And => {
                state.rep_a.push(state.wslot(gate.in0()));
                state.rep_b.push(state.wslot(gate.in1()));
                if lg_off >= lg_buf.len() {
                    lg_buf = triple_pool.draw(streams, 1 << 14).await?;
                    lg_off = 0;
                }
                let slot = ag2pc_alloc_slot(state, out, &mut freelist);
                state.wire_slot[slot] = lg_buf[lg_off];
                state.mask_input[slot] = 0;
                lg_off += 1;
            }
            Ag2pcGateType::Xor => {
                let lhs = state.wslot(gate.in0());
                let rhs = state.wslot(gate.in1());
                let slot = ag2pc_alloc_slot(state, out, &mut freelist);
                state.wire_slot[slot] = AShareBundle {
                    mac: lhs.mac.xor(rhs.mac),
                    key: lhs.key.xor(rhs.key),
                };
                state.mask_input[slot] = 0;
            }
            Ag2pcGateType::Inv => {
                let value = state.wslot(gate.in0());
                let slot = ag2pc_alloc_slot(state, out, &mut freelist);
                state.wire_slot[slot] = value;
                state.mask_input[slot] = 0;
            }
        }
        ag2pc_free_if_dead(state, gate.in0(), gate_index, &mut freelist);
        if gate.typ() != Ag2pcGateType::Inv && gate.in1() != gate.in0() {
            ag2pc_free_if_dead(state, gate.in1(), gate_index, &mut freelist);
        }
    }

    match state.party {
        Role::Alice => state.label_slot.resize(state.num_slots, Block::zero()),
        Role::Bob => state.eval_slot.resize(state.num_slots, Block::zero()),
    }
    Ok(())
}

fn ag2pc_slot_capacity(state: &Ag2pcRunState, program: &Ag2pcProgram) -> usize {
    let mut phys = vec![u32::MAX; program.num_wires];
    for (wire, slot) in phys.iter_mut().take(state.num_inputs).enumerate() {
        *slot = wire as u32;
    }

    let mut num_slots = state.num_inputs;
    let mut freelist = Vec::new();
    for (gate_index, gate) in program.gates.iter().enumerate() {
        let out = program.gate_out(gate_index);
        let slot = if !state.persist[out] {
            freelist.pop().unwrap_or_else(|| {
                let slot = num_slots;
                num_slots += 1;
                slot
            })
        } else {
            let slot = num_slots;
            num_slots += 1;
            slot
        };
        phys[out] = slot as u32;

        ag2pc_capacity_free_if_dead(state, &phys, gate.in0(), gate_index, &mut freelist);
        if gate.typ() != Ag2pcGateType::Inv && gate.in1() != gate.in0() {
            ag2pc_capacity_free_if_dead(state, &phys, gate.in1(), gate_index, &mut freelist);
        }
    }
    num_slots
}

fn ag2pc_capacity_free_if_dead(
    state: &Ag2pcRunState,
    phys: &[u32],
    wire: usize,
    gate_index: usize,
    freelist: &mut Vec<usize>,
) {
    if !state.persist[wire] && state.last_use[wire] == gate_index as i32 {
        freelist.push(phys[wire] as usize);
    }
}

fn ag2pc_alloc_slot(state: &mut Ag2pcRunState, wire: usize, freelist: &mut Vec<usize>) -> usize {
    let slot = if !state.persist[wire] {
        freelist.pop().unwrap_or_else(|| ag2pc_push_slot(state))
    } else {
        ag2pc_push_slot(state)
    };
    state.phys[wire] = slot as u32;
    slot
}

fn ag2pc_push_slot(state: &mut Ag2pcRunState) -> usize {
    let slot = state.num_slots;
    state.num_slots += 1;
    state.wire_slot.push(AShareBundle::default());
    state.mask_input.push(0);
    slot
}

fn ag2pc_free_if_dead(
    state: &Ag2pcRunState,
    wire: usize,
    gate_index: usize,
    freelist: &mut Vec<usize>,
) {
    if !state.persist[wire] && state.last_use[wire] == gate_index as i32 {
        freelist.push(state.slot(wire));
    }
}

async fn ag2pc_garbler_path<S: TranscriptIo>(
    state: &mut Ag2pcRunState,
    program: &Ag2pcProgram,
    streams: &mut Ag2pcStreams<S>,
) -> Result<()> {
    let chunk_ands = state.num_ands.min(AG2PC_GARBLE_CHUNK_ANDS);
    let mut chunk_g = Vec::with_capacity(2 * chunk_ands);
    let mut chunk_b = Vec::with_capacity(chunk_ands);
    let mut and_index = 0usize;
    for (gate_index, gate) in program.gates.iter().enumerate() {
        let out = program.gate_out(gate_index);
        match gate.typ() {
            Ag2pcGateType::Xor => {
                let lhs = state.wslot(gate.in0());
                let rhs = state.wslot(gate.in1());
                state.set_wslot(
                    out,
                    AShareBundle {
                        mac: lhs.mac.xor(rhs.mac),
                        key: lhs.key.xor(rhs.key),
                    },
                );
                state.set_lbl(out, state.lbl(gate.in0()).xor(state.lbl(gate.in1())));
            }
            Ag2pcGateType::Inv => {
                state.set_wslot(out, state.wslot(gate.in0()));
                state.set_lbl(out, state.lbl(gate.in0()).xor(state.delta));
            }
            Ag2pcGateType::And => {
                let (g0, g1, b) = ag2pc_garbler_and_gate(state, gate, out, and_index);
                chunk_g.push(g0);
                chunk_g.push(g1);
                chunk_b.push(b);
                and_index += 1;
                if chunk_b.len() == AG2PC_GARBLE_CHUNK_ANDS {
                    ag2pc_send_garble_chunk(&mut streams.main, &chunk_g, &chunk_b).await?;
                    chunk_g.clear();
                    chunk_b.clear();
                }
            }
        }
    }
    if !chunk_b.is_empty() {
        ag2pc_send_garble_chunk(&mut streams.main, &chunk_g, &chunk_b).await?;
    }
    if state.num_ands > 0 {
        state.lambda_and = ag2pc_recv_bool_vector(&mut streams.main, state.num_ands).await?;
        let digest = ag2pc_gamma_check_digest(state, program);
        streams.main.send_data(&digest).await?;
        streams.main.flush().await?;
    }
    Ok(())
}

fn ag2pc_garbler_and_gate(
    state: &mut Ag2pcRunState,
    gate: &Ag2pcProgramGate,
    out: usize,
    and_index: usize,
) -> (Block, Block, u8) {
    let ml_a0 = state.lbl(gate.in0());
    let ml_a1 = ml_a0.xor(state.delta);
    let ml_b0 = state.lbl(gate.in1());
    let ml_b1 = ml_b0.xor(state.delta);
    let mut buf = [ml_a0, ml_a1, ml_b0, ml_b1];
    state.mitc.hash_cir(&mut buf, 1, 4);

    let wb_in0 = state.wslot(gate.in0());
    let wb_in1 = state.wslot(gate.in1());
    let wb_out = state.wslot(out);
    let sigma = state.sigma[and_index];
    let h_a0 = buf[0];
    let h_a1 = buf[1];
    let h_b0 = buf[2];
    let h_b1 = buf[3];

    let la_dot = select_block(block_lsb(wb_in0.mac)).and(state.delta);
    let lb_dot = select_block(block_lsb(wb_in1.mac)).and(state.delta);
    let lab_dot = select_block(block_lsb(sigma.mac)).and(state.delta);
    let lg_dot = select_block(block_lsb(wb_out.mac)).and(state.delta);

    let g0 = h_a0.xor(h_a1).xor(wb_in1.key).xor(lb_dot);
    let g1 = h_b0.xor(h_b1).xor(ml_a0).xor(wb_in0.key).xor(la_dot);
    let ml_g0 = h_a0
        .xor(h_b0)
        .xor(sigma.key)
        .xor(lab_dot)
        .xor(wb_out.key)
        .xor(lg_dot);
    state.set_lbl(out, ml_g0);
    (g0, g1, block_lsb1(ml_g0))
}

async fn ag2pc_evaluator_path<S: TranscriptIo>(
    state: &mut Ag2pcRunState,
    program: &Ag2pcProgram,
    streams: &mut Ag2pcStreams<S>,
) -> Result<()> {
    let chunk_ands = state.num_ands.min(AG2PC_GARBLE_CHUNK_ANDS);
    let mut chunk_g = Vec::with_capacity(2 * chunk_ands);
    let mut chunk_b = Vec::with_capacity(chunk_ands);
    let mut chunk_pos = 0usize;
    let mut and_index = 0usize;
    let mut gamma_hash = Sha256::new();
    for (gate_index, gate) in program.gates.iter().enumerate() {
        let out = program.gate_out(gate_index);
        match gate.typ() {
            Ag2pcGateType::Xor => {
                let lhs = state.wslot(gate.in0());
                let rhs = state.wslot(gate.in1());
                state.set_wslot(
                    out,
                    AShareBundle {
                        mac: lhs.mac.xor(rhs.mac),
                        key: lhs.key.xor(rhs.key),
                    },
                );
                state.set_evl(out, state.evl(gate.in0()).xor(state.evl(gate.in1())));
                state.set_minp(out, state.minp(gate.in0()) ^ state.minp(gate.in1()));
            }
            Ag2pcGateType::Inv => {
                state.set_wslot(out, state.wslot(gate.in0()));
                state.set_evl(out, state.evl(gate.in0()));
                state.set_minp(out, state.minp(gate.in0()) ^ 1);
            }
            Ag2pcGateType::And => {
                if chunk_pos == chunk_b.len() {
                    let remaining = state.num_ands - and_index;
                    let n = remaining.min(AG2PC_GARBLE_CHUNK_ANDS);
                    let (g, b) = ag2pc_recv_garble_chunk(&mut streams.main, n).await?;
                    chunk_g = g;
                    chunk_b = b;
                    chunk_pos = 0;
                }
                let m = ag2pc_evaluator_and_gate(
                    state,
                    gate,
                    out,
                    and_index,
                    chunk_g[2 * chunk_pos],
                    chunk_g[2 * chunk_pos + 1],
                    chunk_b[chunk_pos],
                );
                gamma_hash.update(m.as_bytes());
                and_index += 1;
                chunk_pos += 1;
            }
        }
    }
    if state.num_ands > 0 {
        ag2pc_send_bool_vector(&mut streams.main, &state.lambda_and).await?;
        let local: [u8; HASH_DIGEST_BYTES] = gamma_hash.finalize().into();
        let peer: [u8; HASH_DIGEST_BYTES] = streams
            .main
            .recv_data(HASH_DIGEST_BYTES)
            .await?
            .try_into()
            .expect("digest length");
        if local != peer {
            return Err(CompatError::FeqMismatch);
        }
    }
    Ok(())
}

fn ag2pc_evaluator_and_gate(
    state: &mut Ag2pcRunState,
    gate: &Ag2pcProgramGate,
    out: usize,
    and_index: usize,
    g0: Block,
    g1: Block,
    b: u8,
) -> Block {
    let la = state.minp(gate.in0());
    let lb = state.minp(gate.in1());
    let wb_in0 = state.wslot(gate.in0());
    let wb_in1 = state.wslot(gate.in1());
    let wb_out = state.wslot(out);
    let sigma = state.sigma[and_index];

    let mut mr = sigma.mac.xor(wb_out.mac);
    mr = mr.xor(select_block(la).and(wb_in1.mac));
    mr = mr.xor(select_block(lb).and(wb_in0.mac));

    let mut buf = [state.evl(gate.in0()), state.evl(gate.in1())];
    state.mitc.hash_cir(&mut buf, 1, 2);
    let mut t = buf[0].xor(buf[1]);
    t = t.xor(select_block(la).and(g0));
    t = t.xor(select_block(lb).and(g1.xor(state.evl(gate.in0()))));
    t = t.xor(mr);
    state.set_evl(out, t);
    let lg = b ^ block_lsb1(t);
    state.set_minp(out, lg);
    state.lambda_and[and_index] = lg;

    let v_in0 = block_lsb(wb_in0.mac);
    let v_in1 = block_lsb(wb_in1.mac);
    let v_out = block_lsb(wb_out.mac);
    let v_sig = block_lsb(sigma.mac);
    let t1 = (la & lb) ^ lg ^ (la & v_in1) ^ (lb & v_in0) ^ v_sig ^ v_out;
    let mut m = select_block(t1).and(state.delta);
    m = m.xor(select_block(la).and(wb_in1.key));
    m = m.xor(select_block(lb).and(wb_in0.key));
    m = m.xor(sigma.key).xor(wb_out.key);
    m
}

fn ag2pc_gamma_check_digest(
    state: &mut Ag2pcRunState,
    program: &Ag2pcProgram,
) -> [u8; HASH_DIGEST_BYTES] {
    let mut and_index = 0usize;
    let mut gamma_hash = Sha256::new();
    for (gate_index, gate) in program.gates.iter().enumerate() {
        let out = program.gate_out(gate_index);
        match gate.typ() {
            Ag2pcGateType::Xor => {
                let lhs = state.wslot(gate.in0());
                let rhs = state.wslot(gate.in1());
                state.set_wslot(
                    out,
                    AShareBundle {
                        mac: lhs.mac.xor(rhs.mac),
                        key: lhs.key.xor(rhs.key),
                    },
                );
                state.set_minp(out, state.minp(gate.in0()) ^ state.minp(gate.in1()));
            }
            Ag2pcGateType::Inv => {
                state.set_wslot(out, state.wslot(gate.in0()));
                state.set_minp(out, state.minp(gate.in0()) ^ 1);
            }
            Ag2pcGateType::And => {
                state.set_minp(out, state.lambda_and[and_index]);
                let la = state.minp(gate.in0());
                let lb = state.minp(gate.in1());
                let mut m = state.sigma[and_index].mac.xor(state.wslot(out).mac);
                m = m.xor(select_block(la).and(state.wslot(gate.in1()).mac));
                m = m.xor(select_block(lb).and(state.wslot(gate.in0()).mac));
                gamma_hash.update(m.as_bytes());
                and_index += 1;
            }
        }
    }
    gamma_hash.finalize().into()
}

fn ag2pc_gather_outputs(state: &Ag2pcRunState, program: &Ag2pcProgram) -> Result<Ag2pcSecureWires> {
    let mut out = Ag2pcSecureWires {
        lambda: Vec::with_capacity(program.outputs.len()),
        wire_bundle: Vec::with_capacity(program.outputs.len()),
        label0: Vec::new(),
        eval_label: Vec::new(),
    };
    match state.party {
        Role::Alice => out.label0 = Vec::with_capacity(program.outputs.len()),
        Role::Bob => out.eval_label = Vec::with_capacity(program.outputs.len()),
    }
    for &wire in &program.outputs {
        let wire = wire as usize;
        out.lambda.push(state.minp(wire));
        out.wire_bundle.push(state.wslot(wire));
        match state.party {
            Role::Alice => out.label0.push(state.lbl(wire)),
            Role::Bob => out.eval_label.push(state.evl(wire)),
        }
    }
    Ok(out)
}

async fn ag2pc_send_garble_chunk<S: ByteIo>(stream: &mut S, g: &[Block], b: &[u8]) -> Result<()> {
    stream.send_block(g).await?;
    stream.send_data(b).await?;
    stream.flush().await?;
    Ok(())
}

async fn ag2pc_recv_garble_chunk<S: ByteIo>(
    stream: &mut S,
    n: usize,
) -> Result<(Vec<Block>, Vec<u8>)> {
    let g = stream.recv_block(2 * n).await?;
    let b = stream.recv_data(n).await?;
    Ok((g, b))
}

const AG2PC_GARBLE_CHUNK_ANDS: usize = 1 << 16;

impl Ag2pcProtocol {
    pub async fn setup<S: TranscriptIo>(
        streams: &mut Ag2pcStreams<S>,
        party: Role,
        ssp: usize,
    ) -> Result<Self> {
        let delta = random_ag2pc_delta(party)?;
        Self::setup_with_delta(streams, party, ssp, delta).await
    }

    pub async fn setup_with_delta<S: TranscriptIo>(
        streams: &mut Ag2pcStreams<S>,
        party: Role,
        ssp: usize,
        delta: Block,
    ) -> Result<Self> {
        let delta = normalize_ag2pc_delta(party, delta);
        let triple_pool = Ag2pcTriplePool::setup_with_delta(streams, party, ssp, delta).await?;
        Ok(Self {
            party,
            delta: triple_pool.delta(),
            triple_pool,
            prg: Prg::new(random_block()?, 0),
            process_input_calls: 0,
        })
    }

    pub fn party(&self) -> Role {
        self.party
    }

    pub fn delta(&self) -> Block {
        self.delta
    }

    pub fn process_input_calls(&self) -> usize {
        self.process_input_calls
    }

    pub fn trim_idle_allocations(&mut self) {
        self.triple_pool.trim_idle_allocations();
    }

    pub async fn flush_cot_check<S: TranscriptIo>(
        &mut self,
        streams: &mut Ag2pcStreams<S>,
    ) -> Result<()> {
        self.triple_pool.maybe_flush_cot_check(streams).await
    }

    pub async fn end<S: TranscriptIo>(&mut self, streams: &mut Ag2pcStreams<S>) -> Result<()> {
        self.triple_pool.end(streams).await
    }

    pub fn public_wires(&self, bits: &[u8]) -> Ag2pcSecureWires {
        let mut wires = Ag2pcSecureWires {
            lambda: bits.iter().map(|bit| bit & 1).collect(),
            wire_bundle: vec![AShareBundle::default(); bits.len()],
            label0: Vec::new(),
            eval_label: Vec::new(),
        };
        match self.party {
            Role::Alice => {
                wires.label0 = bits
                    .iter()
                    .map(|bit| {
                        if (bit & 1) == 0 {
                            Block::zero()
                        } else {
                            self.delta
                        }
                    })
                    .collect();
            }
            Role::Bob => {
                wires.eval_label = vec![Block::zero(); bits.len()];
            }
        }
        wires
    }

    pub async fn process_inputs<S: TranscriptIo>(
        &mut self,
        streams: &mut Ag2pcStreams<S>,
        owners: &[Role],
        bits_per_owner: &[Vec<u8>],
    ) -> Result<Vec<Ag2pcSecureWires>> {
        self.process_input_calls += 1;
        if owners.len() != bits_per_owner.len() {
            return Err(CompatError::BadAg2pcInputShape);
        }
        let mut offsets = Vec::with_capacity(owners.len());
        let mut n_total = 0usize;
        for bits in bits_per_owner {
            offsets.push(n_total);
            n_total = n_total
                .checked_add(bits.len())
                .ok_or(CompatError::LengthOverflow("AG2PC process_inputs"))?;
        }
        if n_total == 0 {
            return Ok(vec![Ag2pcSecureWires::default(); owners.len()]);
        }

        let mut sw = Ag2pcSecureWires {
            lambda: vec![0u8; n_total],
            wire_bundle: self.triple_pool.draw(streams, n_total).await?,
            label0: Vec::new(),
            eval_label: Vec::new(),
        };
        if self.party == Role::Alice {
            sw.label0 = self.prg.random_block(n_total);
        } else {
            sw.eval_label = vec![Block::zero(); n_total];
        }

        let mut owner_of_wire = Vec::with_capacity(n_total);
        let mut own_x_bits = vec![0u8; n_total];
        for (owner_index, owner) in owners.iter().enumerate() {
            let offset = offsets[owner_index];
            let bits = &bits_per_owner[owner_index];
            for (i, bit) in bits.iter().enumerate() {
                let idx = offset + i;
                owner_of_wire.push(*owner);
                if *owner == self.party {
                    own_x_bits[idx] = bit & 1;
                }
            }
        }

        let local_open = reveal_local_share(&sw.wire_bundle);

        let mut own_x_packed = Vec::new();
        let mut peer_idx_list = Vec::new();
        for (i, owner) in owner_of_wire.iter().enumerate() {
            if *owner == self.party {
                own_x_packed.push(own_x_bits[i]);
            } else {
                peer_idx_list.push(i);
            }
        }
        let (peer_share, d_peer, peer_x_packed) = self
            .exchange_input_open(
                streams,
                &local_open.share_bits,
                &local_open.mac_digest,
                &own_x_packed,
                n_total,
                peer_idx_list.len(),
            )
            .await?;

        sw.lambda = finalize_input_open(
            &sw.wire_bundle,
            &own_x_bits,
            &peer_idx_list,
            &peer_share,
            d_peer,
            &peer_x_packed,
            self.delta,
        )
        .map_err(map_input_open_error)?;

        if self.party == Role::Alice {
            let labels: Vec<Block> = sw
                .label0
                .iter()
                .zip(&sw.lambda)
                .map(|(label0, lambda)| label0.xor(select_block(*lambda).and(self.delta)))
                .collect();
            streams.main.send_block(&labels).await?;
            streams.main.flush().await?;
        } else {
            sw.eval_label = streams.main.recv_block(n_total).await?;
        }

        let mut out = Vec::with_capacity(owners.len());
        for (owner_index, bits) in bits_per_owner.iter().enumerate() {
            let start = offsets[owner_index];
            out.push(sw.slice(start, start + bits.len())?);
        }
        Ok(out)
    }

    pub async fn decode<S: TranscriptIo>(
        &mut self,
        streams: &mut Ag2pcStreams<S>,
        wires: &Ag2pcSecureWires,
        recipient: Ag2pcRevealRecipient,
    ) -> Result<Vec<u8>> {
        self.check_reveal_wires(wires)?;
        match recipient {
            Ag2pcRevealRecipient::Public => {
                let local = self.decode_to_party(streams, wires, Role::Bob).await?;
                if self.party == Role::Bob {
                    streams.main.send_data(&local).await?;
                    streams.main.flush().await?;
                    Ok(local)
                } else {
                    Ok(streams
                        .main
                        .recv_data(wires.len())
                        .await?
                        .into_iter()
                        .map(|bit| bit & 1)
                        .collect())
                }
            }
            Ag2pcRevealRecipient::Party(role) => self.decode_to_party(streams, wires, role).await,
        }
    }

    async fn decode_to_party<S: TranscriptIo>(
        &mut self,
        streams: &mut Ag2pcStreams<S>,
        wires: &Ag2pcSecureWires,
        role: Role,
    ) -> Result<Vec<u8>> {
        let n = wires.len();
        let local = reveal_local_share(&wires.wire_bundle);
        if self.party != role {
            streams.main.send_data(&local.share_bits).await?;
            streams.main.send_data(&local.mac_digest).await?;
            streams.main.flush().await?;
            Ok(Vec::new())
        } else {
            let peer_share = streams.main.recv_data(n).await?;
            let peer_digest: [u8; HASH_DIGEST_BYTES] = streams
                .main
                .recv_data(HASH_DIGEST_BYTES)
                .await?
                .try_into()
                .expect("digest length");
            reveal_recipient_bits(
                &wires.lambda,
                &wires.wire_bundle,
                &peer_share,
                peer_digest,
                self.delta,
            )
            .map_err(map_reveal_error)
        }
    }

    async fn exchange_input_open<S: TranscriptIo>(
        &mut self,
        streams: &mut Ag2pcStreams<S>,
        share_msg: &[u8],
        d_me: &[u8; HASH_DIGEST_BYTES],
        own_x_packed: &[u8],
        n_total: usize,
        peer_x_len: usize,
    ) -> Result<(Vec<u8>, [u8; HASH_DIGEST_BYTES], Vec<u8>)> {
        match self.party {
            Role::Alice => {
                let ((), received) = tokio::try_join!(
                    ag2pc_send_input_open(&mut streams.main, share_msg, d_me, own_x_packed),
                    ag2pc_recv_input_open(&mut streams.sibling, n_total, peer_x_len)
                )?;
                Ok(received)
            }
            Role::Bob => {
                let ((), received) = tokio::try_join!(
                    ag2pc_send_input_open(&mut streams.sibling, share_msg, d_me, own_x_packed),
                    ag2pc_recv_input_open(&mut streams.main, n_total, peer_x_len)
                )?;
                Ok(received)
            }
        }
    }

    fn check_secure_wires(&self, wires: &Ag2pcSecureWires) -> Result<()> {
        let n = wires.len();
        if wires.wire_bundle.len() != n {
            return Err(CompatError::BadAg2pcInputShape);
        }
        match self.party {
            Role::Alice if wires.label0.len() != n => Err(CompatError::BadAg2pcInputShape),
            Role::Bob if wires.eval_label.len() != n => Err(CompatError::BadAg2pcInputShape),
            _ => Ok(()),
        }
    }

    fn check_reveal_wires(&self, wires: &Ag2pcSecureWires) -> Result<()> {
        if wires.wire_bundle.len() != wires.len() {
            return Err(CompatError::BadAg2pcInputShape);
        }
        Ok(())
    }
}

async fn ag2pc_send_input_open<S: ByteIo>(
    stream: &mut S,
    share_msg: &[u8],
    digest: &[u8; HASH_DIGEST_BYTES],
    own_x_packed: &[u8],
) -> Result<()> {
    stream.send_data(share_msg).await?;
    stream.send_data(digest).await?;
    if !own_x_packed.is_empty() {
        stream.send_data(own_x_packed).await?;
    }
    stream.flush().await?;
    Ok(())
}

fn map_reveal_error(error: RevealError) -> CompatError {
    match error {
        RevealError::MacDigestMismatch => CompatError::FeqMismatch,
        RevealError::BadWireShape { .. } | RevealError::PeerShareLength { .. } => {
            CompatError::BadAg2pcInputShape
        }
    }
}

fn map_input_open_error(error: InputOpenError) -> CompatError {
    match error {
        InputOpenError::MacDigestMismatch => CompatError::FeqMismatch,
        InputOpenError::OwnInputLength { .. }
        | InputOpenError::PeerShareLength { .. }
        | InputOpenError::PeerInputLength { .. }
        | InputOpenError::PeerInputIndex { .. } => CompatError::BadAg2pcInputShape,
    }
}

async fn ag2pc_recv_input_open<S: ByteIo>(
    stream: &mut S,
    n_total: usize,
    peer_x_len: usize,
) -> Result<(Vec<u8>, [u8; HASH_DIGEST_BYTES], Vec<u8>)> {
    let peer_share = stream.recv_data(n_total).await?;
    let d_peer = stream
        .recv_data(HASH_DIGEST_BYTES)
        .await?
        .try_into()
        .expect("digest length");
    let peer_x = if peer_x_len == 0 {
        Vec::new()
    } else {
        stream.recv_data(peer_x_len).await?
    };
    Ok((peer_share, d_peer, peer_x))
}
