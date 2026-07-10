#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ag2pcProgram {
    num_inputs: usize,
    num_wires: usize,
    outputs: Vec<u32>,
    gates: Vec<Ag2pcProgramGate>,
}

const AG2PC_GATE_TYPE_SHIFT: u32 = 30;
const AG2PC_GATE_WIRE_MASK: u32 = (1 << AG2PC_GATE_TYPE_SHIFT) - 1;
const AG2PC_GATE_WIRE_LIMIT: usize = 1 << AG2PC_GATE_TYPE_SHIFT;

// Wire indices are stored as u32, with the 2-bit gate type packed into the high
// bits of in1_and_typ. Gate outputs are implicit: output(gate_index) is always
// num_inputs + gate_index. Real circuits have far fewer than 2^30 wires, so this
// trims each gate record to 8 bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Ag2pcProgramGate {
    in0: u32,
    in1_and_typ: u32,
}

impl Ag2pcProgramGate {
    fn new(typ: Ag2pcGateType, in0: u32, in1: u32) -> Self {
        debug_assert!(in1 <= AG2PC_GATE_WIRE_MASK);
        Self {
            in0,
            in1_and_typ: in1 | (typ.code() << AG2PC_GATE_TYPE_SHIFT),
        }
    }

    #[inline]
    fn typ(&self) -> Ag2pcGateType {
        Ag2pcGateType::from_code(self.in1_and_typ >> AG2PC_GATE_TYPE_SHIFT)
    }

    #[inline]
    fn in0(&self) -> usize {
        self.in0 as usize
    }
    #[inline]
    fn in1(&self) -> usize {
        (self.in1_and_typ & AG2PC_GATE_WIRE_MASK) as usize
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Ag2pcGateType {
    And,
    Xor,
    Inv,
}

impl Ag2pcGateType {
    fn code(self) -> u32 {
        match self {
            Self::And => 0,
            Self::Xor => 1,
            Self::Inv => 2,
        }
    }

    fn from_code(code: u32) -> Self {
        match code {
            0 => Self::And,
            1 => Self::Xor,
            2 => Self::Inv,
            _ => unreachable!("gate type is packed into two bits"),
        }
    }
}

impl Ag2pcProgram {
    pub fn from_circuit(circuit: &Circuit) -> Result<Self> {
        let num_wire = checked_nonnegative("num_wire", circuit.num_wire)?;
        let n1 = checked_nonnegative("n1", circuit.n1)?;
        let n2 = checked_nonnegative("n2", circuit.n2)?;
        let n3 = checked_nonnegative("n3", circuit.n3)?;
        if num_wire == 0 || n1 + n2 > num_wire || n3 > num_wire || num_wire >= AG2PC_GATE_WIRE_LIMIT
        {
            return Err(CompatError::BadAg2pcProgram(
                "inconsistent circuit header".to_owned(),
            ));
        }
        let num_inputs = n1 + n2;
        if num_wire == num_inputs + circuit.gates.len()
            && circuit
                .gates
                .iter()
                .enumerate()
                .all(|(i, gate)| gate.out >= 0 && gate.out as usize == num_inputs + i)
        {
            return Self::from_ordered_circuit(circuit, num_inputs, n3);
        }
        // remap[old wire] -> new topological index as u32 (UNMAPPED = u32::MAX):
        // 4 bytes/wire instead of 16 for a Vec<Option<usize>> scratch.
        const UNMAPPED: u32 = u32::MAX;
        let mut remap = vec![UNMAPPED; num_wire];
        for (wire, slot) in remap.iter_mut().take(num_inputs).enumerate() {
            *slot = wire as u32;
        }
        for (i, gate) in circuit.gates.iter().enumerate() {
            let out = checked_wire("out", gate.out, num_wire)?;
            remap[out] = (num_inputs + i) as u32;
        }
        let resolve = |old: usize| -> Result<u32> {
            let v = remap[old];
            if v == UNMAPPED {
                Err(CompatError::BadAg2pcProgram(
                    "wire is not defined".to_owned(),
                ))
            } else {
                Ok(v)
            }
        };

        let mut gates = Vec::with_capacity(circuit.gates.len());
        for gate in &circuit.gates {
            let typ = match gate.typ {
                GateType::And => Ag2pcGateType::And,
                GateType::Xor => Ag2pcGateType::Xor,
                GateType::Inv => Ag2pcGateType::Inv,
            };
            let in0_old = checked_wire("in0", gate.in0, num_wire)?;
            let in0 = resolve(in0_old)?;
            let in1 = if typ == Ag2pcGateType::Inv {
                0
            } else {
                let in1_old = checked_wire("in1", gate.in1, num_wire)?;
                resolve(in1_old)?
            };
            gates.push(Ag2pcProgramGate::new(typ, in0, in1));
        }

        let mut outputs = Vec::with_capacity(n3);
        for i in 0..n3 {
            let old = num_wire - n3 + i;
            outputs.push(resolve(old)?);
        }

        Ok(Self {
            num_inputs,
            num_wires: num_inputs + gates.len(),
            outputs,
            gates,
        })
    }

    fn from_ordered_circuit(circuit: &Circuit, num_inputs: usize, n3: usize) -> Result<Self> {
        let mut gates = Vec::with_capacity(circuit.gates.len());
        for (i, gate) in circuit.gates.iter().enumerate() {
            let max_wire = num_inputs + i;
            let typ = match gate.typ {
                GateType::And => Ag2pcGateType::And,
                GateType::Xor => Ag2pcGateType::Xor,
                GateType::Inv => Ag2pcGateType::Inv,
            };
            let in0 = checked_wire("in0", gate.in0, max_wire)?;
            let in1 = if typ == Ag2pcGateType::Inv {
                0
            } else {
                checked_wire("in1", gate.in1, max_wire)?
            };
            gates.push(Ag2pcProgramGate::new(typ, in0 as u32, in1 as u32));
        }
        let num_wires = num_inputs + gates.len();
        let output_start = num_wires - n3;
        let outputs = (output_start..num_wires).map(|wire| wire as u32).collect();
        Ok(Self {
            num_inputs,
            num_wires,
            outputs,
            gates,
        })
    }

    pub fn chunk_from_sha(sha: &Circuit, chain_bits: &[usize], first: bool) -> Result<Self> {
        validate_sha_gadget("BuildChunkProgram", sha)?;
        for &bit in chain_bits {
            if bit >= INDEX_BITS as usize {
                return Err(CompatError::BadAg2pcProgram(
                    "BuildChunkProgram: chain bit exceeds 48 bits".to_owned(),
                ));
            }
        }

        let gate_capacity = 2
            + if first { VALUE_BITS } else { 0 }
            + chain_bits.len() * (sha.gates.len() + 1)
            + VALUE_BITS;
        let mut b = Ag2pcProgramBuilder::with_capacity(
            if first { 2 * VALUE_BITS } else { VALUE_BITS },
            gate_capacity,
        );
        let c0 = b.xor_w(0, 0)?;
        let c1 = b.inv_w(c0)?;
        let pad = ag2pc_padding_bits();

        let mut p = Vec::with_capacity(VALUE_BITS);
        if first {
            for i in 0..VALUE_BITS {
                p.push(b.xor_w(i as u32, (VALUE_BITS + i) as u32)?);
            }
        } else {
            p.extend((0..VALUE_BITS).map(|wire| wire as u32));
        }

        for &bit in chain_bits {
            let idx = ag2pc_flip_bit_index(bit);
            p[idx] = b.inv_w(p[idx])?;
            let mut block = vec![0u32; 512];
            block[..VALUE_BITS].copy_from_slice(&p);
            for i in 0..VALUE_BITS {
                block[VALUE_BITS + i] = if pad[i] != 0 { c1 } else { c0 };
            }
            p = b.apply_gadget(sha, &block)?;
        }

        for wire in p.iter_mut().take(VALUE_BITS) {
            *wire = b.xor_w(*wire, c0)?;
        }
        b.finish(VALUE_BITS)
    }

    pub fn tile_from_sha(sha: &Circuit, bit_offset: usize, tile_height: usize) -> Result<Self> {
        if tile_height < 1 || tile_height > INDEX_BITS as usize {
            return Err(CompatError::BadAg2pcProgram(
                "BuildTileProgram: invalid tile height".to_owned(),
            ));
        }
        if bit_offset + tile_height > INDEX_BITS as usize {
            return Err(CompatError::BadAg2pcProgram(
                "BuildTileProgram: bit window out of range".to_owned(),
            ));
        }
        validate_sha_gadget("BuildTileProgram", sha)?;

        let leaves = 1usize << tile_height;
        let gate_capacity = 2 + (leaves - 1) * (sha.gates.len() + 1) + leaves * VALUE_BITS;
        let mut b = Ag2pcProgramBuilder::with_capacity(VALUE_BITS, gate_capacity);
        let c0 = b.xor_w(0, 0)?;
        let c1 = b.inv_w(c0)?;
        let pad = ag2pc_padding_bits();

        let mut node = vec![Vec::new(); leaves];
        node[0] = (0..VALUE_BITS).map(|wire| wire as u32).collect();

        for depth in 1..=tile_height {
            for suffix in 1..leaves {
                if suffix.count_ones() as usize != depth {
                    continue;
                }
                let bit = bit_offset + suffix.trailing_zeros() as usize;
                let parent = suffix & (suffix - 1);
                let mut p = node[parent].clone();
                let idx = ag2pc_flip_bit_index(bit);
                p[idx] = b.inv_w(p[idx])?;

                let mut block = vec![0u32; 512];
                block[..VALUE_BITS].copy_from_slice(&p);
                for i in 0..VALUE_BITS {
                    block[VALUE_BITS + i] = if pad[i] != 0 { c1 } else { c0 };
                }
                node[suffix] = b.apply_gadget(sha, &block)?;
            }
        }

        for leaf in node.iter().take(leaves) {
            for &wire in leaf.iter().take(VALUE_BITS) {
                let _ = b.xor_w(wire, c0)?;
            }
        }

        b.finish(VALUE_BITS * leaves)
    }

    pub fn num_inputs(&self) -> usize {
        self.num_inputs
    }

    pub fn output_len(&self) -> usize {
        self.outputs.len()
    }

    pub fn num_ands(&self) -> usize {
        self.gates
            .iter()
            .filter(|gate| gate.typ() == Ag2pcGateType::And)
            .count()
    }

    fn gate_out(&self, gate_index: usize) -> usize {
        self.num_inputs + gate_index
    }
}

struct Ag2pcProgramBuilder {
    num_inputs: usize,
    gates: Vec<Ag2pcProgramGate>,
}

impl Ag2pcProgramBuilder {
    fn with_capacity(num_inputs: usize, gate_capacity: usize) -> Self {
        Self {
            num_inputs,
            gates: Vec::with_capacity(gate_capacity),
        }
    }

    fn and_w(&mut self, in0: u32, in1: u32) -> Result<u32> {
        self.push_gate(Ag2pcGateType::And, in0, in1)
    }

    fn xor_w(&mut self, in0: u32, in1: u32) -> Result<u32> {
        self.push_gate(Ag2pcGateType::Xor, in0, in1)
    }

    fn inv_w(&mut self, in0: u32) -> Result<u32> {
        self.push_gate(Ag2pcGateType::Inv, in0, 0)
    }

    fn push_gate(&mut self, typ: Ag2pcGateType, in0: u32, in1: u32) -> Result<u32> {
        let out = self.num_inputs + self.gates.len();
        if out >= AG2PC_GATE_WIRE_LIMIT {
            return Err(CompatError::BadAg2pcProgram(
                "AG2PC direct program is too large".to_owned(),
            ));
        }
        self.gates.push(Ag2pcProgramGate::new(typ, in0, in1));
        Ok(out as u32)
    }

    fn apply_gadget(&mut self, gadget: &Circuit, inputs: &[u32]) -> Result<Vec<u32>> {
        let gin = checked_nonnegative("gadget inputs", gadget.n1 + gadget.n2)?;
        let num_wire = checked_nonnegative("gadget num_wire", gadget.num_wire)?;
        let n3 = checked_nonnegative("gadget n3", gadget.n3)?;
        if inputs.len() != gin || n3 > num_wire {
            return Err(CompatError::BadAg2pcProgram(
                "ApplyAg2pcGadget: wrong gadget shape".to_owned(),
            ));
        }

        const UNMAPPED: u32 = u32::MAX;
        let mut map = vec![UNMAPPED; num_wire];
        map[..gin].copy_from_slice(inputs);

        for gate in &gadget.gates {
            let typ = match gate.typ {
                GateType::And => Ag2pcGateType::And,
                GateType::Xor => Ag2pcGateType::Xor,
                GateType::Inv => Ag2pcGateType::Inv,
            };
            let in0 = resolve_direct_wire(&map, gate.in0)?;
            let in1 = if typ == Ag2pcGateType::Inv {
                0
            } else {
                resolve_direct_wire(&map, gate.in1)?
            };
            let out = match typ {
                Ag2pcGateType::And => self.and_w(in0, in1)?,
                Ag2pcGateType::Xor => self.xor_w(in0, in1)?,
                Ag2pcGateType::Inv => self.inv_w(in0)?,
            };
            let out_wire = checked_wire("gadget out", gate.out, num_wire)?;
            map[out_wire] = out;
        }

        let start = num_wire - n3;
        if map[start..start + n3].contains(&UNMAPPED) {
            return Err(CompatError::BadAg2pcProgram(
                "ApplyAg2pcGadget: output wire is not defined".to_owned(),
            ));
        }
        Ok(map[start..start + n3].to_vec())
    }

    fn finish(self, output_len: usize) -> Result<Ag2pcProgram> {
        if output_len > self.gates.len() + self.num_inputs {
            return Err(CompatError::BadAg2pcProgram(
                "AG2PC direct output length exceeds wire count".to_owned(),
            ));
        }
        let num_wires = self.num_inputs + self.gates.len();
        let output_start = num_wires - output_len;
        let outputs = (output_start..num_wires).map(|wire| wire as u32).collect();
        Ok(Ag2pcProgram {
            num_inputs: self.num_inputs,
            num_wires,
            outputs,
            gates: self.gates,
        })
    }
}

fn resolve_direct_wire(map: &[u32], wire: i32) -> Result<u32> {
    let wire = checked_wire("gadget wire", wire, map.len())?;
    let resolved = map[wire];
    if resolved == u32::MAX {
        Err(CompatError::BadAg2pcProgram(
            "ApplyAg2pcGadget: input wire is not defined".to_owned(),
        ))
    } else {
        Ok(resolved)
    }
}

fn validate_sha_gadget(name: &'static str, sha: &Circuit) -> Result<()> {
    if sha.n1 + sha.n2 != 512 || sha.n3 != VALUE_BITS as i32 {
        return Err(CompatError::BadAg2pcProgram(format!(
            "{name}: gadget is not 512->256"
        )));
    }
    Ok(())
}

fn ag2pc_padding_bits() -> [u8; VALUE_BITS] {
    let mut pad = [0u8; 32];
    pad[0] = 0x80;
    pad[30] = 0x01;
    let mut bits = [0u8; VALUE_BITS];
    for j in 0..32 {
        for k in 0..8 {
            bits[8 * j + k] = (pad[j] >> (7 - k)) & 1;
        }
    }
    bits
}

fn ag2pc_msb_bit_index(byte: usize, lsb: usize) -> usize {
    8 * byte + (7 - lsb)
}

fn ag2pc_flip_bit_index(bit: usize) -> usize {
    ag2pc_msb_bit_index(bit / 8, bit % 8)
}
