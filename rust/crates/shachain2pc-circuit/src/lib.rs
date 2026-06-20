use sha2::{Digest, Sha256};
use shachain2pc_types::{Index48, Value32, INDEX_BITS, MAX_INDEX, VALUE_BITS};
use std::fmt;
use std::fs;
use std::path::Path;

pub const DEFAULT_SHA256_COMPRESS_PATH: &str =
    ".deps/emp/include/emp-tool/circuits/files/bristol_format/sha-256.txt";
pub const CACHE_TILE_HEIGHT: usize = 4;
pub const CACHE_TILE_LEAVES: usize = 1 << CACHE_TILE_HEIGHT;
pub const CACHE_TILE_BITS: usize = VALUE_BITS * CACHE_TILE_LEAVES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GateType {
    And,
    Xor,
    Inv,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Gate {
    pub typ: GateType,
    pub in0: i32,
    pub in1: i32,
    pub out: i32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Circuit {
    pub num_wire: i32,
    pub n1: i32,
    pub n2: i32,
    pub n3: i32,
    pub gates: Vec<Gate>,
}

impl Circuit {
    pub fn num_gate(&self) -> i32 {
        self.gates.len() as i32
    }

    pub fn count_type(&self, typ: GateType) -> usize {
        self.gates.iter().filter(|g| g.typ == typ).count()
    }
}

#[derive(Debug)]
pub enum CircuitError {
    Io(std::io::Error),
    Parse(String),
    Shape(String),
    Index(shachain2pc_types::ParseError),
}

impl fmt::Display for CircuitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Parse(e) | Self::Shape(e) => f.write_str(e),
            Self::Index(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for CircuitError {}

impl From<std::io::Error> for CircuitError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<shachain2pc_types::ParseError> for CircuitError {
    fn from(value: shachain2pc_types::ParseError) -> Self {
        Self::Index(value)
    }
}

pub fn load_bristol(path: impl AsRef<Path>) -> Result<Circuit, CircuitError> {
    let path = path.as_ref();
    let text = fs::read_to_string(path)?;
    let mut it = text.split_whitespace();
    let num_gate: i32 = next_parse(&mut it, "num_gate")?;
    let num_wire: i32 = next_parse(&mut it, "num_wire")?;
    let n1: i32 = next_parse(&mut it, "n1")?;
    let n2: i32 = next_parse(&mut it, "n2")?;
    let n3: i32 = next_parse(&mut it, "n3")?;

    if num_gate < 0
        || num_wire <= 0
        || n1 < 0
        || n2 < 0
        || n3 < 0
        || n1 + n2 > num_wire
        || n3 > num_wire
    {
        return Err(CircuitError::Parse(format!(
            "LoadBristol: inconsistent header in {}",
            path.display()
        )));
    }

    let mut gates = Vec::with_capacity(num_gate as usize);
    for _ in 0..num_gate {
        let n_in: i32 = next_parse(&mut it, "gate n_in")?;
        let n_out: i32 = next_parse(&mut it, "gate n_out")?;
        if n_out != 1 {
            return Err(CircuitError::Parse(format!(
                "LoadBristol: bad gate arity in {}",
                path.display()
            )));
        }

        let gate = match n_in {
            2 => {
                let in0: i32 = next_parse(&mut it, "in0")?;
                let in1: i32 = next_parse(&mut it, "in1")?;
                let out: i32 = next_parse(&mut it, "out")?;
                let op = next_token(&mut it, "op")?;
                let typ = match op.as_bytes().first().copied() {
                    Some(b'A') => GateType::And,
                    Some(b'X') => GateType::Xor,
                    _ => {
                        return Err(CircuitError::Parse(format!(
                            "LoadBristol: unknown 2-input op in {}",
                            path.display()
                        )))
                    }
                };
                Gate { typ, in0, in1, out }
            }
            1 => {
                let in0: i32 = next_parse(&mut it, "in0")?;
                let out: i32 = next_parse(&mut it, "out")?;
                let _op = next_token(&mut it, "op")?;
                Gate {
                    typ: GateType::Inv,
                    in0,
                    in1: -1,
                    out,
                }
            }
            _ => {
                return Err(CircuitError::Parse(format!(
                    "LoadBristol: unexpected gate fan-in in {}",
                    path.display()
                )))
            }
        };

        let in_range = |w: i32| w >= 0 && w < num_wire;
        if !in_range(gate.in0)
            || !in_range(gate.out)
            || (gate.typ != GateType::Inv && !in_range(gate.in1))
        {
            return Err(CircuitError::Parse(format!(
                "LoadBristol: gate wire index out of range in {}",
                path.display()
            )));
        }
        gates.push(gate);
    }

    Ok(Circuit {
        num_wire,
        n1,
        n2,
        n3,
        gates,
    })
}

fn next_token<'a>(
    it: &mut impl Iterator<Item = &'a str>,
    field: &str,
) -> Result<&'a str, CircuitError> {
    it.next()
        .ok_or_else(|| CircuitError::Parse(format!("LoadBristol: missing {field}")))
}

fn next_parse<'a, T: std::str::FromStr>(
    it: &mut impl Iterator<Item = &'a str>,
    field: &str,
) -> Result<T, CircuitError> {
    next_token(it, field)?
        .parse()
        .map_err(|_| CircuitError::Parse(format!("LoadBristol: bad {field}")))
}

pub fn eval_bristol(c: &Circuit, in_bits: &[u8]) -> Result<Vec<u8>, CircuitError> {
    if in_bits.len() != (c.n1 + c.n2) as usize {
        return Err(CircuitError::Shape("EvalBristol: wrong input width".into()));
    }
    let mut wires = vec![0u8; c.num_wire as usize];
    for (i, b) in in_bits.iter().enumerate() {
        wires[i] = b & 1;
    }
    for g in &c.gates {
        let out = g.out as usize;
        match g.typ {
            GateType::And => wires[out] = wires[g.in0 as usize] & wires[g.in1 as usize],
            GateType::Xor => wires[out] = wires[g.in0 as usize] ^ wires[g.in1 as usize],
            GateType::Inv => wires[out] = wires[g.in0 as usize] ^ 1,
        }
    }
    let start = (c.num_wire - c.n3) as usize;
    Ok(wires[start..start + c.n3 as usize].to_vec())
}

pub fn build_circuit_for_index(index: Index48, sha: &Circuit) -> Result<Circuit, CircuitError> {
    build_derivation_circuit(sha, index.get())
}

pub fn split_chain_bits(
    index: u64,
    blocks_per_chunk: usize,
) -> Result<Vec<Vec<usize>>, CircuitError> {
    if blocks_per_chunk < 1 {
        return Err(CircuitError::Shape(
            "SplitChainBits: blocks_per_chunk must be >= 1".into(),
        ));
    }
    if index > MAX_INDEX {
        return Err(CircuitError::Index(
            shachain2pc_types::ParseError::IndexTooLarge(index),
        ));
    }

    let mut groups = vec![Vec::new()];
    for bit in (0..INDEX_BITS).rev() {
        if ((index >> bit) & 1) == 0 {
            continue;
        }
        if !groups.last().expect("group exists").is_empty()
            && groups.last().expect("group exists").len() == blocks_per_chunk
        {
            groups.push(Vec::new());
        }
        groups.last_mut().expect("group exists").push(bit as usize);
    }
    Ok(groups)
}

pub fn build_chunk_circuit(
    sha: &Circuit,
    chain_bits: &[usize],
    first: bool,
) -> Result<Circuit, CircuitError> {
    if sha.n1 + sha.n2 != 512 || sha.n3 != VALUE_BITS as i32 {
        return Err(CircuitError::Shape(
            "BuildChunkCircuit: gadget is not 512->256".into(),
        ));
    }
    for &bit in chain_bits {
        if bit >= INDEX_BITS as usize {
            return Err(CircuitError::Shape(
                "BuildChunkCircuit: chain bit exceeds 48 bits".into(),
            ));
        }
    }

    let num_inputs = if first { 2 * VALUE_BITS } else { VALUE_BITS } as i32;
    let mut b = Builder::new(num_inputs);
    let c0 = b.xor_w(0, 0);
    let c1 = b.inv_w(c0);
    let pad = padding_bits();

    let mut p = Vec::with_capacity(VALUE_BITS);
    if first {
        for i in 0..VALUE_BITS as i32 {
            p.push(b.xor_w(i, VALUE_BITS as i32 + i));
        }
    } else {
        for i in 0..VALUE_BITS as i32 {
            p.push(i);
        }
    }

    for &bit in chain_bits {
        let idx = flip_bit_index(bit);
        p[idx] = b.inv_w(p[idx]);

        let mut block = vec![0; 512];
        block[..VALUE_BITS].copy_from_slice(&p);
        for i in 0..VALUE_BITS {
            block[VALUE_BITS + i] = if pad[i] != 0 { c1 } else { c0 };
        }
        p = b.apply_gadget(sha, &block)?;
    }

    for wire in p.iter_mut().take(VALUE_BITS) {
        *wire = b.xor_w(*wire, c0);
    }

    Ok(b.finish(
        VALUE_BITS as i32,
        if first { VALUE_BITS as i32 } else { 0 },
        VALUE_BITS as i32,
    ))
}

pub fn build_tile_circuit(sha: &Circuit, tile_height: usize) -> Result<Circuit, CircuitError> {
    if tile_height < 1 || tile_height > INDEX_BITS as usize {
        return Err(CircuitError::Shape(
            "BuildTileCircuit: invalid tile height".into(),
        ));
    }
    if sha.n1 + sha.n2 != 512 || sha.n3 != VALUE_BITS as i32 {
        return Err(CircuitError::Shape(
            "BuildTileCircuit: gadget is not 512->256".into(),
        ));
    }

    let leaves = 1usize << tile_height;
    let mut b = Builder::new(VALUE_BITS as i32);
    let c0 = b.xor_w(0, 0);
    let c1 = b.inv_w(c0);
    let pad = padding_bits();

    let mut node = vec![Vec::new(); leaves];
    node[0] = (0..VALUE_BITS as i32).collect();

    for depth in 1..=tile_height {
        for suffix in 1..leaves {
            if suffix.count_ones() as usize != depth {
                continue;
            }
            let bit = suffix.trailing_zeros() as usize;
            let parent = suffix & (suffix - 1);
            let mut p = node[parent].clone();
            let idx = flip_bit_index(bit);
            p[idx] = b.inv_w(p[idx]);

            let mut block = vec![0; 512];
            block[..VALUE_BITS].copy_from_slice(&p);
            for i in 0..VALUE_BITS {
                block[VALUE_BITS + i] = if pad[i] != 0 { c1 } else { c0 };
            }
            node[suffix] = b.apply_gadget(sha, &block)?;
        }
    }

    for leaf in node.iter().take(leaves) {
        for &wire in leaf.iter().take(VALUE_BITS) {
            let _ = b.xor_w(wire, c0);
        }
    }

    Ok(b.finish(VALUE_BITS as i32, 0, (VALUE_BITS * leaves) as i32))
}

pub fn check_chunk_circuit(c: &Circuit) -> Result<(), CircuitError> {
    let ni = c.n1 + c.n2;
    if (ni != VALUE_BITS as i32 && ni != 2 * VALUE_BITS as i32) || c.n3 != VALUE_BITS as i32 {
        return Err(CircuitError::Shape(
            "shachain2pc: chunk circuit has wrong shape".into(),
        ));
    }
    Ok(())
}

pub fn check_tile_circuit(c: &Circuit, tile_height: usize) -> Result<(), CircuitError> {
    let tile_bits = VALUE_BITS
        .checked_mul(1usize << tile_height)
        .ok_or_else(|| CircuitError::Shape("shachain2pc: tile circuit too large".into()))?;
    if c.n1 != VALUE_BITS as i32 || c.n2 != 0 || c.n3 != tile_bits as i32 {
        return Err(CircuitError::Shape(
            "shachain2pc: tile circuit has wrong shape".into(),
        ));
    }
    Ok(())
}

pub fn build_derivation_circuit(sha: &Circuit, index: u64) -> Result<Circuit, CircuitError> {
    if index > MAX_INDEX {
        return Err(CircuitError::Index(
            shachain2pc_types::ParseError::IndexTooLarge(index),
        ));
    }
    if sha.n1 + sha.n2 != 512 || sha.n3 != VALUE_BITS as i32 {
        return Err(CircuitError::Shape(
            "BuildDerivationCircuit: gadget is not 512->256".into(),
        ));
    }

    let mut b = Builder::new(2 * VALUE_BITS as i32);
    let c0 = b.xor_w(0, 0);
    let c1 = b.inv_w(c0);
    let pad = padding_bits();

    let mut p = Vec::with_capacity(VALUE_BITS);
    for i in 0..VALUE_BITS as i32 {
        p.push(b.xor_w(i, VALUE_BITS as i32 + i));
    }

    for bit in (0..INDEX_BITS).rev() {
        if ((index >> bit) & 1) == 0 {
            continue;
        }
        let idx = flip_bit_index(bit as usize);
        p[idx] = b.inv_w(p[idx]);

        let mut block = vec![0; 512];
        block[..VALUE_BITS].copy_from_slice(&p);
        for i in 0..VALUE_BITS {
            block[VALUE_BITS + i] = if pad[i] != 0 { c1 } else { c0 };
        }
        p = b.apply_gadget(sha, &block)?;
    }

    for wire in p.iter_mut().take(VALUE_BITS) {
        *wire = b.xor_w(*wire, c0);
    }

    Ok(b.finish(VALUE_BITS as i32, VALUE_BITS as i32, VALUE_BITS as i32))
}

pub fn to_emp_gate_array(c: &Circuit) -> Vec<i32> {
    let mut out = Vec::with_capacity(c.gates.len() * 4);
    for g in &c.gates {
        out.push(g.in0);
        out.push(if g.typ == GateType::Inv { 0 } else { g.in1 });
        out.push(g.out);
        out.push(match g.typ {
            GateType::And => 0,
            GateType::Xor => 1,
            GateType::Inv => 2,
        });
    }
    out
}

pub fn circuit_digest(c: &Circuit, gate_arr: &[i32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for v in [c.num_gate(), c.num_wire, c.n1, c.n2, c.n3] {
        // Native-endian i32 hashing intentionally matches C++ int[] memory
        // hashing from the compatibility fixture.
        hasher.update(v.to_ne_bytes());
    }
    for v in gate_arr {
        hasher.update(v.to_ne_bytes());
    }
    hasher.finalize().into()
}

pub fn batch_digest(indices: &[u64], sha: &Circuit) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for index in indices {
        hasher.update(index.to_ne_bytes());
    }
    hasher.update(circuit_digest(sha, &to_emp_gate_array(sha)));
    hasher.finalize().into()
}

pub fn chunk_spec_digest(index: u64, blocks_per_chunk: i32, sha: &Circuit) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(index.to_ne_bytes());
    hasher.update(blocks_per_chunk.to_ne_bytes());
    hasher.update(circuit_digest(sha, &to_emp_gate_array(sha)));
    hasher.finalize().into()
}

pub fn tree_digest(indices: &[u64], trunk_chunk_blocks: i32, sha: &Circuit) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for index in indices {
        hasher.update(index.to_ne_bytes());
    }
    hasher.update(trunk_chunk_blocks.to_ne_bytes());
    hasher.update(circuit_digest(sha, &to_emp_gate_array(sha)));
    hasher.finalize().into()
}

pub fn cache_digest(
    lo: u64,
    hi: u64,
    trunk_chunk_blocks: i32,
    tile_height: i32,
    sha: &Circuit,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(lo.to_ne_bytes());
    hasher.update(hi.to_ne_bytes());
    hasher.update(trunk_chunk_blocks.to_ne_bytes());
    hasher.update(tile_height.to_ne_bytes());
    hasher.update(circuit_digest(sha, &to_emp_gate_array(sha)));
    hasher.finalize().into()
}

pub fn generate_from_seed(seed: Value32, index: Index48) -> Value32 {
    let mut p = seed.into_bytes();
    for b in (0..INDEX_BITS).rev() {
        if ((index.get() >> b) & 1) == 0 {
            continue;
        }
        p[(b / 8) as usize] ^= 1u8 << (b % 8);
        let digest = Sha256::digest(p);
        p.copy_from_slice(&digest);
    }
    Value32::new(p)
}

pub fn at_index(v: u64) -> Result<Index48, CircuitError> {
    Index48::new(MAX_INDEX - v).map_err(Into::into)
}

pub fn combine(a: Value32, b: Value32) -> Value32 {
    a.xor(b)
}

fn padding_bits() -> Vec<i32> {
    let mut pad = [0u8; 32];
    pad[0] = 0x80;
    pad[30] = 0x01;
    let mut bits = vec![0; VALUE_BITS];
    for j in 0..32 {
        for k in 0..8 {
            bits[8 * j + k] = i32::from((pad[j] >> (7 - k)) & 1);
        }
    }
    bits
}

fn msb_bit_index(byte: usize, lsb: usize) -> usize {
    8 * byte + (7 - lsb)
}

fn flip_bit_index(bit: usize) -> usize {
    msb_bit_index(bit / 8, bit % 8)
}

struct Builder {
    next: i32,
    gates: Vec<Gate>,
}

impl Builder {
    fn new(num_inputs: i32) -> Self {
        Self {
            next: num_inputs,
            gates: Vec::new(),
        }
    }

    fn alloc(&mut self) -> i32 {
        let out = self.next;
        self.next += 1;
        out
    }

    fn and(&mut self, in0: i32, in1: i32, out: i32) {
        self.gates.push(Gate {
            typ: GateType::And,
            in0,
            in1,
            out,
        });
    }

    fn xor(&mut self, in0: i32, in1: i32, out: i32) {
        self.gates.push(Gate {
            typ: GateType::Xor,
            in0,
            in1,
            out,
        });
    }

    fn inv(&mut self, in0: i32, out: i32) {
        self.gates.push(Gate {
            typ: GateType::Inv,
            in0,
            in1: -1,
            out,
        });
    }

    fn xor_w(&mut self, in0: i32, in1: i32) -> i32 {
        let out = self.alloc();
        self.xor(in0, in1, out);
        out
    }

    fn inv_w(&mut self, in0: i32) -> i32 {
        let out = self.alloc();
        self.inv(in0, out);
        out
    }

    fn apply_gadget(&mut self, gadget: &Circuit, inputs: &[i32]) -> Result<Vec<i32>, CircuitError> {
        let gin = (gadget.n1 + gadget.n2) as usize;
        if inputs.len() != gin {
            return Err(CircuitError::Shape(
                "ApplyGadget: wrong gadget input width".into(),
            ));
        }
        let mut map = vec![0; gadget.num_wire as usize];
        map[..gin].copy_from_slice(inputs);
        for slot in &mut map[gin..gadget.num_wire as usize] {
            *slot = self.alloc();
        }

        for ge in &gadget.gates {
            match ge.typ {
                GateType::And => self.and(
                    map[ge.in0 as usize],
                    map[ge.in1 as usize],
                    map[ge.out as usize],
                ),
                GateType::Xor => self.xor(
                    map[ge.in0 as usize],
                    map[ge.in1 as usize],
                    map[ge.out as usize],
                ),
                GateType::Inv => self.inv(map[ge.in0 as usize], map[ge.out as usize]),
            }
        }

        let start = (gadget.num_wire - gadget.n3) as usize;
        Ok(map[start..start + gadget.n3 as usize].to_vec())
    }

    fn finish(self, n1: i32, n2: i32, n3: i32) -> Circuit {
        Circuit {
            num_wire: self.next,
            n1,
            n2,
            n3,
            gates: self.gates,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::path::PathBuf;

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
    }

    fn fixture_records() -> Vec<Value> {
        let path = repo_root().join("compat/v1/probes/cpp-compat-probe.jsonl");
        let data = std::fs::read_to_string(path).unwrap();
        data.lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn sha_gadget() -> Circuit {
        load_bristol(repo_root().join(DEFAULT_SHA256_COMPRESS_PATH)).unwrap()
    }

    fn hex32(bytes: [u8; 32]) -> String {
        Value32::new(bytes).to_hex()
    }

    #[test]
    fn split_chain_bits_matches_cpp_ordering() {
        assert_eq!(split_chain_bits(0, 16).unwrap(), vec![Vec::<usize>::new()]);

        let groups = split_chain_bits(0xffff_ffff_ffff, 16).unwrap();
        assert_eq!(groups.len(), 3);
        assert_eq!(groups[0], (32..=47).rev().collect::<Vec<_>>());
        assert_eq!(groups[1], (16..=31).rev().collect::<Vec<_>>());
        assert_eq!(groups[2], (0..=15).rev().collect::<Vec<_>>());

        assert_eq!(
            split_chain_bits(0b101101, 2).unwrap(),
            vec![vec![5, 3], vec![2, 0]]
        );
        assert!(split_chain_bits(1, 0).is_err());
        assert!(split_chain_bits(MAX_INDEX + 1, 1).is_err());
    }

    #[test]
    fn reference_matches_cpp_fixture() {
        for record in fixture_records()
            .into_iter()
            .filter(|r| r["probe"] == "shachain_reference")
        {
            let seed = Value32::from_hex(record["inputs"]["seed"].as_str().unwrap()).unwrap();
            let index = Index48::from_hex(record["inputs"]["index_hex"].as_str().unwrap()).unwrap();
            let got = generate_from_seed(seed, index).to_hex();
            assert_eq!(got, record["outputs"]["value"].as_str().unwrap());
        }
    }

    #[test]
    fn circuit_digest_matches_cpp_fixture() {
        let sha = sha_gadget();
        for record in fixture_records()
            .into_iter()
            .filter(|r| r["probe"] == "circuit_digest")
        {
            let index = Index48::from_hex(record["inputs"]["index_hex"].as_str().unwrap()).unwrap();
            let circuit = build_circuit_for_index(index, &sha).unwrap();
            let gate_arr = to_emp_gate_array(&circuit);
            let digest = hex32(circuit_digest(&circuit, &gate_arr));

            assert_eq!(i64::from(circuit.num_gate()), record["outputs"]["num_gate"]);
            assert_eq!(i64::from(circuit.num_wire), record["outputs"]["num_wire"]);
            assert_eq!(
                circuit.count_type(GateType::And) as i64,
                record["outputs"]["and_gates"]
            );
            assert_eq!(
                gate_arr.len() as i64,
                record["outputs"]["emp_gate_array_ints"]
            );
            assert_eq!(digest, record["outputs"]["digest"].as_str().unwrap());
        }
    }

    #[test]
    fn chunked_plaintext_eval_matches_reference() {
        let sha = sha_gadget();
        let seed =
            Value32::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                .unwrap();
        let alice =
            Value32::from_hex("ffffffffffffffffffffffffffffffff00000000000000000000000000000000")
                .unwrap();
        let bob = seed.xor(alice);
        let cases = [
            ("000000000001", 1),
            ("0000000000ff", 3),
            ("ffffffffffff", 16),
        ];

        for (index_hex, blocks_per_chunk) in cases {
            let index = Index48::from_hex(index_hex).unwrap();
            let groups = split_chain_bits(index.get(), blocks_per_chunk).unwrap();
            let mut input = bob.to_bits_msb();
            input.extend_from_slice(&alice.to_bits_msb());

            let mut out_bits = Vec::new();
            for (chunk, bits) in groups.iter().enumerate() {
                let circuit = build_chunk_circuit(&sha, bits, chunk == 0).unwrap();
                check_chunk_circuit(&circuit).unwrap();
                out_bits = eval_bristol(&circuit, &input).unwrap();
                input = out_bits.clone();
            }

            let got = Value32::from_bits_msb(&out_bits).unwrap();
            assert_eq!(got, generate_from_seed(seed, index));
        }
    }

    #[test]
    fn tile_plaintext_eval_matches_low_subtree_reference() {
        let sha = sha_gadget();
        let seed =
            Value32::from_hex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
                .unwrap();
        let circuit = build_tile_circuit(&sha, CACHE_TILE_HEIGHT).unwrap();
        check_tile_circuit(&circuit, CACHE_TILE_HEIGHT).unwrap();
        let out_bits = eval_bristol(&circuit, &seed.to_bits_msb()).unwrap();
        assert_eq!(out_bits.len(), CACHE_TILE_BITS);

        for suffix in 0..CACHE_TILE_LEAVES {
            let start = suffix * VALUE_BITS;
            let got = Value32::from_bits_msb(&out_bits[start..start + VALUE_BITS]).unwrap();
            let expected = generate_from_seed(seed, Index48::new(suffix as u64).unwrap());
            assert_eq!(got, expected, "suffix {suffix}");
        }
    }

    #[test]
    fn chunk_tile_and_mode_digests_match_cpp_constants() {
        let sha = sha_gadget();
        let batch_indices = [0xffff_ffff_ffff, 0xffff_ffff_fffe, 0xffff_ffff_fffd];
        assert_eq!(
            hex32(batch_digest(&batch_indices, &sha)),
            "19102fa397acec25af910f805d89195b4e284757dda7791e42b5da2aacb19522"
        );
        assert_eq!(
            hex32(chunk_spec_digest(0xffff_ffff_ffff, 16, &sha)),
            "700937e6bc5769cde9473037cddaeae90a5f6a0652727b83041959ea3f87aae5"
        );
        assert_eq!(
            hex32(tree_digest(&batch_indices, 16, &sha)),
            "35a24a4d64c46acf1a099638e86ab4a54c4bb8856cf8f71413317c2001d4a8f9"
        );
        assert_eq!(
            hex32(cache_digest(
                0xffff_ffff_ff00,
                0xffff_ffff_ffff,
                16,
                CACHE_TILE_HEIGHT as i32,
                &sha,
            )),
            "deb4f1490561f849c8407905ad49b227751af11ceb27bd50c15d61bad4e48d5f"
        );

        let chunk = build_chunk_circuit(&sha, &[47, 46, 45], true).unwrap();
        assert_eq!(
            hex32(circuit_digest(&chunk, &to_emp_gate_array(&chunk))),
            "5104a2fd1427f01bdf0ca477649453bf836c3fb15ac26b49d4f865aa7baf140d"
        );

        let tile = build_tile_circuit(&sha, CACHE_TILE_HEIGHT).unwrap();
        assert_eq!(
            hex32(circuit_digest(&tile, &to_emp_gate_array(&tile))),
            "5dead3f8a9201513f80f3dd6e674bd043fa546754a54a2480f1a27248b6bce7c"
        );
    }

    #[test]
    fn plaintext_derivation_circuit_matches_reference() {
        let sha = sha_gadget();
        let cases = [
            Index48::from_hex("000000000001").unwrap(),
            Index48::from_hex("0000000000ff").unwrap(),
        ];
        let seed =
            Value32::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                .unwrap();
        let alice =
            Value32::from_hex("ffffffffffffffffffffffffffffffff00000000000000000000000000000000")
                .unwrap();
        let bob = seed.xor(alice);
        for index in cases {
            let circuit = build_circuit_for_index(index, &sha).unwrap();
            let mut input = bob.to_bits_msb();
            input.extend_from_slice(&alice.to_bits_msb());
            let out_bits = eval_bristol(&circuit, &input).unwrap();
            let got = Value32::from_bits_msb(&out_bits).unwrap();
            assert_eq!(got, generate_from_seed(seed, index));
        }
    }
}
