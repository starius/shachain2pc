use sha2::{Digest, Sha256};
use shachain2pc_types::{Index48, Value32, INDEX_BITS, MAX_INDEX, VALUE_BITS};
use std::fmt;
use std::fs;
use std::path::Path;

pub const DEFAULT_SHA256_COMPRESS_PATH: &str =
    ".deps/emp/include/emp-tool/circuits/files/bristol_format/sha-256.txt";

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
