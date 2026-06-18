use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcPoint, EcPointRef, PointConversionForm};
use openssl::error::ErrorStack;
use openssl::nid::Nid;
use sha2::{Digest, Sha256};
use shachain2pc_emp_wire::Block;
use std::fmt;

pub const HASH_DIGEST_BYTES: usize = 32;
pub const POINT_BYTES: usize = 65;

#[derive(Debug)]
pub enum CompatError {
    OpenSsl(ErrorStack),
    BadPointLength(usize),
    LengthMismatch {
        receiver_scalars: usize,
        choices: usize,
        data0: usize,
        data1: usize,
    },
}

impl fmt::Display for CompatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OpenSsl(e) => write!(f, "{e}"),
            Self::BadPointLength(len) => write!(f, "expected {POINT_BYTES} point bytes, got {len}"),
            Self::LengthMismatch {
                receiver_scalars,
                choices,
                data0,
                data1,
            } => write!(
                f,
                "OTCO vector length mismatch: receiver_scalars={receiver_scalars}, choices={choices}, data0={data0}, data1={data1}"
            ),
        }
    }
}

impl std::error::Error for CompatError {}

impl From<ErrorStack> for CompatError {
    fn from(value: ErrorStack) -> Self {
        Self::OpenSsl(value)
    }
}

pub type Result<T> = std::result::Result<T, CompatError>;

pub fn hash_once(data: &[u8]) -> [u8; HASH_DIGEST_BYTES] {
    Sha256::digest(data).into()
}

pub struct Prp {
    cipher: Aes128,
}

impl Prp {
    pub fn new(key: Block) -> Self {
        Self {
            cipher: Aes128::new(GenericArray::from_slice(key.as_bytes())),
        }
    }

    pub fn zero_key() -> Self {
        Self::new(Block::zero())
    }

    pub fn permute_block(&self, blocks: &mut [Block]) {
        for block in blocks {
            let mut aes_block = GenericArray::clone_from_slice(block.as_bytes());
            self.cipher.encrypt_block(&mut aes_block);
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&aes_block);
            *block = Block::from_bytes(bytes);
        }
    }
}

pub struct Prg {
    prp: Prp,
    counter: u64,
}

impl Prg {
    pub fn new(seed: Block, id: u64) -> Self {
        let mut key = seed.into_bytes();
        for (dst, src) in key[..8].iter_mut().zip(id.to_le_bytes()) {
            *dst ^= src;
        }
        Self {
            prp: Prp::new(Block::from_bytes(key)),
            counter: 0,
        }
    }

    pub fn random_block(&mut self, nblocks: usize) -> Vec<Block> {
        let mut out = Vec::with_capacity(nblocks);
        for _ in 0..nblocks {
            out.push(Block::make(0, self.counter));
            self.counter += 1;
        }
        self.prp.permute_block(&mut out);
        out
    }

    pub fn random_data(&mut self, nbytes: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(nbytes);
        let full_blocks = nbytes / 16;
        for block in self.random_block(full_blocks) {
            out.extend_from_slice(block.as_bytes());
        }
        let rem = nbytes % 16;
        if rem != 0 {
            let extra = self.random_block(1);
            out.extend_from_slice(&extra[0].as_bytes()[..rem]);
        }
        out
    }

    pub fn random_bool_aligned(&mut self, length: usize) -> Vec<bool> {
        self.random_data(length)
            .into_iter()
            .map(|byte| (byte & 1) != 0)
            .collect()
    }
}

pub fn garble_hash_preprocess(
    a: Block,
    b: Block,
    delta: Block,
    gate_index: u64,
) -> [[Block; 2]; 4] {
    let a0 = a.sigma();
    let a1 = a.xor(delta).sigma();
    let b0 = b.sigma().sigma();
    let b1 = b.xor(delta).sigma().sigma();

    let mut rows = [
        [a0.xor(b0), a0.xor(b0)],
        [a0.xor(b1), a0.xor(b1)],
        [a1.xor(b0), a1.xor(b0)],
        [a1.xor(b1), a1.xor(b1)],
    ];
    for (row, pair) in rows.iter_mut().enumerate() {
        pair[0] = pair[0].xor(Block::make(4 * gate_index + row as u64, 0));
        pair[1] = pair[1].xor(Block::make(4 * gate_index + row as u64, 1));
    }

    let mut flat = [
        rows[0][0], rows[0][1], rows[1][0], rows[1][1], rows[2][0], rows[2][1], rows[3][0],
        rows[3][1],
    ];
    Prp::zero_key().permute_block(&mut flat);
    [
        [flat[0], flat[1]],
        [flat[2], flat[3]],
        [flat[4], flat[5]],
        [flat[6], flat[7]],
    ]
}

pub fn garble_hash_online(a: Block, b: Block, gate_index: u64, row: u64) -> [Block; 2] {
    let base = a.sigma().xor(b.sigma().sigma());
    let mut blocks = [
        base.xor(Block::make(4 * gate_index + row, 0)),
        base.xor(Block::make(4 * gate_index + row, 1)),
    ];
    Prp::zero_key().permute_block(&mut blocks);
    blocks
}

pub struct P256 {
    group: EcGroup,
}

impl P256 {
    pub fn new() -> Result<Self> {
        Ok(Self {
            group: EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?,
        })
    }

    pub fn mul_gen(&self, scalar: u64) -> Result<Vec<u8>> {
        let mut ctx = BigNumContext::new()?;
        let scalar = BigNum::from_dec_str(&scalar.to_string())?;
        let mut point = EcPoint::new(&self.group)?;
        point.mul_generator2(&self.group, &scalar, &mut ctx)?;
        point_bytes(&self.group, &point, &mut ctx)
    }

    pub fn point_add(&self, lhs: &[u8], rhs: &[u8]) -> Result<Vec<u8>> {
        let mut ctx = BigNumContext::new()?;
        let lhs = point_from_bytes(&self.group, lhs, &mut ctx)?;
        let rhs = point_from_bytes(&self.group, rhs, &mut ctx)?;
        let mut out = EcPoint::new(&self.group)?;
        out.add(&self.group, &lhs, &rhs, &mut ctx)?;
        point_bytes(&self.group, &out, &mut ctx)
    }

    pub fn point_mul(&self, point: &[u8], scalar: u64) -> Result<Vec<u8>> {
        let mut ctx = BigNumContext::new()?;
        let point = point_from_bytes(&self.group, point, &mut ctx)?;
        let scalar = BigNum::from_dec_str(&scalar.to_string())?;
        let mut out = EcPoint::new(&self.group)?;
        out.mul2(&self.group, &point, &scalar, &mut ctx)?;
        point_bytes(&self.group, &out, &mut ctx)
    }

    pub fn point_inv(&self, point: &[u8]) -> Result<Vec<u8>> {
        let mut ctx = BigNumContext::new()?;
        let mut point = point_from_bytes(&self.group, point, &mut ctx)?;
        point.invert2(&self.group, &mut ctx)?;
        point_bytes(&self.group, &point, &mut ctx)
    }

    pub fn send_pt_bytes(&self, point: &[u8]) -> Result<Vec<u8>> {
        if point.len() != POINT_BYTES {
            return Err(CompatError::BadPointLength(point.len()));
        }
        let mut out = Vec::with_capacity(4 + point.len());
        out.extend_from_slice(&(point.len() as u32).to_le_bytes());
        out.extend_from_slice(point);
        Ok(out)
    }

    pub fn kdf(&self, point: &[u8], id: u64) -> Result<Block> {
        if point.len() != POINT_BYTES {
            return Err(CompatError::BadPointLength(point.len()));
        }
        let mut data = Vec::with_capacity(point.len() + 8);
        data.extend_from_slice(point);
        data.extend_from_slice(&id.to_le_bytes());
        let digest = hash_once(&data);
        let mut block = [0u8; 16];
        block.copy_from_slice(&digest[..16]);
        Ok(Block::from_bytes(block))
    }
}

pub struct OtcoItem {
    pub i: usize,
    pub b_point: Vec<u8>,
    pub mask0_point: Vec<u8>,
    pub mask1_point: Vec<u8>,
    pub mask0: Block,
    pub mask1: Block,
    pub ciphertext0: Block,
    pub ciphertext1: Block,
    pub receiver_mask_point: Vec<u8>,
    pub receiver_mask: Block,
    pub recovered: Block,
}

pub fn fixed_otco_transcript(
    sender_scalar: u64,
    receiver_scalars: &[u64],
    choices: &[bool],
    data0: &[Block],
    data1: &[Block],
) -> Result<(Vec<u8>, Vec<OtcoItem>)> {
    if receiver_scalars.len() != choices.len()
        || receiver_scalars.len() != data0.len()
        || receiver_scalars.len() != data1.len()
    {
        return Err(CompatError::LengthMismatch {
            receiver_scalars: receiver_scalars.len(),
            choices: choices.len(),
            data0: data0.len(),
            data1: data1.len(),
        });
    }

    let group = P256::new()?;
    let a_point = group.mul_gen(sender_scalar)?;
    let aa = group.point_mul(&a_point, sender_scalar)?;
    let aa_inv = group.point_inv(&aa)?;
    let mut items = Vec::with_capacity(receiver_scalars.len());

    for i in 0..receiver_scalars.len() {
        let mut b_point = group.mul_gen(receiver_scalars[i])?;
        if choices[i] {
            b_point = group.point_add(&b_point, &a_point)?;
        }

        let mask0_point = group.point_mul(&b_point, sender_scalar)?;
        let mask1_point = group.point_add(&mask0_point, &aa_inv)?;
        let mask0 = group.kdf(&mask0_point, i as u64)?;
        let mask1 = group.kdf(&mask1_point, i as u64)?;
        let ciphertext0 = mask0.xor(data0[i]);
        let ciphertext1 = mask1.xor(data1[i]);
        let receiver_mask_point = group.point_mul(&a_point, receiver_scalars[i])?;
        let receiver_mask = group.kdf(&receiver_mask_point, i as u64)?;
        let recovered = receiver_mask.xor(if choices[i] { ciphertext1 } else { ciphertext0 });

        items.push(OtcoItem {
            i,
            b_point,
            mask0_point,
            mask1_point,
            mask0,
            mask1,
            ciphertext0,
            ciphertext1,
            receiver_mask_point,
            receiver_mask,
            recovered,
        });
    }

    Ok((a_point, items))
}

fn point_from_bytes(group: &EcGroup, bytes: &[u8], ctx: &mut BigNumContext) -> Result<EcPoint> {
    if bytes.len() != POINT_BYTES {
        return Err(CompatError::BadPointLength(bytes.len()));
    }
    Ok(EcPoint::from_bytes(group, bytes, ctx)?)
}

fn point_bytes(group: &EcGroup, point: &EcPointRef, ctx: &mut BigNumContext) -> Result<Vec<u8>> {
    Ok(point.to_bytes(group, PointConversionForm::UNCOMPRESSED, ctx)?)
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

    fn hex_decode(input: &str) -> Vec<u8> {
        assert_eq!(input.len() % 2, 0);
        input
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let hi = (pair[0] as char).to_digit(16).unwrap() as u8;
                let lo = (pair[1] as char).to_digit(16).unwrap() as u8;
                (hi << 4) | lo
            })
            .collect()
    }

    fn hex_encode(bytes: &[u8]) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push(char::from(DIGITS[usize::from(b >> 4)]));
            out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
        }
        out
    }

    fn block_from_hex(input: &str) -> Block {
        let bytes: [u8; 16] = hex_decode(input).try_into().unwrap();
        Block::from_bytes(bytes)
    }

    fn block_array_from_json(value: &Value) -> Vec<Block> {
        value
            .as_array()
            .unwrap()
            .iter()
            .map(|v| block_from_hex(v.as_str().unwrap()))
            .collect()
    }

    fn block_json(block: Block) -> String {
        hex_encode(block.as_bytes())
    }

    #[test]
    fn emp_hash_fixture_matches_cpp() {
        for record in fixture_records()
            .into_iter()
            .filter(|r| r["probe"] == "emp_hash")
        {
            let msg = hex_decode(record["inputs"]["message_hex"].as_str().unwrap());
            assert_eq!(
                hex_encode(&hash_once(&msg)),
                record["outputs"]["sha256"].as_str().unwrap()
            );
        }
    }

    #[test]
    fn emp_prp_fixture_matches_cpp() {
        for record in fixture_records()
            .into_iter()
            .filter(|r| r["probe"] == "emp_prp")
        {
            let key = block_from_hex(record["inputs"]["key"].as_str().unwrap());
            let mut blocks = block_array_from_json(&record["inputs"]["blocks"]);
            Prp::new(key).permute_block(&mut blocks);
            let got: Vec<String> = blocks.into_iter().map(block_json).collect();
            let expected: Vec<String> = record["outputs"]["permuted"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_owned())
                .collect();
            assert_eq!(got, expected);
        }
    }

    #[test]
    fn emp_prg_fixture_matches_cpp() {
        let record = fixture_records()
            .into_iter()
            .find(|r| r["probe"] == "emp_prg" && r["case"] == "seeded")
            .unwrap();
        let seed = block_from_hex(record["inputs"]["seed"].as_str().unwrap());
        let id = record["inputs"]["id"].as_u64().unwrap();
        let mut prg = Prg::new(seed, id);

        let blocks: Vec<String> = prg.random_block(5).into_iter().map(block_json).collect();
        let expected_blocks: Vec<String> = record["outputs"]["blocks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect();
        assert_eq!(blocks, expected_blocks);

        assert_eq!(
            hex_encode(&prg.random_data(23)),
            record["outputs"]["random_data_23"].as_str().unwrap()
        );

        let bools = prg.random_bool_aligned(17);
        let expected_bools: Vec<bool> = record["outputs"]["random_bool_17"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_bool().unwrap())
            .collect();
        assert_eq!(bools, expected_bools);
    }

    #[test]
    fn emp_garble_hash_fixture_matches_cpp() {
        for record in fixture_records()
            .into_iter()
            .filter(|r| r["probe"] == "emp_garble_hash")
        {
            let a = block_from_hex(record["inputs"]["a"].as_str().unwrap());
            let b = block_from_hex(record["inputs"]["b"].as_str().unwrap());
            let gate_index = record["inputs"]["gate_index"].as_u64().unwrap();
            if record["case"] == "preprocess_4x2" {
                let delta = block_from_hex(record["inputs"]["delta"].as_str().unwrap());
                let rows = garble_hash_preprocess(a, b, delta, gate_index);
                for (row, expected_row) in rows
                    .iter()
                    .zip(record["outputs"]["rows"].as_array().unwrap())
                {
                    let expected = expected_row.as_array().unwrap();
                    assert_eq!(block_json(row[0]), expected[0].as_str().unwrap());
                    assert_eq!(block_json(row[1]), expected[1].as_str().unwrap());
                }
            } else {
                let row = record["inputs"]["row"].as_u64().unwrap();
                let blocks = garble_hash_online(a, b, gate_index, row);
                let expected = record["outputs"]["blocks"].as_array().unwrap();
                assert_eq!(block_json(blocks[0]), expected[0].as_str().unwrap());
                assert_eq!(block_json(blocks[1]), expected[1].as_str().unwrap());
            }
        }
    }

    #[test]
    fn emp_point_fixture_matches_cpp() {
        let group = P256::new().unwrap();
        for record in fixture_records()
            .into_iter()
            .filter(|r| r["probe"] == "emp_point")
        {
            let scalar = record["inputs"]["scalar"].as_u64().unwrap();
            let point = group.mul_gen(scalar).unwrap();
            assert_eq!(
                hex_encode(&point),
                record["outputs"]["point"].as_str().unwrap()
            );
            assert_eq!(
                hex_encode(&group.send_pt_bytes(&point).unwrap()),
                record["outputs"]["send_pt"].as_str().unwrap()
            );
            assert_eq!(
                block_json(group.kdf(&point, 1).unwrap()),
                record["outputs"]["kdf_id_1"].as_str().unwrap()
            );
            assert_eq!(
                block_json(group.kdf(&point, 42).unwrap()),
                record["outputs"]["kdf_id_42"].as_str().unwrap()
            );
        }
    }

    #[test]
    fn emp_otco_fixed_transcript_fixture_matches_cpp() {
        let record = fixture_records()
            .into_iter()
            .find(|r| r["probe"] == "emp_otco_transcript")
            .unwrap();

        let sender_scalar = record["inputs"]["sender_scalar"].as_u64().unwrap();
        let items = record["outputs"]["items"].as_array().unwrap();
        let receiver_scalars: Vec<u64> = items
            .iter()
            .map(|item| item["receiver_scalar"].as_u64().unwrap())
            .collect();
        let choices: Vec<bool> = items
            .iter()
            .map(|item| item["choice"].as_bool().unwrap())
            .collect();
        let data0: Vec<Block> = items
            .iter()
            .map(|item| block_from_hex(item["data0"].as_str().unwrap()))
            .collect();
        let data1: Vec<Block> = items
            .iter()
            .map(|item| block_from_hex(item["data1"].as_str().unwrap()))
            .collect();

        let group = P256::new().unwrap();
        let (a_point, got_items) =
            fixed_otco_transcript(sender_scalar, &receiver_scalars, &choices, &data0, &data1)
                .unwrap();
        assert_eq!(
            hex_encode(&a_point),
            record["outputs"]["A_point"].as_str().unwrap()
        );
        assert_eq!(
            hex_encode(&group.send_pt_bytes(&a_point).unwrap()),
            record["outputs"]["A_send_pt"].as_str().unwrap()
        );

        for (got, expected) in got_items.iter().zip(items.iter()) {
            assert_eq!(got.i as u64, expected["i"].as_u64().unwrap());
            assert_eq!(
                hex_encode(&got.b_point),
                expected["B_point"].as_str().unwrap()
            );
            assert_eq!(
                hex_encode(&group.send_pt_bytes(&got.b_point).unwrap()),
                expected["B_send_pt"].as_str().unwrap()
            );
            assert_eq!(
                hex_encode(&got.mask0_point),
                expected["mask0_point"].as_str().unwrap()
            );
            assert_eq!(
                hex_encode(&got.mask1_point),
                expected["mask1_point"].as_str().unwrap()
            );
            assert_eq!(block_json(got.mask0), expected["mask0"].as_str().unwrap());
            assert_eq!(block_json(got.mask1), expected["mask1"].as_str().unwrap());
            assert_eq!(
                block_json(got.ciphertext0),
                expected["ciphertext0"].as_str().unwrap()
            );
            assert_eq!(
                block_json(got.ciphertext1),
                expected["ciphertext1"].as_str().unwrap()
            );
            assert_eq!(
                format!(
                    "{}{}",
                    block_json(got.ciphertext0),
                    block_json(got.ciphertext1)
                ),
                expected["ciphertext_pair_wire"].as_str().unwrap()
            );
            assert_eq!(
                hex_encode(&got.receiver_mask_point),
                expected["receiver_mask_point"].as_str().unwrap()
            );
            assert_eq!(
                block_json(got.receiver_mask),
                expected["receiver_mask"].as_str().unwrap()
            );
            assert_eq!(
                block_json(got.recovered),
                expected["recovered"].as_str().unwrap()
            );
        }
    }
}
