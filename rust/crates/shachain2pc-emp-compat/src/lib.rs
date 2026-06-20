use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;
use openssl::bn::{BigNum, BigNumContext, BigNumRef};
use openssl::ec::{EcGroup, EcPoint, EcPointRef, PointConversionForm};
use openssl::error::ErrorStack;
use openssl::nid::Nid;
use openssl::rand::rand_bytes;
use p256::elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::{Digest, Sha256};
use shachain2pc_circuit::{Circuit, GateType};
use shachain2pc_emp_wire::{Ag2pcStreams, Block, EmpStream, WireError, BLOCK_BYTES};
use shachain2pc_types::Role;
use std::fmt;
use std::sync::OnceLock;
use zeroize::Zeroize;

pub const HASH_DIGEST_BYTES: usize = 32;
pub const POINT_BYTES: usize = 65;
#[derive(Debug)]
pub enum CompatError {
    OpenSsl(ErrorStack),
    Wire(WireError),
    BadPointLength(usize),
    BadPointWireLength(u32),
    BadOtLength {
        data0: usize,
        data1: usize,
    },
    BadCswLength(usize),
    BadAg2pcOwner(u8),
    BadAg2pcInputShape,
    BadAg2pcProgram(String),
    BadAg2pcInputLength {
        expected: usize,
        actual: usize,
    },
    BadAuthenticatedSlice {
        len: usize,
        start: usize,
        end: usize,
    },
    FeqMismatch,
    HashToCurve,
    CswProofMismatch,
    CswReceiverMismatch,
    LengthOverflow(&'static str),
    BadOtRole(&'static str),
}

impl fmt::Display for CompatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OpenSsl(e) => write!(f, "{e}"),
            Self::Wire(e) => write!(f, "{e}"),
            Self::BadPointLength(len) => write!(f, "expected {POINT_BYTES} point bytes, got {len}"),
            Self::BadPointWireLength(len) => {
                write!(f, "expected EMP point wire length {POINT_BYTES}, got {len}")
            }
            Self::BadOtLength { data0, data1 } => {
                write!(
                    f,
                    "CSW base OT data length mismatch: data0={data0}, data1={data1}"
                )
            }
            Self::BadCswLength(len) => {
                write!(f, "CSW base OT length must be at least 80, got {len}")
            }
            Self::BadAg2pcOwner(owner) => {
                write!(f, "AG2PC input owner must be 1 or 2, got {owner}")
            }
            Self::BadAg2pcInputShape => {
                write!(f, "AG2PC owner and input-bit vector lengths differ")
            }
            Self::BadAg2pcProgram(msg) => write!(f, "bad AG2PC program: {msg}"),
            Self::BadAg2pcInputLength { expected, actual } => write!(
                f,
                "AG2PC input length mismatch: expected={expected}, actual={actual}"
            ),
            Self::BadAuthenticatedSlice { len, start, end } => write!(
                f,
                "authenticated bit slice [{start}, {end}) is out of range for length {len}"
            ),
            Self::FeqMismatch => write!(f, "AG2PC equality check mismatch"),
            Self::HashToCurve => write!(f, "P-256 hash-to-curve failed"),
            Self::CswProofMismatch => write!(f, "CSW base OT proof verification failed"),
            Self::CswReceiverMismatch => {
                write!(f, "CSW base OT receiver response verification failed")
            }
            Self::LengthOverflow(name) => write!(f, "{name} length overflow"),
            Self::BadOtRole(role) => write!(f, "OT state is not initialized for {role}"),
        }
    }
}

impl std::error::Error for CompatError {}

impl From<ErrorStack> for CompatError {
    fn from(value: ErrorStack) -> Self {
        Self::OpenSsl(value)
    }
}

impl From<WireError> for CompatError {
    fn from(value: WireError) -> Self {
        Self::Wire(value)
    }
}

pub type Result<T> = std::result::Result<T, CompatError>;

pub fn hash_once(data: &[u8]) -> [u8; HASH_DIGEST_BYTES] {
    Sha256::digest(data).into()
}

pub struct EmpRo {
    domain: Vec<u8>,
    buf: Vec<u8>,
}

impl EmpRo {
    pub fn new(domain: &str, sid: Block) -> Self {
        let mut out = Self {
            domain: domain.as_bytes().to_vec(),
            buf: Vec::new(),
        };
        out.frame(1, domain.as_bytes());
        out.frame(3, sid.as_bytes());
        out
    }

    pub fn absorb_bytes(mut self, data: &[u8]) -> Self {
        self.frame(2, data);
        self
    }

    pub fn absorb_block(mut self, block: Block) -> Self {
        self.frame(3, block.as_bytes());
        self
    }

    pub fn absorb_u64(mut self, value: u64) -> Self {
        self.frame(4, &value.to_le_bytes());
        self
    }

    pub fn absorb_point(mut self, point: &[u8]) -> Self {
        self.frame(5, point);
        self
    }

    pub fn squeeze_block(&self) -> Block {
        let digest = hash_once(&self.buf);
        let mut bytes = [0u8; BLOCK_BYTES];
        bytes.copy_from_slice(&digest[..BLOCK_BYTES]);
        Block::from_bytes(bytes)
    }

    pub fn squeeze_p256_point(&self) -> Result<Vec<u8>> {
        let point =
            p256::NistP256::hash_from_bytes::<ExpandMsgXmd<Sha256>>(&[&self.buf], &[&self.domain])
                .map_err(|_| CompatError::HashToCurve)?;
        Ok(point
            .to_affine()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec())
    }

    fn frame(&mut self, typ: u32, data: &[u8]) {
        let len: u32 = data
            .len()
            .try_into()
            .expect("EMP RO frame length exceeds u32");
        self.buf.extend_from_slice(&typ.to_le_bytes());
        self.buf.extend_from_slice(&len.to_le_bytes());
        self.buf.extend_from_slice(data);
    }
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
        // Batch through AES-NI: encrypt_blocks pipelines 8 blocks wide, vs the
        // ~4-cycle latency of one-at-a-time encrypt_block. Block is
        // repr(transparent) over [u8; 16], the same layout as aes::Block.
        let aes_blocks: &mut [aes::Block] = unsafe {
            std::slice::from_raw_parts_mut(blocks.as_mut_ptr().cast::<aes::Block>(), blocks.len())
        };
        self.cipher.encrypt_blocks(aes_blocks);
    }

    pub fn permute_one(&self, block: Block) -> Block {
        let mut aes_block = GenericArray::clone_from_slice(block.as_bytes());
        self.cipher.encrypt_block(&mut aes_block);
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&aes_block);
        Block::from_bytes(bytes)
    }
}

fn zero_key_prp() -> &'static Prp {
    static ZERO_KEY_PRP: OnceLock<Prp> = OnceLock::new();
    ZERO_KEY_PRP.get_or_init(Prp::zero_key)
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
        let prp = Prp::new(Block::from_bytes(key));
        key.zeroize();
        Self { prp, counter: 0 }
    }

    pub fn random() -> Result<Self> {
        Ok(Self::new(random_block()?, 0))
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
        let mut out = vec![0u8; nbytes];
        self.fill_random_data(&mut out);
        out
    }

    pub fn fill_random_data(&mut self, out: &mut [u8]) {
        let mut chunks = out.chunks_exact_mut(BLOCK_BYTES);
        for chunk in &mut chunks {
            let block = self.next_block();
            chunk.copy_from_slice(block.as_bytes());
        }
        let rem = chunks.into_remainder();
        if !rem.is_empty() {
            let block = self.next_block();
            rem.copy_from_slice(&block.as_bytes()[..rem.len()]);
        }
    }

    fn next_block(&mut self) -> Block {
        let block = Block::make(0, self.counter);
        self.counter += 1;
        self.prp.permute_one(block)
    }

    pub fn random_bool_aligned(&mut self, length: usize) -> Vec<bool> {
        self.random_data(length)
            .into_iter()
            .map(|byte| (byte & 1) != 0)
            .collect()
    }
}

impl Drop for Prg {
    fn drop(&mut self) {
        self.counter.zeroize();
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
    zero_key_prp().permute_block(&mut flat);
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
    zero_key_prp().permute_block(&mut blocks);
    blocks
}

const CGGM_LSB_CLEAR_MASK: Block = Block::from_bytes([
    0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
]);

fn ccrh_hash(block: Block) -> Block {
    let sigma = block.sigma();
    zero_key_prp().permute_one(sigma).xor(sigma)
}

pub fn cggm_bit_reverse(mut x: u32, depth: usize) -> u32 {
    let mut out = 0;
    for _ in 0..depth {
        out = (out << 1) | (x & 1);
        x >>= 1;
    }
    out
}

fn cggm_expand_level(
    leaves: &mut [Block],
    parents: usize,
    want_right: bool,
    clear_lsb: bool,
) -> Block {
    let mut sum = Block::zero();
    for j in 0..parents {
        let parent = leaves[j];
        let mut left = ccrh_hash(parent);
        let mut right = parent.xor(left);
        if clear_lsb {
            left = left.and(CGGM_LSB_CLEAR_MASK);
            right = right.and(CGGM_LSB_CLEAR_MASK);
        }
        leaves[parents + j] = right;
        leaves[j] = left;
        sum = sum.xor(if want_right { right } else { left });
    }
    sum
}

pub fn cggm_build_sender(
    depth: usize,
    delta: Block,
    root: Block,
    clear_leaf_lsb: bool,
) -> (Vec<Block>, Vec<Block>) {
    assert!(depth >= 1);
    let q = 1usize << depth;
    let mut leaves = vec![Block::zero(); q];
    let mut k0 = vec![Block::zero(); depth];

    leaves[0] = root;
    leaves[1] = delta.xor(root);
    k0[0] = leaves[0];

    for level in 2..depth {
        let parents = 1usize << (level - 1);
        k0[level - 1] = cggm_expand_level(&mut leaves, parents, false, false);
    }
    if depth >= 2 {
        let parents = 1usize << (depth - 1);
        k0[depth - 1] = cggm_expand_level(&mut leaves, parents, false, clear_leaf_lsb);
    }
    (leaves, k0)
}

pub fn cggm_eval_receiver(
    depth: usize,
    alpha: usize,
    recv_keys: &[Block],
    clear_leaf_lsb: bool,
) -> Vec<Block> {
    assert!(depth >= 1);
    assert_eq!(recv_keys.len(), depth);
    let q = 1usize << depth;
    let mut leaves = vec![Block::zero(); q];

    let alpha_1 = (alpha >> (depth - 1)) & 1;
    let alpha_bar_1 = 1 - alpha_1;
    leaves[alpha_bar_1] = recv_keys[0];
    let mut pos = alpha_1;

    for level in 2..=depth {
        let half = 1usize << (level - 1);
        let alpha_i = (alpha >> (depth - level)) & 1;
        let alpha_bar_i = 1 - alpha_i;
        let clear = clear_leaf_lsb && level == depth;

        let sum_pre = cggm_expand_level(&mut leaves, half, alpha_bar_i != 0, clear);
        let junk = leaves[pos];
        leaves[pos] = Block::zero();
        leaves[pos + half] = Block::zero();
        let mut sibling = sum_pre.xor(junk).xor(recv_keys[level - 1]);
        if clear {
            sibling = sibling.and(CGGM_LSB_CLEAR_MASK);
        }
        leaves[pos + alpha_bar_i * half] = sibling;
        pos += alpha_i * half;
    }
    leaves
}

fn aes_dm(key: &Prp, counter: u64, tweak: Block) -> Block {
    let pt = Block::make(0, counter).xor(tweak);
    key.permute_one(pt).xor(pt)
}

fn block_to_u128(block: Block) -> u128 {
    u128::from_le_bytes(block.into_bytes())
}

fn u128_to_block(value: u128) -> Block {
    Block::from_bytes(value.to_le_bytes())
}

fn gf_mul(a: Block, b: Block) -> Block {
    let a = block_to_u128(a);
    let b = block_to_u128(b);
    let mut product = [0u64; 4];
    for i in 0..128 {
        if ((b >> i) & 1) != 0 {
            xor_shifted_u128(&mut product, a, i);
        }
    }
    gf_reduce(product)
}

fn xor_shifted_u128(dst: &mut [u64; 4], value: u128, shift: usize) {
    let lo = value as u64;
    let hi = (value >> 64) as u64;
    let word = shift / 64;
    let bits = shift % 64;
    if bits == 0 {
        dst[word] ^= lo;
        dst[word + 1] ^= hi;
    } else {
        dst[word] ^= lo << bits;
        dst[word + 1] ^= (lo >> (64 - bits)) ^ (hi << bits);
        if word + 2 < dst.len() {
            dst[word + 2] ^= hi >> (64 - bits);
        }
    }
}

fn gf_bit(words: &[u64; 4], bit: usize) -> bool {
    ((words[bit / 64] >> (bit % 64)) & 1) != 0
}

fn gf_flip(words: &mut [u64; 4], bit: usize) {
    words[bit / 64] ^= 1u64 << (bit % 64);
}

fn gf_reduce(mut product: [u64; 4]) -> Block {
    for bit in (128..256).rev() {
        if gf_bit(&product, bit) {
            gf_flip(&mut product, bit);
            let base = bit - 128;
            gf_flip(&mut product, base);
            gf_flip(&mut product, base + 1);
            gf_flip(&mut product, base + 2);
            gf_flip(&mut product, base + 7);
        }
    }
    let value = (product[0] as u128) | ((product[1] as u128) << 64);
    u128_to_block(value)
}

fn gf_inner_product(a: &[Block], b: &[Block]) -> Block {
    assert_eq!(a.len(), b.len());
    a.iter()
        .zip(b)
        .fold(Block::zero(), |acc, (lhs, rhs)| acc.xor(gf_mul(*lhs, *rhs)))
}

fn gf_pack_128(data: &[Block]) -> Block {
    assert_eq!(data.len(), 128);
    let mut product = [0u64; 4];
    for (shift, block) in data.iter().enumerate() {
        xor_shifted_u128(&mut product, block_to_u128(*block), shift);
    }
    gf_reduce(product)
}

pub fn sfvole_sender_butterfly(
    k: usize,
    leaves: &[Block],
    counter_base: u64,
    bs: usize,
    session_id: u64,
) -> (Vec<Block>, Vec<Block>) {
    assert!(k >= 2);
    assert_eq!(leaves.len(), 1usize << k);
    let q = 1usize << k;
    let key = Prp::new(Block::make(0, session_id));
    let mut u = vec![Block::zero(); bs];
    let mut v = vec![Block::zero(); k * bs];

    for j in 0..bs {
        let mut r = vec![Block::zero(); q];
        for x in 0..q {
            r[x] = aes_dm(&key, counter_base + j as u64, leaves[x]);
            u[j] = u[j].xor(r[x]);
        }
        for plane in 0..k {
            let mut acc = Block::zero();
            for (x, value) in r.iter().enumerate() {
                if ((x >> plane) & 1) != 0 {
                    acc = acc.xor(*value);
                }
            }
            v[plane * bs + j] = acc;
        }
    }
    (u, v)
}

pub fn sfvole_receiver_butterfly(
    k: usize,
    alpha: usize,
    leaves: &[Block],
    counter_base: u64,
    bs: usize,
    session_id: u64,
) -> Vec<Block> {
    assert!(k >= 2);
    assert_eq!(leaves.len(), 1usize << k);
    let q = 1usize << k;
    let key = Prp::new(Block::make(0, session_id));
    let mut w = vec![Block::zero(); k * bs];

    for j in 0..bs {
        let mut r = vec![Block::zero(); q];
        for y in 0..q {
            r[y] = aes_dm(&key, counter_base + j as u64, leaves[alpha ^ y]);
        }
        for plane in 0..k {
            let mut acc = Block::zero();
            for (y, value) in r.iter().enumerate() {
                if ((y >> plane) & 1) != 0 {
                    acc = acc.xor(*value);
                }
            }
            w[plane * bs + j] = acc;
        }
    }
    w
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
        self.mul_gen_bn(&scalar, &mut ctx)
    }

    fn random_scalar(&self) -> Result<BigNum> {
        let mut ctx = BigNumContext::new()?;
        let mut order = BigNum::new()?;
        self.group.order(&mut order, &mut ctx)?;
        let mut out = BigNum::new()?;
        order.rand_range(&mut out)?;
        Ok(out)
    }

    fn mul_gen_bn(&self, scalar: &BigNumRef, ctx: &mut BigNumContext) -> Result<Vec<u8>> {
        let mut point = EcPoint::new(&self.group)?;
        point.mul_generator2(&self.group, scalar, ctx)?;
        point_bytes(&self.group, &point, ctx)
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
        self.point_mul_bn_ref(&point, &scalar, &mut ctx)
    }

    fn point_mul_bn(&self, point: &[u8], scalar: &BigNumRef) -> Result<Vec<u8>> {
        let mut ctx = BigNumContext::new()?;
        let point = point_from_bytes(&self.group, point, &mut ctx)?;
        self.point_mul_bn_ref(&point, scalar, &mut ctx)
    }

    fn point_mul_bn_ref(
        &self,
        point: &EcPointRef,
        scalar: &BigNumRef,
        ctx: &mut BigNumContext,
    ) -> Result<Vec<u8>> {
        let mut out = EcPoint::new(&self.group)?;
        out.mul2(&self.group, point, scalar, ctx)?;
        point_bytes(&self.group, &out, ctx)
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

    pub fn hash_to_point(&self, msg: &[u8], dst: &str) -> Result<Vec<u8>> {
        let _ = &self.group;
        let point =
            p256::NistP256::hash_from_bytes::<ExpandMsgXmd<Sha256>>(&[msg], &[dst.as_bytes()])
                .map_err(|_| CompatError::HashToCurve)?;
        Ok(point
            .to_affine()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec())
    }
}

async fn send_point(stream: &mut EmpStream, point: &[u8]) -> Result<()> {
    if point.len() != POINT_BYTES {
        return Err(CompatError::BadPointLength(point.len()));
    }
    stream
        .send_data(&(point.len() as u32).to_le_bytes())
        .await?;
    stream.send_data(point).await?;
    Ok(())
}

async fn recv_point(stream: &mut EmpStream) -> Result<Vec<u8>> {
    let len_bytes = stream.recv_data(4).await?;
    let len = u32::from_le_bytes(len_bytes.try_into().expect("length prefix"));
    if len != POINT_BYTES as u32 {
        return Err(CompatError::BadPointWireLength(len));
    }
    Ok(stream.recv_data(POINT_BYTES).await?)
}

pub async fn csw_send(stream: &mut EmpStream, data0: &[Block], data1: &[Block]) -> Result<()> {
    if data0.len() != data1.len() {
        return Err(CompatError::BadOtLength {
            data0: data0.len(),
            data1: data1.len(),
        });
    }
    if data0.len() < 80 {
        return Err(CompatError::BadCswLength(data0.len()));
    }

    let group = P256::new()?;
    let sid = Block::zero();

    let seed = stream.recv_block(1).await?[0];
    let mut b_points = Vec::with_capacity(data0.len());
    for _ in 0..data0.len() {
        b_points.push(recv_point(stream).await?);
    }

    let t = EmpRo::new("emp-ot:csw-base-ot:to-curve", sid)
        .absorb_block(seed)
        .squeeze_p256_point()?;
    let r = group.random_scalar()?;
    let z = {
        let mut ctx = BigNumContext::new()?;
        group.mul_gen_bn(&r, &mut ctx)?
    };
    let t_r = group.point_mul_bn(&t, &r)?;
    let t_r_neg = group.point_inv(&t_r)?;

    let mut p0 = Vec::with_capacity(data0.len());
    let mut p1 = Vec::with_capacity(data0.len());
    let mut h0 = Vec::with_capacity(data0.len());
    for (i, b_point) in b_points.iter().enumerate() {
        let rho0 = group.point_mul_bn(b_point, &r)?;
        let rho1 = group.point_add(&rho0, &t_r_neg)?;
        let pad0 = csw_pad_block(sid, i, &rho0);
        let pad1 = csw_pad_block(sid, i, &rho1);
        h0.push(csw_short_block(sid, pad0));
        p0.push(pad0);
        p1.push(pad1);
    }

    let otans = EmpRo::new("emp-ot:csw-base-ot:agg", sid)
        .absorb_bytes(&blocks_to_bytes(&h0))
        .squeeze_block();
    let proof = csw_short_block(sid, otans);
    let mut chi = Vec::with_capacity(data0.len());
    let mut c0 = Vec::with_capacity(data0.len());
    let mut c1 = Vec::with_capacity(data0.len());
    for i in 0..data0.len() {
        chi.push(h0[i].xor(csw_short_block(sid, p1[i])));
        c0.push(p0[i].xor(data0[i]));
        c1.push(p1[i].xor(data1[i]));
    }

    send_point(stream, &z).await?;
    stream.send_block(&chi).await?;
    stream.send_block(&[proof]).await?;
    stream.send_block(&c0).await?;
    stream.send_block(&c1).await?;
    stream.flush().await?;

    let otans_prime = stream.recv_block(1).await?[0];
    if otans_prime != otans {
        return Err(CompatError::CswReceiverMismatch);
    }
    Ok(())
}

pub async fn csw_recv(stream: &mut EmpStream, choices: &[bool]) -> Result<Vec<Block>> {
    if choices.len() < 80 {
        return Err(CompatError::BadCswLength(choices.len()));
    }

    let group = P256::new()?;
    let sid = Block::zero();
    let seed = random_block()?;
    let t = EmpRo::new("emp-ot:csw-base-ot:to-curve", sid)
        .absorb_block(seed)
        .squeeze_p256_point()?;

    stream.send_block(&[seed]).await?;
    let mut alphas = Vec::with_capacity(choices.len());
    for choice in choices {
        let alpha = group.random_scalar()?;
        let b_point = {
            let mut ctx = BigNumContext::new()?;
            group.mul_gen_bn(&alpha, &mut ctx)?
        };
        let b_point = if *choice {
            group.point_add(&b_point, &t)?
        } else {
            b_point
        };
        send_point(stream, &b_point).await?;
        alphas.push(alpha);
    }
    stream.flush().await?;

    let z = recv_point(stream).await?;
    let mut p_bi = Vec::with_capacity(choices.len());
    let mut h_bi = Vec::with_capacity(choices.len());
    for (i, alpha) in alphas.iter().enumerate() {
        let z_alpha = group.point_mul_bn(&z, alpha)?;
        let pad = csw_pad_block(sid, i, &z_alpha);
        h_bi.push(csw_short_block(sid, pad));
        p_bi.push(pad);
    }

    let chi = stream.recv_block(choices.len()).await?;
    let proof = stream.recv_block(1).await?[0];
    let c0 = stream.recv_block(choices.len()).await?;
    let c1 = stream.recv_block(choices.len()).await?;

    let mut otresp = Vec::with_capacity(choices.len());
    for i in 0..choices.len() {
        otresp.push(if choices[i] {
            h_bi[i].xor(chi[i])
        } else {
            h_bi[i]
        });
    }
    let otans_prime = EmpRo::new("emp-ot:csw-base-ot:agg", sid)
        .absorb_bytes(&blocks_to_bytes(&otresp))
        .squeeze_block();
    if csw_short_block(sid, otans_prime) != proof {
        return Err(CompatError::CswProofMismatch);
    }

    let mut out = Vec::with_capacity(choices.len());
    for i in 0..choices.len() {
        out.push(p_bi[i].xor(if choices[i] { c1[i] } else { c0[i] }));
    }
    stream.send_block(&[otans_prime]).await?;
    stream.flush().await?;
    Ok(out)
}

fn csw_pad_block(sid: Block, i: usize, point: &[u8]) -> Block {
    EmpRo::new("emp-ot:csw-base-ot:pad", sid)
        .absorb_u64(i as u64)
        .absorb_point(point)
        .squeeze_block()
}

fn csw_short_block(sid: Block, block: Block) -> Block {
    EmpRo::new("emp-ot:csw-base-ot:short", sid)
        .absorb_block(block)
        .squeeze_block()
}

fn blocks_to_bytes(blocks: &[Block]) -> Vec<u8> {
    let mut out = Vec::with_capacity(blocks.len() * BLOCK_BYTES);
    for block in blocks {
        out.extend_from_slice(block.as_bytes());
    }
    out
}

const SOFTSPOKEN_K: usize = 4;
const SOFTSPOKEN_N: usize = 128 / SOFTSPOKEN_K;
const SOFTSPOKEN_Q: usize = 1 << SOFTSPOKEN_K;
const SOFTSPOKEN_CHUNK_BLOCKS: usize = 64;
const SOFTSPOKEN_CHUNK_OTS: usize = SOFTSPOKEN_CHUNK_BLOCKS * 128;
const SOFTSPOKEN_PPRF_CHECK_HIGH: u64 = 0x7050_5246_434b_5f00;

pub struct SoftSpoken4 {
    role: Role,
    malicious: bool,
    setup_done: bool,
    delta: Block,
    delta_bool: [bool; 128],
    choice_prg: Prg,
    session: u64,
    cur_send_session: u64,
    cur_recv_session: u64,
    cur_send_b0: u64,
    cur_recv_b0: u64,
    leftover: Vec<Block>,
    leftover_pos: usize,
    leftover_count: usize,
    alphas: [usize; SOFTSPOKEN_N],
    leaves_recv: Vec<Block>,
    leaves_send: Vec<Block>,
    check_q: Block,
    check_t: Block,
    check_x: Block,
}

impl SoftSpoken4 {
    pub fn new(role: Role, malicious: bool) -> Result<Self> {
        let mut delta = Block::zero();
        let mut delta_bool = [false; 128];
        if role == Role::Alice {
            delta = random_block()?;
            let mut bytes = delta.into_bytes();
            bytes[0] |= 1;
            delta = Block::from_bytes(bytes);
            delta_bool = block_to_bools(delta);
        }
        Ok(Self {
            role,
            malicious,
            setup_done: false,
            delta,
            delta_bool,
            choice_prg: Prg::random()?,
            session: 0,
            cur_send_session: 0,
            cur_recv_session: 0,
            cur_send_b0: 0,
            cur_recv_b0: 0,
            leftover: Vec::new(),
            leftover_pos: 0,
            leftover_count: 0,
            alphas: [0; SOFTSPOKEN_N],
            leaves_recv: Vec::new(),
            leaves_send: Vec::new(),
            check_q: Block::zero(),
            check_t: Block::zero(),
            check_x: Block::zero(),
        })
    }

    pub fn new_with_delta(role: Role, malicious: bool, delta: Block) -> Result<Self> {
        let mut out = Self::new(role, malicious)?;
        out.set_delta(delta)?;
        Ok(out)
    }

    pub fn set_delta(&mut self, delta: Block) -> Result<()> {
        if self.setup_done || self.role != Role::Alice {
            return Err(CompatError::BadOtRole("SoftSpoken4::set_delta"));
        }
        self.delta = delta;
        self.delta_bool = block_to_bools(delta);
        Ok(())
    }

    pub fn delta(&self) -> Block {
        self.delta
    }

    pub async fn run(&mut self, stream: &mut EmpStream, length: usize) -> Result<Vec<Block>> {
        let mut out = vec![Block::zero(); length];
        let got = self.drain_leftover(&mut out);
        if got == length {
            return Ok(out);
        }
        self.begin(stream).await?;
        let rest = self.next_n(stream, length - got).await?;
        self.end(stream).await?;
        out[got..].copy_from_slice(&rest);
        Ok(out)
    }

    pub async fn begin(&mut self, stream: &mut EmpStream) -> Result<()> {
        if self.role == Role::Alice {
            self.send_begin(stream).await
        } else {
            self.recv_begin(stream).await
        }
    }

    pub async fn end(&mut self, stream: &mut EmpStream) -> Result<()> {
        if self.role == Role::Alice {
            self.send_end(stream).await
        } else {
            self.recv_end(stream).await
        }
    }

    pub async fn next_n(&mut self, stream: &mut EmpStream, length: usize) -> Result<Vec<Block>> {
        let mut out = vec![Block::zero(); length];
        let mut got = self.drain_leftover(&mut out);
        while got + SOFTSPOKEN_CHUNK_OTS <= length {
            let chunk = self.next_chunk(stream, SOFTSPOKEN_CHUNK_BLOCKS).await?;
            out[got..got + SOFTSPOKEN_CHUNK_OTS].copy_from_slice(&chunk);
            got += SOFTSPOKEN_CHUNK_OTS;
        }
        if got < length {
            let chunk = self.next_chunk(stream, SOFTSPOKEN_CHUNK_BLOCKS).await?;
            let take = length - got;
            out[got..].copy_from_slice(&chunk[..take]);
            self.leftover = chunk;
            self.leftover_pos = take;
            self.leftover_count = SOFTSPOKEN_CHUNK_OTS - take;
        }
        Ok(out)
    }

    fn reset_leftover(&mut self) {
        self.leftover_pos = 0;
        self.leftover_count = 0;
    }

    fn drain_leftover(&mut self, out: &mut [Block]) -> usize {
        if self.leftover_count == 0 || out.is_empty() {
            return 0;
        }
        let take = out.len().min(self.leftover_count);
        let start = self.leftover_pos;
        let end = start + take;
        out[..take].copy_from_slice(&self.leftover[start..end]);
        self.leftover_pos += take;
        self.leftover_count -= take;
        take
    }

    async fn next_chunk(&mut self, stream: &mut EmpStream, bs: usize) -> Result<Vec<Block>> {
        if self.role == Role::Alice {
            self.send_chunk_pipeline(stream, bs).await
        } else {
            self.recv_chunk_pipeline(stream, bs).await
        }
    }

    async fn send_begin(&mut self, stream: &mut EmpStream) -> Result<()> {
        self.reset_leftover();
        if !self.setup_done {
            self.bootstrap_send(stream).await?;
        }
        self.cur_send_session = self.session;
        self.session += 1;
        self.cur_send_b0 = 0;
        if self.malicious {
            self.check_q = Block::zero();
        }
        Ok(())
    }

    async fn recv_begin(&mut self, stream: &mut EmpStream) -> Result<()> {
        self.reset_leftover();
        if !self.setup_done {
            self.bootstrap_recv(stream).await?;
        }
        self.cur_recv_session = self.session;
        self.session += 1;
        self.cur_recv_b0 = 0;
        if self.malicious {
            self.check_t = Block::zero();
            self.check_x = Block::zero();
        }
        Ok(())
    }

    async fn send_end(&mut self, stream: &mut EmpStream) -> Result<()> {
        if self.malicious {
            let _scratch = self.send_chunk_pipeline(stream, 1).await?;
            let x = stream.recv_block(1).await?[0];
            let t = stream.recv_block(1).await?[0];
            let lhs = self.check_q.xor(gf_mul(x, self.delta));
            if lhs != t {
                return Err(CompatError::FeqMismatch);
            }
        }
        Ok(())
    }

    async fn recv_end(&mut self, stream: &mut EmpStream) -> Result<()> {
        if self.malicious {
            let _scratch = self.recv_chunk_pipeline(stream, 1).await?;
            stream.send_block(&[self.check_x]).await?;
            stream.send_block(&[self.check_t]).await?;
        }
        stream.flush().await?;
        Ok(())
    }

    async fn bootstrap_send(&mut self, stream: &mut EmpStream) -> Result<()> {
        let mut choices = Vec::with_capacity(128);
        for i in 0..SOFTSPOKEN_N {
            let mut alpha = 0usize;
            for bit in 0..SOFTSPOKEN_K {
                if self.delta_bool[i * SOFTSPOKEN_K + bit] {
                    alpha |= 1 << bit;
                }
            }
            self.alphas[i] = alpha;
            for bit in 0..SOFTSPOKEN_K {
                choices.push(((alpha >> bit) & 1) == 0);
            }
        }
        let received = csw_recv(stream, &choices).await?;
        self.leaves_recv = vec![Block::zero(); SOFTSPOKEN_N * SOFTSPOKEN_Q];
        for i in 0..SOFTSPOKEN_N {
            let path = cggm_bit_reverse(self.alphas[i] as u32, SOFTSPOKEN_K) as usize;
            let leaves = cggm_eval_receiver(
                SOFTSPOKEN_K,
                path,
                &received[i * SOFTSPOKEN_K..(i + 1) * SOFTSPOKEN_K],
                false,
            );
            self.leaves_recv[i * SOFTSPOKEN_Q..(i + 1) * SOFTSPOKEN_Q].copy_from_slice(&leaves);
        }
        if self.malicious {
            self.pprf_check_recv(stream).await?;
            if !stream.fs_enabled() {
                stream.enable_fs(true)?;
            }
        }
        self.setup_done = true;
        Ok(())
    }

    async fn bootstrap_recv(&mut self, stream: &mut EmpStream) -> Result<()> {
        self.leaves_send = vec![Block::zero(); SOFTSPOKEN_N * SOFTSPOKEN_Q];
        let mut k0 = Vec::with_capacity(128);
        let mut k1 = Vec::with_capacity(128);
        for i in 0..SOFTSPOKEN_N {
            let pair = self.choice_prg.random_block(2);
            let (leaves, k0_i) = cggm_build_sender(SOFTSPOKEN_K, pair[0], pair[1], false);
            self.leaves_send[i * SOFTSPOKEN_Q..(i + 1) * SOFTSPOKEN_Q].copy_from_slice(&leaves);
            for key in k0_i {
                k0.push(key);
                k1.push(key.xor(pair[0]));
            }
        }
        csw_send(stream, &k0, &k1).await?;
        if self.malicious {
            self.pprf_check_send(stream).await?;
            if !stream.fs_enabled() {
                stream.enable_fs(false)?;
            }
        }
        self.setup_done = true;
        Ok(())
    }

    async fn pprf_check_send(&mut self, stream: &mut EmpStream) -> Result<()> {
        let check_key = Prp::new(Block::make(SOFTSPOKEN_PPRF_CHECK_HIGH, 0));
        let mut t_buf = vec![Block::zero(); SOFTSPOKEN_N * 2];
        let mut hash = Sha256::new();
        for i in 0..SOFTSPOKEN_N {
            let base = i * SOFTSPOKEN_Q;
            let mut tx = Block::zero();
            let mut ty = Block::zero();
            for y in 0..SOFTSPOKEN_Q {
                let exp = aes_dm_3(&check_key, self.leaves_send[base + y]);
                self.leaves_send[base + y] = exp[0];
                tx = tx.xor(exp[1]);
                ty = ty.xor(exp[2]);
                hash.update(exp[1].as_bytes());
                hash.update(exp[2].as_bytes());
            }
            t_buf[i * 2] = tx;
            t_buf[i * 2 + 1] = ty;
        }
        stream.send_block(&t_buf).await?;
        stream.send_data(&hash.finalize()).await?;
        stream.flush().await?;
        Ok(())
    }

    async fn pprf_check_recv(&mut self, stream: &mut EmpStream) -> Result<()> {
        let check_key = Prp::new(Block::make(SOFTSPOKEN_PPRF_CHECK_HIGH, 0));
        let t_buf = stream.recv_block(SOFTSPOKEN_N * 2).await?;
        let their_digest = stream.recv_data(HASH_DIGEST_BYTES).await?;
        let mut hash = Sha256::new();
        let mut s_buf = vec![Block::zero(); SOFTSPOKEN_Q * 2];
        for i in 0..SOFTSPOKEN_N {
            let base = i * SOFTSPOKEN_Q;
            let mut tx = Block::zero();
            let mut ty = Block::zero();
            for y in 0..SOFTSPOKEN_Q {
                if y == self.alphas[i] {
                    continue;
                }
                let exp = aes_dm_3(&check_key, self.leaves_recv[base + y]);
                self.leaves_recv[base + y] = exp[0];
                s_buf[y * 2] = exp[1];
                s_buf[y * 2 + 1] = exp[2];
                tx = tx.xor(exp[1]);
                ty = ty.xor(exp[2]);
            }
            s_buf[self.alphas[i] * 2] = t_buf[i * 2].xor(tx);
            s_buf[self.alphas[i] * 2 + 1] = t_buf[i * 2 + 1].xor(ty);
            for block in &s_buf {
                hash.update(block.as_bytes());
            }
        }
        if hash.finalize().as_slice() != their_digest.as_slice() {
            return Err(CompatError::FeqMismatch);
        }
        Ok(())
    }

    async fn send_chunk_pipeline(
        &mut self,
        stream: &mut EmpStream,
        bs: usize,
    ) -> Result<Vec<Block>> {
        let mut planes = vec![Block::zero(); 128 * bs];
        for i in 0..SOFTSPOKEN_N {
            let w = sfvole_receiver_butterfly(
                SOFTSPOKEN_K,
                self.alphas[i],
                &self.leaves_recv[i * SOFTSPOKEN_Q..(i + 1) * SOFTSPOKEN_Q],
                self.cur_send_b0,
                bs,
                self.cur_send_session,
            );
            for bit in 0..SOFTSPOKEN_K {
                let dst = (i * SOFTSPOKEN_K + bit) * bs;
                planes[dst..dst + bs].copy_from_slice(&w[bit * bs..(bit + 1) * bs]);
            }
        }
        let d_bufs = stream.recv_block((SOFTSPOKEN_N - 1) * bs).await?;
        for i in 1..SOFTSPOKEN_N {
            let d_i = &d_bufs[(i - 1) * bs..i * bs];
            for bit in 0..SOFTSPOKEN_K {
                if ((self.alphas[i] >> bit) & 1) != 0 {
                    let offset = (i * SOFTSPOKEN_K + bit) * bs;
                    for j in 0..bs {
                        planes[offset + j] = planes[offset + j].xor(d_i[j]);
                    }
                }
            }
        }
        planes[..bs].fill(Block::zero());
        let out = transpose_softspoken_planes(&planes, bs);
        if self.malicious {
            self.combine_send_chunk(stream, &out, bs)?;
        }
        self.cur_send_b0 += bs as u64;
        Ok(out)
    }

    async fn recv_chunk_pipeline(
        &mut self,
        stream: &mut EmpStream,
        bs: usize,
    ) -> Result<Vec<Block>> {
        let mut planes = vec![Block::zero(); 128 * bs];
        let (u_canonical, v0) = sfvole_sender_butterfly(
            SOFTSPOKEN_K,
            &self.leaves_send[..SOFTSPOKEN_Q],
            self.cur_recv_b0,
            bs,
            self.cur_recv_session,
        );
        for bit in 0..SOFTSPOKEN_K {
            planes[bit * bs..(bit + 1) * bs].copy_from_slice(&v0[bit * bs..(bit + 1) * bs]);
        }
        let mut d_bufs = vec![Block::zero(); (SOFTSPOKEN_N - 1) * bs];
        for i in 1..SOFTSPOKEN_N {
            let (u_temp, v_i) = sfvole_sender_butterfly(
                SOFTSPOKEN_K,
                &self.leaves_send[i * SOFTSPOKEN_Q..(i + 1) * SOFTSPOKEN_Q],
                self.cur_recv_b0,
                bs,
                self.cur_recv_session,
            );
            for j in 0..bs {
                d_bufs[(i - 1) * bs + j] = u_canonical[j].xor(u_temp[j]);
            }
            for bit in 0..SOFTSPOKEN_K {
                let dst = (i * SOFTSPOKEN_K + bit) * bs;
                planes[dst..dst + bs].copy_from_slice(&v_i[bit * bs..(bit + 1) * bs]);
            }
        }
        stream.send_block(&d_bufs).await?;
        planes[..bs].copy_from_slice(&u_canonical);
        let out = transpose_softspoken_planes(&planes, bs);
        if self.malicious {
            self.combine_recv_chunk(stream, &out, &u_canonical, bs)?;
        }
        self.cur_recv_b0 += bs as u64;
        Ok(out)
    }

    fn combine_send_chunk(
        &mut self,
        stream: &mut EmpStream,
        out: &[Block],
        bs: usize,
    ) -> Result<()> {
        let seed = stream.get_digest()?;
        let mut chi_prg = Prg::new(seed, 0);
        let chi = chi_prg.random_block(bs);
        let packed: Vec<Block> = (0..bs)
            .map(|i| gf_pack_128(&out[i * 128..(i + 1) * 128]))
            .collect();
        self.check_q = self.check_q.xor(gf_inner_product(&chi, &packed));
        Ok(())
    }

    fn combine_recv_chunk(
        &mut self,
        stream: &mut EmpStream,
        out: &[Block],
        u_canonical: &[Block],
        bs: usize,
    ) -> Result<()> {
        let seed = stream.get_digest()?;
        let mut chi_prg = Prg::new(seed, 0);
        let chi = chi_prg.random_block(bs);
        let packed: Vec<Block> = (0..bs)
            .map(|i| gf_pack_128(&out[i * 128..(i + 1) * 128]))
            .collect();
        self.check_t = self.check_t.xor(gf_inner_product(&chi, &packed));
        self.check_x = self.check_x.xor(gf_inner_product(&chi, u_canonical));
        Ok(())
    }
}

fn aes_dm_3(key: &Prp, tweak: Block) -> [Block; 3] {
    [
        aes_dm(key, 0, tweak),
        aes_dm(key, 1, tweak),
        aes_dm(key, 2, tweak),
    ]
}

fn block_to_bools(block: Block) -> [bool; 128] {
    let bytes = block.into_bytes();
    let mut out = [false; 128];
    for i in 0..128 {
        out[i] = ((bytes[i / 8] >> (i % 8)) & 1) != 0;
    }
    out
}

fn transpose_softspoken_planes(planes: &[Block], bs: usize) -> Vec<Block> {
    let mut rows = Vec::with_capacity(planes.len() * BLOCK_BYTES);
    for block in planes {
        rows.extend_from_slice(block.as_bytes());
    }
    transpose_128_rows(&rows, bs * BLOCK_BYTES, bs * 128)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AShareBundle {
    pub mac: Block,
    pub key: Block,
}

impl Default for AShareBundle {
    fn default() -> Self {
        Self {
            mac: Block::zero(),
            key: Block::zero(),
        }
    }
}

impl Zeroize for AShareBundle {
    fn zeroize(&mut self) {
        self.mac.zeroize();
        self.key.zeroize();
    }
}

#[derive(Clone, Debug, Default)]
pub struct Ag2pcSecureWires {
    pub lambda: Vec<u8>,
    pub wire_bundle: Vec<AShareBundle>,
    pub label0: Vec<Block>,
    pub eval_label: Vec<Block>,
}

impl Ag2pcSecureWires {
    pub fn len(&self) -> usize {
        self.lambda.len()
    }

    pub fn is_empty(&self) -> bool {
        self.lambda.is_empty()
    }

    pub fn slice(&self, start: usize, end: usize) -> Result<Self> {
        if start > end || end > self.len() {
            return Err(CompatError::BadAuthenticatedSlice {
                len: self.len(),
                start,
                end,
            });
        }
        Ok(Self {
            lambda: self.lambda[start..end].to_vec(),
            wire_bundle: self.wire_bundle[start..end].to_vec(),
            label0: if self.label0.is_empty() {
                Vec::new()
            } else {
                self.label0[start..end].to_vec()
            },
            eval_label: if self.eval_label.is_empty() {
                Vec::new()
            } else {
                self.eval_label[start..end].to_vec()
            },
        })
    }

    pub fn concat(parts: &[Self]) -> Self {
        let total = parts.iter().map(Self::len).sum();
        let mut out = Self {
            lambda: Vec::with_capacity(total),
            wire_bundle: Vec::with_capacity(total),
            label0: Vec::new(),
            eval_label: Vec::new(),
        };
        if parts.iter().any(|part| !part.label0.is_empty()) {
            out.label0 = Vec::with_capacity(total);
        }
        if parts.iter().any(|part| !part.eval_label.is_empty()) {
            out.eval_label = Vec::with_capacity(total);
        }
        for part in parts {
            out.lambda.extend_from_slice(&part.lambda);
            out.wire_bundle.extend_from_slice(&part.wire_bundle);
            out.label0.extend_from_slice(&part.label0);
            out.eval_label.extend_from_slice(&part.eval_label);
        }
        out
    }
}

impl Drop for Ag2pcSecureWires {
    fn drop(&mut self) {
        self.lambda.zeroize();
        self.wire_bundle.zeroize();
        self.label0.zeroize();
        self.eval_label.zeroize();
    }
}

pub struct Ag2pcTriplePool {
    party: Role,
    ssp: usize,
    abit1: SoftSpoken4,
    abit2: SoftSpoken4,
    delta: Block,
    cots_minted_since_check: bool,
}

pub struct Ag2pcProtocol {
    party: Role,
    triple_pool: Ag2pcTriplePool,
    delta: Block,
    prg: Prg,
    process_input_calls: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ag2pcRevealRecipient {
    Public,
    Party(Role),
}

struct Mitccrh8 {
    start_point: Block,
    gid: u64,
    key_used: usize,
    scheduled_bucket: Option<u64>,
    scheduled_keys: Vec<Prp>,
}

impl Mitccrh8 {
    fn new(seed: Block) -> Self {
        Self {
            start_point: seed,
            gid: 0,
            key_used: 8,
            scheduled_bucket: None,
            scheduled_keys: Vec::new(),
        }
    }

    fn hash(&mut self, blocks: &mut [Block], k: usize, h: usize) {
        self.hash_inner(blocks, k, h, false);
    }

    #[allow(dead_code)]
    fn hash_cir(&mut self, blocks: &mut [Block], k: usize, h: usize) {
        self.hash_inner(blocks, k, h, true);
    }

    fn hash_inner(&mut self, blocks: &mut [Block], k: usize, h: usize, cir: bool) {
        assert!(k <= 8);
        assert_eq!(8 % k, 0);
        assert_eq!(blocks.len(), k * h);
        if self.key_used == 8 {
            self.renew_ks();
        }
        if self.scheduled_bucket.is_some() {
            // All blocks share one key (gid is 8-aligned, so renew_ks always takes
            // the single-bucket branch): batch the AES instead of one
            // mitccrh_apply per block. result = AES_key(input) ^ input, with
            // input = sigma(block) if cir else block.
            let key = &self.scheduled_keys[0];
            if cir {
                for block in blocks.iter_mut() {
                    *block = block.sigma();
                }
            }
            for chunk in blocks.chunks_mut(16) {
                let n = chunk.len();
                let mut inp = [Block::zero(); 16];
                inp[..n].copy_from_slice(chunk);
                key.permute_block(chunk);
                for i in 0..n {
                    chunk[i] = chunk[i].xor(inp[i]);
                }
            }
        } else {
            for key_index in 0..k {
                for j in 0..h {
                    let offset = key_index * h + j;
                    blocks[offset] = mitccrh_apply(
                        &self.scheduled_keys[self.key_used + key_index],
                        blocks[offset],
                        cir,
                    );
                }
            }
        }
        self.key_used += k;
    }

    fn renew_ks(&mut self) {
        let first = self.gid >> 3;
        let last = (self.gid + 7) >> 3;
        self.scheduled_keys.clear();
        if first == last {
            self.scheduled_keys
                .push(Prp::new(self.start_point.xor(Block::make(first, 0))));
            self.scheduled_bucket = Some(first);
        } else {
            for i in 0..8 {
                self.scheduled_keys.push(Prp::new(
                    self.start_point.xor(Block::make((self.gid + i) >> 3, 0)),
                ));
            }
            self.scheduled_bucket = None;
        }
        self.gid += 8;
        self.key_used = 0;
    }
}

fn mitccrh_apply(key: &Prp, block: Block, cir: bool) -> Block {
    let input = if cir { block.sigma() } else { block };
    key.permute_one(input).xor(input)
}

struct Ag2pcComputeHashes<'a> {
    gmitc: &'a mut Mitccrh8,
    emitc: &'a mut Mitccrh8,
    feq: &'a mut Sha256,
}

struct Ag2pcLayerView<'a> {
    mac: &'a [Block],
    key: &'a [Block],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ag2pcProgram {
    num_inputs: usize,
    num_wires: usize,
    outputs: Vec<usize>,
    gates: Vec<Ag2pcProgramGate>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Ag2pcProgramGate {
    typ: Ag2pcGateType,
    in0: usize,
    in1: usize,
    out: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Ag2pcGateType {
    And,
    Xor,
    Inv,
}

impl Ag2pcProgram {
    pub fn from_circuit(circuit: &Circuit) -> Result<Self> {
        let num_wire = checked_nonnegative("num_wire", circuit.num_wire)?;
        let n1 = checked_nonnegative("n1", circuit.n1)?;
        let n2 = checked_nonnegative("n2", circuit.n2)?;
        let n3 = checked_nonnegative("n3", circuit.n3)?;
        if num_wire == 0 || n1 + n2 > num_wire || n3 > num_wire {
            return Err(CompatError::BadAg2pcProgram(
                "inconsistent circuit header".to_owned(),
            ));
        }
        let num_inputs = n1 + n2;
        let mut remap = vec![None; num_wire];
        for (wire, slot) in remap.iter_mut().take(num_inputs).enumerate() {
            *slot = Some(wire);
        }
        for (i, gate) in circuit.gates.iter().enumerate() {
            let out = checked_wire("out", gate.out, num_wire)?;
            remap[out] = Some(num_inputs + i);
        }

        let mut gates = Vec::with_capacity(circuit.gates.len());
        for (i, gate) in circuit.gates.iter().enumerate() {
            let typ = match gate.typ {
                GateType::And => Ag2pcGateType::And,
                GateType::Xor => Ag2pcGateType::Xor,
                GateType::Inv => Ag2pcGateType::Inv,
            };
            let in0_old = checked_wire("in0", gate.in0, num_wire)?;
            let in1_old = if typ == Ag2pcGateType::Inv {
                0
            } else {
                checked_wire("in1", gate.in1, num_wire)?
            };
            let in0 = remap[in0_old].ok_or_else(|| {
                CompatError::BadAg2pcProgram("gate input is not defined".to_owned())
            })?;
            let in1 = if typ == Ag2pcGateType::Inv {
                0
            } else {
                remap[in1_old].ok_or_else(|| {
                    CompatError::BadAg2pcProgram("gate input is not defined".to_owned())
                })?
            };
            gates.push(Ag2pcProgramGate {
                typ,
                in0,
                in1,
                out: num_inputs + i,
            });
        }

        let mut outputs = Vec::with_capacity(n3);
        for i in 0..n3 {
            let old = num_wire - n3 + i;
            outputs.push(remap[old].ok_or_else(|| {
                CompatError::BadAg2pcProgram("output wire is not defined".to_owned())
            })?);
        }

        Ok(Self {
            num_inputs,
            num_wires: num_inputs + gates.len(),
            outputs,
            gates,
        })
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
            .filter(|gate| gate.typ == Ag2pcGateType::And)
            .count()
    }
}

struct Ag2pcRunState {
    party: Role,
    delta: Block,
    num_inputs: usize,
    num_ands: usize,
    num_wires: usize,
    num_slots: usize,
    phys: Vec<usize>,
    last_use: Vec<isize>,
    persist: Vec<bool>,
    wire_slot: Vec<AShareBundle>,
    mask_input: Vec<u8>,
    label_slot: Vec<Block>,
    eval_slot: Vec<Block>,
    rep_a: Vec<AShareBundle>,
    rep_b: Vec<AShareBundle>,
    sigma: Vec<AShareBundle>,
    m1_t: Vec<Block>,
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
            m1_t: Vec::new(),
            lambda_and: Vec::new(),
            mitc: Mitccrh8::new(Block::zero()),
        }
    }

    fn slot(&self, wire: usize) -> usize {
        self.phys[wire]
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
    pub async fn setup(streams: &mut Ag2pcStreams, party: Role, ssp: usize) -> Result<Self> {
        Ok(Self {
            protocol: Ag2pcProtocol::setup(streams, party, ssp).await?,
        })
    }

    pub fn party(&self) -> Role {
        self.protocol.party()
    }

    pub fn process_input_calls(&self) -> usize {
        self.protocol.process_input_calls()
    }

    pub async fn process_inputs(
        &mut self,
        streams: &mut Ag2pcStreams,
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

    pub async fn run_program(
        &mut self,
        streams: &mut Ag2pcStreams,
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
        state.sigma = self
            .protocol
            .triple_pool
            .compute_inplace(streams, &state.rep_a, &state.rep_b)
            .await?;
        state.m1_t = vec![Block::zero(); state.num_ands.max(1)];
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

    pub async fn reveal_public(
        &mut self,
        streams: &mut Ag2pcStreams,
        wires: &Ag2pcSecureWires,
    ) -> Result<Vec<u8>> {
        self.protocol
            .decode(streams, wires, Ag2pcRevealRecipient::Public)
            .await
    }

    pub async fn end(&mut self, streams: &mut Ag2pcStreams) -> Result<()> {
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
        state.persist[gate.out] = gate.typ == Ag2pcGateType::And;
        state.last_use[gate.in0] = gate_index as isize;
        if gate.typ != Ag2pcGateType::Inv {
            state.last_use[gate.in1] = gate_index as isize;
        }
        if gate.typ == Ag2pcGateType::And {
            state.num_ands += 1;
        }
    }
    for &out in &program.outputs {
        state.persist[out] = true;
    }
}

async fn ag2pc_slot_mask_pass(
    state: &mut Ag2pcRunState,
    program: &Ag2pcProgram,
    triple_pool: &mut Ag2pcTriplePool,
    streams: &mut Ag2pcStreams,
) -> Result<()> {
    state.phys = vec![usize::MAX; program.num_wires];
    for i in 0..state.num_inputs {
        state.phys[i] = i;
    }
    state.rep_a.clear();
    state.rep_b.clear();
    state.rep_a.reserve(state.num_ands);
    state.rep_b.reserve(state.num_ands);

    let mut freelist = Vec::new();
    let mut lg_buf = Vec::new();
    let mut lg_off = 0usize;

    for (gate_index, gate) in program.gates.iter().enumerate() {
        match gate.typ {
            Ag2pcGateType::And => {
                state.rep_a.push(state.wslot(gate.in0));
                state.rep_b.push(state.wslot(gate.in1));
                if lg_off >= lg_buf.len() {
                    lg_buf = triple_pool.draw(streams, 1 << 14).await?;
                    lg_off = 0;
                }
                let slot = ag2pc_alloc_slot(state, gate.out, &mut freelist);
                state.wire_slot[slot] = lg_buf[lg_off];
                state.mask_input[slot] = 0;
                lg_off += 1;
            }
            Ag2pcGateType::Xor => {
                let lhs = state.wslot(gate.in0);
                let rhs = state.wslot(gate.in1);
                let slot = ag2pc_alloc_slot(state, gate.out, &mut freelist);
                state.wire_slot[slot] = AShareBundle {
                    mac: lhs.mac.xor(rhs.mac),
                    key: lhs.key.xor(rhs.key),
                };
                state.mask_input[slot] = 0;
            }
            Ag2pcGateType::Inv => {
                let value = state.wslot(gate.in0);
                let slot = ag2pc_alloc_slot(state, gate.out, &mut freelist);
                state.wire_slot[slot] = value;
                state.mask_input[slot] = 0;
            }
        }
        ag2pc_free_if_dead(state, gate.in0, gate_index, &mut freelist);
        if gate.typ != Ag2pcGateType::Inv && gate.in1 != gate.in0 {
            ag2pc_free_if_dead(state, gate.in1, gate_index, &mut freelist);
        }
    }

    state.sigma = vec![AShareBundle::default(); state.num_ands.max(1)];
    match state.party {
        Role::Alice => state.label_slot.resize(state.num_slots, Block::zero()),
        Role::Bob => state.eval_slot.resize(state.num_slots, Block::zero()),
    }
    Ok(())
}

fn ag2pc_alloc_slot(state: &mut Ag2pcRunState, wire: usize, freelist: &mut Vec<usize>) -> usize {
    let slot = if !state.persist[wire] {
        freelist.pop().unwrap_or_else(|| ag2pc_push_slot(state))
    } else {
        ag2pc_push_slot(state)
    };
    state.phys[wire] = slot;
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
    if !state.persist[wire] && state.last_use[wire] == gate_index as isize {
        freelist.push(state.slot(wire));
    }
}

async fn ag2pc_garbler_path(
    state: &mut Ag2pcRunState,
    program: &Ag2pcProgram,
    streams: &mut Ag2pcStreams,
) -> Result<()> {
    let mut chunk_g = Vec::new();
    let mut chunk_b = Vec::new();
    let mut and_index = 0usize;
    for gate in &program.gates {
        match gate.typ {
            Ag2pcGateType::Xor => {
                let lhs = state.wslot(gate.in0);
                let rhs = state.wslot(gate.in1);
                state.set_wslot(
                    gate.out,
                    AShareBundle {
                        mac: lhs.mac.xor(rhs.mac),
                        key: lhs.key.xor(rhs.key),
                    },
                );
                state.set_lbl(gate.out, state.lbl(gate.in0).xor(state.lbl(gate.in1)));
            }
            Ag2pcGateType::Inv => {
                state.set_wslot(gate.out, state.wslot(gate.in0));
                state.set_lbl(gate.out, state.lbl(gate.in0).xor(state.delta));
            }
            Ag2pcGateType::And => {
                let (g0, g1, b) = ag2pc_garbler_and_gate(state, gate, and_index);
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
        ag2pc_gamma_check_pass(state, program);
        let digest = hash_once(&blocks_to_bytes(&state.m1_t));
        streams.main.send_data(&digest).await?;
        streams.main.flush().await?;
    }
    Ok(())
}

fn ag2pc_garbler_and_gate(
    state: &mut Ag2pcRunState,
    gate: &Ag2pcProgramGate,
    and_index: usize,
) -> (Block, Block, u8) {
    let ml_a0 = state.lbl(gate.in0);
    let ml_a1 = ml_a0.xor(state.delta);
    let ml_b0 = state.lbl(gate.in1);
    let ml_b1 = ml_b0.xor(state.delta);
    let mut buf = [ml_a0, ml_a1, ml_b0, ml_b1];
    state.mitc.hash_cir(&mut buf, 1, 4);

    let wb_in0 = state.wslot(gate.in0);
    let wb_in1 = state.wslot(gate.in1);
    let wb_out = state.wslot(gate.out);
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
    state.set_lbl(gate.out, ml_g0);
    (g0, g1, block_lsb1(ml_g0))
}

async fn ag2pc_evaluator_path(
    state: &mut Ag2pcRunState,
    program: &Ag2pcProgram,
    streams: &mut Ag2pcStreams,
) -> Result<()> {
    let mut chunk_g = Vec::new();
    let mut chunk_b = Vec::new();
    let mut chunk_pos = 0usize;
    let mut and_index = 0usize;
    for gate in &program.gates {
        match gate.typ {
            Ag2pcGateType::Xor => {
                let lhs = state.wslot(gate.in0);
                let rhs = state.wslot(gate.in1);
                state.set_wslot(
                    gate.out,
                    AShareBundle {
                        mac: lhs.mac.xor(rhs.mac),
                        key: lhs.key.xor(rhs.key),
                    },
                );
                state.set_evl(gate.out, state.evl(gate.in0).xor(state.evl(gate.in1)));
                state.set_minp(gate.out, state.minp(gate.in0) ^ state.minp(gate.in1));
            }
            Ag2pcGateType::Inv => {
                state.set_wslot(gate.out, state.wslot(gate.in0));
                state.set_evl(gate.out, state.evl(gate.in0));
                state.set_minp(gate.out, state.minp(gate.in0) ^ 1);
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
                ag2pc_evaluator_and_gate(
                    state,
                    gate,
                    and_index,
                    chunk_g[2 * chunk_pos],
                    chunk_g[2 * chunk_pos + 1],
                    chunk_b[chunk_pos],
                );
                and_index += 1;
                chunk_pos += 1;
            }
        }
    }
    if state.num_ands > 0 {
        ag2pc_send_bool_vector(&mut streams.main, &state.lambda_and).await?;
        let local = hash_once(&blocks_to_bytes(&state.m1_t));
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
    and_index: usize,
    g0: Block,
    g1: Block,
    b: u8,
) {
    let la = state.minp(gate.in0);
    let lb = state.minp(gate.in1);
    let wb_in0 = state.wslot(gate.in0);
    let wb_in1 = state.wslot(gate.in1);
    let wb_out = state.wslot(gate.out);
    let sigma = state.sigma[and_index];

    let mut mr = sigma.mac.xor(wb_out.mac);
    mr = mr.xor(select_block(la).and(wb_in1.mac));
    mr = mr.xor(select_block(lb).and(wb_in0.mac));

    let mut buf = [state.evl(gate.in0), state.evl(gate.in1)];
    state.mitc.hash_cir(&mut buf, 1, 2);
    let mut t = buf[0].xor(buf[1]);
    t = t.xor(select_block(la).and(g0));
    t = t.xor(select_block(lb).and(g1.xor(state.evl(gate.in0))));
    t = t.xor(mr);
    state.set_evl(gate.out, t);
    let lg = b ^ block_lsb1(t);
    state.set_minp(gate.out, lg);
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
    state.m1_t[and_index] = m;
}

fn ag2pc_gamma_check_pass(state: &mut Ag2pcRunState, program: &Ag2pcProgram) {
    let mut and_index = 0usize;
    for gate in &program.gates {
        match gate.typ {
            Ag2pcGateType::Xor => {
                let lhs = state.wslot(gate.in0);
                let rhs = state.wslot(gate.in1);
                state.set_wslot(
                    gate.out,
                    AShareBundle {
                        mac: lhs.mac.xor(rhs.mac),
                        key: lhs.key.xor(rhs.key),
                    },
                );
                state.set_minp(gate.out, state.minp(gate.in0) ^ state.minp(gate.in1));
            }
            Ag2pcGateType::Inv => {
                state.set_wslot(gate.out, state.wslot(gate.in0));
                state.set_minp(gate.out, state.minp(gate.in0) ^ 1);
            }
            Ag2pcGateType::And => {
                state.set_minp(gate.out, state.lambda_and[and_index]);
                let la = state.minp(gate.in0);
                let lb = state.minp(gate.in1);
                let mut m = state.sigma[and_index].mac.xor(state.wslot(gate.out).mac);
                m = m.xor(select_block(la).and(state.wslot(gate.in1).mac));
                m = m.xor(select_block(lb).and(state.wslot(gate.in0).mac));
                state.m1_t[and_index] = m;
                and_index += 1;
            }
        }
    }
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
        out.lambda.push(state.minp(wire));
        out.wire_bundle.push(state.wslot(wire));
        match state.party {
            Role::Alice => out.label0.push(state.lbl(wire)),
            Role::Bob => out.eval_label.push(state.evl(wire)),
        }
    }
    Ok(out)
}

async fn ag2pc_send_garble_chunk(stream: &mut EmpStream, g: &[Block], b: &[u8]) -> Result<()> {
    stream.send_block(g).await?;
    stream.send_data(b).await?;
    stream.flush().await?;
    Ok(())
}

async fn ag2pc_recv_garble_chunk(
    stream: &mut EmpStream,
    n: usize,
) -> Result<(Vec<Block>, Vec<u8>)> {
    let g = stream.recv_block(2 * n).await?;
    let b = stream.recv_data(n).await?;
    Ok((g, b))
}

const AG2PC_GARBLE_CHUNK_ANDS: usize = 1 << 16;

impl Ag2pcProtocol {
    pub async fn setup(streams: &mut Ag2pcStreams, party: Role, ssp: usize) -> Result<Self> {
        let triple_pool = Ag2pcTriplePool::setup(streams, party, ssp).await?;
        Ok(Self {
            party,
            delta: triple_pool.delta(),
            triple_pool,
            prg: Prg::random()?,
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

    pub async fn flush_cot_check(&mut self, streams: &mut Ag2pcStreams) -> Result<()> {
        self.triple_pool.maybe_flush_cot_check(streams).await
    }

    pub async fn end(&mut self, streams: &mut Ag2pcStreams) -> Result<()> {
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

    pub async fn process_inputs(
        &mut self,
        streams: &mut Ag2pcStreams,
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

        let share_msg: Vec<u8> = sw
            .wire_bundle
            .iter()
            .map(|wire| block_lsb(wire.mac))
            .collect();
        let my_macs: Vec<Block> = sw.wire_bundle.iter().map(|wire| wire.mac).collect();
        let d_me = hash_once(&blocks_to_bytes(&my_macs));

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
                &share_msg,
                &d_me,
                &own_x_packed,
                n_total,
                peer_idx_list.len(),
            )
            .await?;

        let exp_macs: Vec<Block> = sw
            .wire_bundle
            .iter()
            .zip(&peer_share)
            .map(|(wire, share)| wire.key.xor(select_block(*share).and(self.delta)))
            .collect();
        if hash_once(&blocks_to_bytes(&exp_macs)) != d_peer {
            return Err(CompatError::FeqMismatch);
        }

        for i in 0..n_total {
            sw.lambda[i] = share_msg[i] ^ peer_share[i] ^ own_x_bits[i];
        }
        for (i, wire_index) in peer_idx_list.iter().enumerate() {
            sw.lambda[*wire_index] ^= peer_x_packed[i] & 1;
        }

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

    pub async fn decode(
        &mut self,
        streams: &mut Ag2pcStreams,
        wires: &Ag2pcSecureWires,
        recipient: Ag2pcRevealRecipient,
    ) -> Result<Vec<u8>> {
        self.check_secure_wires(wires)?;
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

    async fn decode_to_party(
        &mut self,
        streams: &mut Ag2pcStreams,
        wires: &Ag2pcSecureWires,
        role: Role,
    ) -> Result<Vec<u8>> {
        let n = wires.len();
        let my_share: Vec<u8> = wires
            .wire_bundle
            .iter()
            .map(|wire| block_lsb(wire.mac))
            .collect();
        let my_macs: Vec<Block> = wires.wire_bundle.iter().map(|wire| wire.mac).collect();
        if self.party != role {
            let digest = hash_once(&blocks_to_bytes(&my_macs));
            streams.main.send_data(&my_share).await?;
            streams.main.send_data(&digest).await?;
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
            let exp_macs: Vec<Block> = wires
                .wire_bundle
                .iter()
                .zip(&peer_share)
                .map(|(wire, share)| wire.key.xor(select_block(*share).and(self.delta)))
                .collect();
            if hash_once(&blocks_to_bytes(&exp_macs)) != peer_digest {
                return Err(CompatError::FeqMismatch);
            }
            Ok((0..n)
                .map(|i| my_share[i] ^ wires.lambda[i] ^ (peer_share[i] & 1))
                .map(|bit| bit & 1)
                .collect())
        }
    }

    async fn exchange_input_open(
        &mut self,
        streams: &mut Ag2pcStreams,
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
}

async fn ag2pc_send_input_open(
    stream: &mut EmpStream,
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

async fn ag2pc_recv_input_open(
    stream: &mut EmpStream,
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

impl Ag2pcTriplePool {
    pub async fn setup(streams: &mut Ag2pcStreams, party: Role, ssp: usize) -> Result<Self> {
        if !streams.main.fs_enabled() {
            streams.main.enable_fs(party == Role::Alice)?;
        }
        if !streams.sibling.fs_enabled() {
            streams.sibling.enable_fs(party == Role::Alice)?;
        }

        let delta = random_ag2pc_delta(party)?;
        let mut out = Self {
            party,
            ssp,
            abit1: SoftSpoken4::new_with_delta(Role::Alice, true, delta)?,
            abit2: SoftSpoken4::new(Role::Bob, true)?,
            delta,
            cots_minted_since_check: false,
        };
        out.begin_abits(streams).await?;
        Ok(out)
    }

    pub fn party(&self) -> Role {
        self.party
    }

    pub fn delta(&self) -> Block {
        self.delta
    }

    pub fn ssp(&self) -> usize {
        self.ssp
    }

    pub fn get_bucket_size(&self, size: usize) -> usize {
        let size = size.max(1024);
        let log2_l = (size as f64).log2();
        let mut bucket = 2usize;
        while log2_l * ((bucket - 1) as f64) <= self.ssp as f64 {
            bucket += 1;
        }
        bucket
    }

    pub async fn draw(
        &mut self,
        streams: &mut Ag2pcStreams,
        count: usize,
    ) -> Result<Vec<AShareBundle>> {
        let (mac, key) = self.gen_cot_shares(streams, count).await?;
        Ok(mac
            .into_iter()
            .zip(key)
            .map(|(mac, key)| AShareBundle { mac, key })
            .collect())
    }

    pub async fn compute_inplace(
        &mut self,
        streams: &mut Ag2pcStreams,
        rep_a: &[AShareBundle],
        rep_b: &[AShareBundle],
    ) -> Result<Vec<AShareBundle>> {
        if rep_a.len() != rep_b.len() {
            return Err(CompatError::BadAg2pcInputShape);
        }
        let l = rep_a.len();
        if l == 0 {
            return Ok(Vec::new());
        }
        let bucket = self.get_bucket_size(l);
        let pair_seed = {
            let mine = u64::from(self.party.party_id());
            let peer = u64::from(3 - self.party.party_id());
            Block::make(mine.min(peer), mine.max(peer))
        };
        let mut gmitc = Mitccrh8::new(pair_seed);
        let mut emitc = Mitccrh8::new(pair_seed);
        let mut feq = Sha256::new();
        let mut hashes = Ag2pcComputeHashes {
            gmitc: &mut gmitc,
            emitc: &mut emitc,
            feq: &mut feq,
        };

        let mut acc_mac = vec![Block::zero(); 3 * l];
        let mut acc_key = vec![Block::zero(); 3 * l];
        for i in 0..l {
            acc_mac[i] = rep_a[i].mac;
            acc_key[i] = rep_a[i].key;
            acc_mac[l + i] = rep_b[i].mac;
            acc_key[l + i] = rep_b[i].key;
        }
        let (r_mac, r_key) = self.gen_cot_shares(streams, l).await?;
        acc_mac[2 * l..3 * l].copy_from_slice(&r_mac);
        acc_key[2 * l..3 * l].copy_from_slice(&r_key);
        self.leaky_and_halfgate(streams, &mut acc_mac, &mut acc_key, l, &mut hashes)
            .await?;
        self.layered_bucket_into_acc(streams, &mut acc_mac, &mut acc_key, bucket, l, &mut hashes)
            .await?;

        let dme: [u8; HASH_DIGEST_BYTES] = feq.finalize().into();
        ag2pc_feq_check(&mut streams.main, self.party, &dme).await?;

        let mut xb_me = vec![0u8; l];
        let mut yb_me = vec![0u8; l];
        for i in 0..l {
            xb_me[i] = block_lsb(rep_a[i].mac) ^ block_lsb(acc_mac[i]);
            yb_me[i] = block_lsb(rep_b[i].mac) ^ block_lsb(acc_mac[l + i]);
        }
        let (xb_peer, yb_peer) = self
            .exchange_two_bool_vectors(streams, &xb_me, &yb_me, l)
            .await?;

        let mut out = vec![AShareBundle::default(); l];
        let dxor = self.delta.xor(bit0_mask());
        for i in 0..l {
            let xb = xb_me[i] ^ xb_peer[i];
            let yb = yb_me[i] ^ yb_peer[i];
            let mut mac = acc_mac[2 * l + i]
                .xor(select_block(xb).and(acc_mac[l + i]))
                .xor(select_block(yb).and(acc_mac[i]));
            let mut key = acc_key[2 * l + i]
                .xor(select_block(xb).and(acc_key[l + i]))
                .xor(select_block(yb).and(acc_key[i]));
            let both = select_block(xb & yb);
            if self.party == Role::Alice {
                mac = mac.xor(both.and(bit0_mask()));
            } else {
                key = key.xor(both.and(dxor));
            }
            out[i] = AShareBundle { mac, key };
        }
        Ok(out)
    }

    pub async fn maybe_flush_cot_check(&mut self, streams: &mut Ag2pcStreams) -> Result<()> {
        if self.cots_minted_since_check {
            self.flush_cot_check(streams).await?;
        }
        Ok(())
    }

    pub async fn flush_cot_check(&mut self, streams: &mut Ag2pcStreams) -> Result<()> {
        self.cots_minted_since_check = false;
        self.end_abits(streams).await?;
        self.begin_abits(streams).await
    }

    pub async fn end(&mut self, streams: &mut Ag2pcStreams) -> Result<()> {
        self.cots_minted_since_check = false;
        self.end_abits(streams).await
    }

    async fn gen_cot_shares(
        &mut self,
        streams: &mut Ag2pcStreams,
        count: usize,
    ) -> Result<(Vec<Block>, Vec<Block>)> {
        self.cots_minted_since_check = true;
        match self.party {
            Role::Alice => {
                let (key, mac) = tokio::try_join!(
                    ag2pc_next_n_flush(&mut self.abit1, &mut streams.sibling, count),
                    ag2pc_next_n_flush(&mut self.abit2, &mut streams.main, count)
                )?;
                Ok((mac, key))
            }
            Role::Bob => {
                let (key, mac) = tokio::try_join!(
                    ag2pc_next_n_flush(&mut self.abit1, &mut streams.main, count),
                    ag2pc_next_n_flush(&mut self.abit2, &mut streams.sibling, count)
                )?;
                Ok((mac, key))
            }
        }
    }

    async fn leaky_and_halfgate(
        &mut self,
        streams: &mut Ag2pcStreams,
        mac: &mut [Block],
        key: &mut [Block],
        l: usize,
        hashes: &mut Ag2pcComputeHashes<'_>,
    ) -> Result<()> {
        let mut g_blocks = Vec::with_capacity(l);
        for k0 in (0..l).step_by(8) {
            let batch = (l - k0).min(8);
            let mut pad = [Block::zero(); 16];
            for j in 0..8 {
                if j < batch {
                    let kk = key[k0 + j];
                    pad[2 * j] = kk;
                    pad[2 * j + 1] = kk.xor(self.delta);
                }
            }
            hashes.gmitc.hash(&mut pad, 8, 2);
            for j in 0..batch {
                let k = k0 + j;
                let c = select_block(block_lsb(mac[l + k]))
                    .and(self.delta)
                    .xor(key[l + k])
                    .xor(mac[l + k]);
                g_blocks.push(pad[2 * j].xor(pad[2 * j + 1]).xor(c));
            }
        }
        let w_blocks = self.exchange_blocks(streams, &g_blocks, l).await?;

        let mut sout = vec![Block::zero(); l];
        for k0 in (0..l).step_by(8) {
            let batch = (l - k0).min(8);
            let mut pad = [Block::zero(); 16];
            for j in 0..8 {
                if j < batch {
                    pad[2 * j] = mac[k0 + j];
                    pad[2 * j + 1] = key[k0 + j];
                }
            }
            hashes.emitc.hash(&mut pad, 8, 2);
            for j in 0..batch {
                let k = k0 + j;
                let hm = pad[2 * j];
                let hk = pad[2 * j + 1];
                let e = hm.xor(w_blocks[k].and(select_block(block_lsb(mac[k]))));
                let c = select_block(block_lsb(mac[l + k]))
                    .and(self.delta)
                    .xor(key[l + k])
                    .xor(mac[l + k]);
                sout[k] = hk
                    .xor(e)
                    .xor(key[2 * l + k])
                    .xor(mac[2 * l + k])
                    .xor(c.and(select_block(block_lsb(mac[k]))))
                    .xor(self.delta.and(select_block(block_lsb(mac[2 * l + k]))));
            }
        }

        let s_me: Vec<u8> = sout.iter().map(|block| block_lsb1(*block)).collect();
        let s_peer = self.exchange_bool_vector(streams, &s_me, l).await?;
        let dxor = self.delta.xor(bit0_mask());
        for k in 0..l {
            let d = s_me[k] ^ s_peer[k];
            let mask = select_block(d);
            if self.party == Role::Alice {
                mac[2 * l + k] = mac[2 * l + k].xor(bit0_mask().and(mask));
            } else {
                key[2 * l + k] = key[2 * l + k].xor(dxor.and(mask));
            }
            sout[k] = sout[k].xor(self.delta.and(mask));
        }
        hashes.feq.update(blocks_to_bytes(&sout));
        Ok(())
    }

    async fn layered_bucket_into_acc(
        &mut self,
        streams: &mut Ag2pcStreams,
        acc_mac: &mut [Block],
        acc_key: &mut [Block],
        bucket: usize,
        l: usize,
        hashes: &mut Ag2pcComputeHashes<'_>,
    ) -> Result<()> {
        for _ in 0..bucket - 1 {
            let (mut sac_mac, mut sac_key) = self.gen_cot_shares(streams, 3 * l).await?;
            self.leaky_and_halfgate(streams, &mut sac_mac, &mut sac_key, l, hashes)
                .await?;
            let seed = EmpRo::new("AG2PC RO", Block::zero())
                .absorb_block(streams.main.get_digest()?)
                .absorb_block(streams.sibling.get_digest()?)
                .squeeze_block();
            let mut prg = Prg::new(seed, 0);
            let raw = u32::from_ne_bytes(
                prg.random_data(4)
                    .try_into()
                    .expect("four random bytes for bucket shift"),
            );
            let r = (raw as usize) % l;
            let layer = Ag2pcLayerView {
                mac: &sac_mac,
                key: &sac_key,
            };
            self.bucket_one_layer(streams, acc_mac, acc_key, layer, l, r)
                .await?;
        }
        Ok(())
    }

    async fn bucket_one_layer(
        &mut self,
        streams: &mut Ag2pcStreams,
        acc_mac: &mut [Block],
        acc_key: &mut [Block],
        layer: Ag2pcLayerView<'_>,
        l: usize,
        r: usize,
    ) -> Result<()> {
        let mut d_me = vec![0u8; l];
        let cut = l - r;
        for i in 0..l {
            let src = if i < cut { i + r } else { i + r - l };
            acc_mac[i] = acc_mac[i].xor(layer.mac[src]);
            acc_mac[2 * l + i] = acc_mac[2 * l + i].xor(layer.mac[2 * l + src]);
            acc_key[i] = acc_key[i].xor(layer.key[src]);
            acc_key[2 * l + i] = acc_key[2 * l + i].xor(layer.key[2 * l + src]);
            d_me[i] = block_lsb(acc_mac[l + i]) ^ block_lsb(layer.mac[l + src]);
        }
        let d_peer = self.exchange_bool_vector(streams, &d_me, l).await?;
        for i in 0..l {
            let src = if i < cut { i + r } else { i + r - l };
            let mask = select_block(d_me[i] ^ d_peer[i]);
            acc_mac[2 * l + i] = acc_mac[2 * l + i].xor(layer.mac[src].and(mask));
            acc_key[2 * l + i] = acc_key[2 * l + i].xor(layer.key[src].and(mask));
        }
        Ok(())
    }

    async fn exchange_blocks(
        &mut self,
        streams: &mut Ag2pcStreams,
        mine: &[Block],
        peer_len: usize,
    ) -> Result<Vec<Block>> {
        match self.party {
            Role::Alice => {
                let ((), peer) = tokio::try_join!(
                    ag2pc_send_blocks(&mut streams.main, mine),
                    ag2pc_recv_blocks(&mut streams.sibling, peer_len)
                )?;
                Ok(peer)
            }
            Role::Bob => {
                let ((), peer) = tokio::try_join!(
                    ag2pc_send_blocks(&mut streams.sibling, mine),
                    ag2pc_recv_blocks(&mut streams.main, peer_len)
                )?;
                Ok(peer)
            }
        }
    }

    async fn exchange_bool_vector(
        &mut self,
        streams: &mut Ag2pcStreams,
        mine: &[u8],
        peer_len: usize,
    ) -> Result<Vec<u8>> {
        match self.party {
            Role::Alice => {
                let ((), peer) = tokio::try_join!(
                    ag2pc_send_bool_vector(&mut streams.main, mine),
                    ag2pc_recv_bool_vector(&mut streams.sibling, peer_len)
                )?;
                Ok(peer)
            }
            Role::Bob => {
                let ((), peer) = tokio::try_join!(
                    ag2pc_send_bool_vector(&mut streams.sibling, mine),
                    ag2pc_recv_bool_vector(&mut streams.main, peer_len)
                )?;
                Ok(peer)
            }
        }
    }

    async fn exchange_two_bool_vectors(
        &mut self,
        streams: &mut Ag2pcStreams,
        mine_a: &[u8],
        mine_b: &[u8],
        peer_len: usize,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        match self.party {
            Role::Alice => {
                let ((), peer) = tokio::try_join!(
                    ag2pc_send_two_bool_vectors(&mut streams.main, mine_a, mine_b),
                    ag2pc_recv_two_bool_vectors(&mut streams.sibling, peer_len)
                )?;
                Ok(peer)
            }
            Role::Bob => {
                let ((), peer) = tokio::try_join!(
                    ag2pc_send_two_bool_vectors(&mut streams.sibling, mine_a, mine_b),
                    ag2pc_recv_two_bool_vectors(&mut streams.main, peer_len)
                )?;
                Ok(peer)
            }
        }
    }

    async fn begin_abits(&mut self, streams: &mut Ag2pcStreams) -> Result<()> {
        match self.party {
            Role::Alice => {
                tokio::try_join!(
                    ag2pc_begin_flush(&mut self.abit1, &mut streams.sibling),
                    ag2pc_begin_flush(&mut self.abit2, &mut streams.main)
                )?;
            }
            Role::Bob => {
                tokio::try_join!(
                    ag2pc_begin_flush(&mut self.abit1, &mut streams.main),
                    ag2pc_begin_flush(&mut self.abit2, &mut streams.sibling)
                )?;
            }
        }
        Ok(())
    }

    async fn end_abits(&mut self, streams: &mut Ag2pcStreams) -> Result<()> {
        match self.party {
            Role::Alice => {
                tokio::try_join!(
                    ag2pc_end_flush(&mut self.abit1, &mut streams.sibling),
                    ag2pc_end_flush(&mut self.abit2, &mut streams.main)
                )?;
            }
            Role::Bob => {
                tokio::try_join!(
                    ag2pc_end_flush(&mut self.abit1, &mut streams.main),
                    ag2pc_end_flush(&mut self.abit2, &mut streams.sibling)
                )?;
            }
        }
        Ok(())
    }
}

impl Drop for Ag2pcTriplePool {
    fn drop(&mut self) {
        self.delta.zeroize();
    }
}

async fn ag2pc_begin_flush(soft: &mut SoftSpoken4, stream: &mut EmpStream) -> Result<()> {
    soft.begin(stream).await?;
    stream.flush().await?;
    Ok(())
}

async fn ag2pc_next_n_flush(
    soft: &mut SoftSpoken4,
    stream: &mut EmpStream,
    count: usize,
) -> Result<Vec<Block>> {
    let out = soft.next_n(stream, count).await?;
    stream.flush().await?;
    Ok(out)
}

async fn ag2pc_end_flush(soft: &mut SoftSpoken4, stream: &mut EmpStream) -> Result<()> {
    soft.end(stream).await?;
    stream.flush().await?;
    Ok(())
}

async fn ag2pc_send_blocks(stream: &mut EmpStream, blocks: &[Block]) -> Result<()> {
    stream.send_block(blocks).await?;
    stream.flush().await?;
    Ok(())
}

async fn ag2pc_recv_blocks(stream: &mut EmpStream, len: usize) -> Result<Vec<Block>> {
    Ok(stream.recv_block(len).await?)
}

async fn ag2pc_send_bool_vector(stream: &mut EmpStream, data: &[u8]) -> Result<()> {
    stream.send_data(&ag2pc_pack_bools(data)).await?;
    stream.flush().await?;
    Ok(())
}

async fn ag2pc_recv_bool_vector(stream: &mut EmpStream, len: usize) -> Result<Vec<u8>> {
    let encoded = stream.recv_data(ag2pc_bool_wire_len(len)).await?;
    Ok(ag2pc_unpack_bools(&encoded, len))
}

async fn ag2pc_send_two_bool_vectors(
    stream: &mut EmpStream,
    first: &[u8],
    second: &[u8],
) -> Result<()> {
    stream.send_data(&ag2pc_pack_bools(first)).await?;
    stream.send_data(&ag2pc_pack_bools(second)).await?;
    stream.flush().await?;
    Ok(())
}

async fn ag2pc_recv_two_bool_vectors(
    stream: &mut EmpStream,
    len: usize,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let first = ag2pc_recv_bool_vector(stream, len).await?;
    let second = ag2pc_recv_bool_vector(stream, len).await?;
    Ok((first, second))
}

fn ag2pc_bool_wire_len(len: usize) -> usize {
    len.div_ceil(8)
}

fn ag2pc_pack_bools(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; ag2pc_bool_wire_len(data.len())];
    for (i, bit) in data.iter().enumerate() {
        if *bit != 0 {
            out[i / 8] |= 1 << (i % 8);
        }
    }
    out
}

fn ag2pc_unpack_bools(encoded: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    for i in 0..len {
        out.push((encoded[i / 8] >> (i % 8)) & 1);
    }
    out
}

async fn ag2pc_feq_check(
    stream: &mut EmpStream,
    party: Role,
    local_digest: &[u8; HASH_DIGEST_BYTES],
) -> Result<()> {
    match party {
        Role::Alice => {
            let nonce = random_block()?;
            let commitment = ag2pc_feq_commitment(local_digest, nonce);
            stream.send_data(&commitment).await?;
            let peer_digest: [u8; HASH_DIGEST_BYTES] = stream
                .recv_data(HASH_DIGEST_BYTES)
                .await?
                .try_into()
                .expect("digest length");
            stream.send_data(local_digest).await?;
            stream.send_block(&[nonce]).await?;
            stream.flush().await?;
            if peer_digest != *local_digest {
                return Err(CompatError::FeqMismatch);
            }
        }
        Role::Bob => {
            let commitment: [u8; HASH_DIGEST_BYTES] = stream
                .recv_data(HASH_DIGEST_BYTES)
                .await?
                .try_into()
                .expect("digest length");
            stream.send_data(local_digest).await?;
            let peer_digest: [u8; HASH_DIGEST_BYTES] = stream
                .recv_data(HASH_DIGEST_BYTES)
                .await?
                .try_into()
                .expect("digest length");
            let nonce = stream.recv_block(1).await?[0];
            let expected = ag2pc_feq_commitment(&peer_digest, nonce);
            if commitment != expected || peer_digest != *local_digest {
                return Err(CompatError::FeqMismatch);
            }
        }
    }
    Ok(())
}

fn ag2pc_feq_commitment(digest: &[u8; HASH_DIGEST_BYTES], nonce: Block) -> [u8; 32] {
    let mut data = Vec::with_capacity(HASH_DIGEST_BYTES + BLOCK_BYTES);
    data.extend_from_slice(digest);
    data.extend_from_slice(nonce.as_bytes());
    hash_once(&data)
}

fn random_ag2pc_delta(party: Role) -> Result<Block> {
    let mut bytes = random_block()?.into_bytes();
    bytes[0] |= 1;
    if party == Role::Alice {
        bytes[0] |= 2;
    } else {
        bytes[0] &= !2;
    }
    Ok(Block::from_bytes(bytes))
}

fn select_block(bit: u8) -> Block {
    if (bit & 1) == 0 {
        Block::zero()
    } else {
        Block::from_bytes([0xff; BLOCK_BYTES])
    }
}

fn block_lsb(block: Block) -> u8 {
    u8::from(block.get_lsb())
}

fn block_lsb1(block: Block) -> u8 {
    (block.as_bytes()[0] >> 1) & 1
}

fn bit0_mask() -> Block {
    Block::make(0, 1)
}

pub fn verify_ag2pc_share_relation(
    local: &[AShareBundle],
    local_delta: Block,
    peer: &[AShareBundle],
    peer_delta: Block,
) -> bool {
    local.len() == peer.len()
        && local.iter().zip(peer).all(|(mine, theirs)| {
            let mine_expected = theirs
                .key
                .xor(select_block(block_lsb(mine.mac)).and(peer_delta));
            let peer_expected = mine
                .key
                .xor(select_block(block_lsb(theirs.mac)).and(local_delta));
            mine.mac == mine_expected && theirs.mac == peer_expected
        })
}

fn checked_nonnegative(name: &'static str, value: i32) -> Result<usize> {
    if value < 0 {
        Err(CompatError::BadAg2pcProgram(format!(
            "{name} must be nonnegative"
        )))
    } else {
        Ok(value as usize)
    }
}

fn checked_wire(name: &'static str, wire: i32, num_wire: usize) -> Result<usize> {
    if wire < 0 || wire as usize >= num_wire {
        Err(CompatError::BadAg2pcProgram(format!(
            "{name} wire {wire} out of range 0..{num_wire}"
        )))
    } else {
        Ok(wire as usize)
    }
}

fn random_block() -> Result<Block> {
    let mut bytes = [0u8; BLOCK_BYTES];
    rand_bytes(&mut bytes)?;
    Ok(Block::from_bytes(bytes))
}

fn transpose_128_rows(rows: &[u8], row_bytes: usize, output_len: usize) -> Vec<Block> {
    debug_assert_eq!(output_len, row_bytes * 8);
    let mut out = vec![[0u8; BLOCK_BYTES]; output_len];
    for source_byte in 0..row_bytes {
        for (group, _) in [0u8; BLOCK_BYTES].iter().enumerate() {
            let row = group * 8;
            let x = u64::from_le_bytes([
                rows[(row) * row_bytes + source_byte],
                rows[(row + 1) * row_bytes + source_byte],
                rows[(row + 2) * row_bytes + source_byte],
                rows[(row + 3) * row_bytes + source_byte],
                rows[(row + 4) * row_bytes + source_byte],
                rows[(row + 5) * row_bytes + source_byte],
                rows[(row + 6) * row_bytes + source_byte],
                rows[(row + 7) * row_bytes + source_byte],
            ]);
            let transposed = transpose_8x8(x).to_le_bytes();
            for bit in 0..8 {
                out[source_byte * 8 + bit][group] = transposed[bit];
            }
        }
    }
    out.into_iter().map(Block::from_bytes).collect()
}

fn transpose_8x8(mut x: u64) -> u64 {
    let mut t = (x ^ (x >> 7)) & 0x00AA_00AA_00AA_00AA;
    x ^= t ^ (t << 7);
    t = (x ^ (x >> 14)) & 0x0000_CCCC_0000_CCCC;
    x ^= t ^ (t << 14);
    t = (x ^ (x >> 28)) & 0x0000_0000_F0F0_F0F0;
    x ^= t ^ (t << 28);
    x
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
    use shachain2pc_circuit::Gate;
    use std::net::{IpAddr, Ipv4Addr, TcpListener as StdTcpListener};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use tokio::sync::Mutex;
    use tokio::time::{timeout, Duration};

    const LIVE_INTEROP_TIMEOUT: Duration = Duration::from_secs(60);
    const TRANSPOSE_ROWS: usize = 128;
    const LIVE_SOFTSPOKEN_LENGTH: usize = 2051;
    const LIVE_AG2PC_DRAW_LENGTH: usize = 257;
    #[cfg(feature = "cpp-probes")]
    const LIVE_AG2PC_COMPUTE_LENGTH: usize = 35;
    static LIVE_CPP_INTEROP_LOCK: Mutex<()> = Mutex::const_new(());

    #[test]
    fn transpose_128_rows_matches_bit_reference() {
        for row_bytes in [1usize, 16, 32, 256] {
            let output_len = row_bytes * 8;
            let mut rows = vec![0u8; TRANSPOSE_ROWS * row_bytes];
            for (i, byte) in rows.iter_mut().enumerate() {
                *byte = ((i * 37 + i / 7 + 0x5a) & 0xff) as u8;
            }
            assert_eq!(
                transpose_128_rows(&rows, row_bytes, output_len),
                transpose_128_rows_bit_reference(&rows, row_bytes, output_len)
            );
        }
    }

    fn transpose_128_rows_bit_reference(
        rows: &[u8],
        row_bytes: usize,
        output_len: usize,
    ) -> Vec<Block> {
        let mut out = vec![Block::zero(); output_len];
        for (col, out_block) in out.iter_mut().enumerate() {
            let mut bytes = [0u8; BLOCK_BYTES];
            let source_byte = col / 8;
            let source_mask = 1 << (col % 8);
            for row in 0..TRANSPOSE_ROWS {
                if (rows[row * row_bytes + source_byte] & source_mask) != 0 {
                    bytes[row / 8] |= 1 << (row % 8);
                }
            }
            *out_block = Block::from_bytes(bytes);
        }
        out
    }

    #[derive(Clone, Copy, Debug)]
    enum TestTransport {
        Listen,
        Connect,
    }

    #[derive(Clone, Copy, Debug)]
    enum TestOtRole {
        Send,
        Recv,
    }

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

    fn blocks_digest_json(blocks: &[Block]) -> String {
        let mut hasher = Sha256::new();
        for block in blocks {
            hasher.update(block.as_bytes());
        }
        hex_encode(&hasher.finalize())
    }

    fn assert_block_json_array(fixture: &Value, name: &str, blocks: &[Block]) {
        let expected = fixture[name].as_array().unwrap();
        assert_eq!(expected.len(), blocks.len(), "{name} length mismatch");
        for (i, block) in blocks.iter().enumerate() {
            assert_eq!(
                block_json(*block),
                expected[i].as_str().unwrap(),
                "{name}[{i}]"
            );
        }
    }

    fn blocks_bytes(blocks: &[Block]) -> Vec<u8> {
        let mut out = Vec::with_capacity(blocks.len() * BLOCK_BYTES);
        for block in blocks {
            out.extend_from_slice(block.as_bytes());
        }
        out
    }

    fn csw_pad(sid: Block, i: usize, point: &[u8]) -> Block {
        EmpRo::new("emp-ot:csw-base-ot:pad", sid)
            .absorb_u64(i as u64)
            .absorb_point(point)
            .squeeze_block()
    }

    fn csw_short(sid: Block, block: Block) -> Block {
        EmpRo::new("emp-ot:csw-base-ot:short", sid)
            .absorb_block(block)
            .squeeze_block()
    }

    fn csw_data0(i: usize) -> Block {
        Block::make(0x1000_0000_0000_0000 | i as u64, 0x100 | i as u64)
    }

    fn csw_data1(i: usize) -> Block {
        Block::make(0x2000_0000_0000_0000 | i as u64, 0x200 | i as u64)
    }

    fn csw_choice(i: usize) -> bool {
        ((i * 7 + 3) % 11) < 5
    }

    fn opposite_role(role: Role) -> Role {
        match role {
            Role::Alice => Role::Bob,
            Role::Bob => Role::Alice,
        }
    }

    fn ag2pc_test_circuit() -> Circuit {
        Circuit {
            num_wire: 8,
            n1: 3,
            n2: 2,
            n3: 1,
            gates: vec![
                Gate {
                    typ: GateType::And,
                    in0: 0,
                    in1: 3,
                    out: 5,
                },
                Gate {
                    typ: GateType::Xor,
                    in0: 1,
                    in1: 4,
                    out: 6,
                },
                Gate {
                    typ: GateType::And,
                    in0: 5,
                    in1: 6,
                    out: 7,
                },
            ],
        }
    }

    fn ag2pc_test_input() -> [u8; 5] {
        [1, 0, 1, 1, 1]
    }

    fn ag2pc_expected_output() -> [u8; 1] {
        [1]
    }

    #[test]
    fn ag2pc_bool_packing_is_compact_lsb_first() {
        for len in 0usize..20 {
            let data: Vec<u8> = (0..len).map(|i| ((i * 5 + 1) & 1) as u8).collect();
            let packed = ag2pc_pack_bools(&data);
            assert_eq!(packed.len(), len.div_ceil(8));
            assert_eq!(ag2pc_unpack_bools(&packed, len), data);
            for i in len..packed.len() * 8 {
                assert_eq!((packed[i / 8] >> (i % 8)) & 1, 0);
            }
        }

        assert_eq!(
            ag2pc_pack_bools(&[1, 0, 1, 1, 0, 0, 1, 0, 1]),
            vec![0x4d, 0x01]
        );
    }

    #[test]
    fn softspoken_helpers_match_cpp_fixture() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../../compat/ag2pc/softspoken-helper-v1.json"
        ))
        .unwrap();
        let k = fixture["k"].as_u64().unwrap() as usize;
        let bs = fixture["bs"].as_u64().unwrap() as usize;
        let alpha_field = fixture["alpha_field"].as_u64().unwrap() as usize;
        let session_id = fixture["session_id"].as_u64().unwrap();
        let counter_base = fixture["counter_base"].as_u64().unwrap();

        let delta = Block::make(0x0112_2334_4556_6778, 0x899a_abbc_cdde_eff1);
        let root = Block::make(0x0103_0507_090b_0d0f, 0x1113_1517_191b_1d1f);
        let (sender_leaves, k0) = cggm_build_sender(k, delta, root, false);

        let alpha_path = cggm_bit_reverse(alpha_field as u32, k) as usize;
        assert_eq!(alpha_path, fixture["alpha_path"].as_u64().unwrap() as usize);
        let recv_keys: Vec<Block> = (1..=k)
            .map(|level| {
                let alpha_i = ((alpha_path >> (k - level)) & 1) != 0;
                let alpha_bar_i = !alpha_i;
                if alpha_bar_i {
                    k0[level - 1].xor(delta)
                } else {
                    k0[level - 1]
                }
            })
            .collect();
        let receiver_leaves = cggm_eval_receiver(k, alpha_path, &recv_keys, false);
        let (sfvole_u, sfvole_v) =
            sfvole_sender_butterfly(k, &sender_leaves, counter_base, bs, session_id);
        let sfvole_w = sfvole_receiver_butterfly(
            k,
            alpha_field,
            &receiver_leaves,
            counter_base,
            bs,
            session_id,
        );

        assert_block_json_array(&fixture, "k0", &k0);
        assert_block_json_array(&fixture, "recv_keys", &recv_keys);
        assert_block_json_array(&fixture, "sender_leaves", &sender_leaves);
        assert_block_json_array(&fixture, "receiver_leaves", &receiver_leaves);
        assert_block_json_array(&fixture, "sfvole_u", &sfvole_u);
        assert_block_json_array(&fixture, "sfvole_v", &sfvole_v);
        assert_block_json_array(&fixture, "sfvole_w", &sfvole_w);
    }

    #[test]
    fn csw_helper_transcript_matches_cpp_fixture() {
        let fixture: Value =
            serde_json::from_str(include_str!("../../../../compat/ag2pc/csw-helper-v1.json"))
                .unwrap();
        let group = P256::new().unwrap();
        let sid = Block::zero();
        let seed = Block::make(0x0102_0304_0506_0708, 0x1112_1314_1516_1718);
        let t = EmpRo::new("emp-ot:csw-base-ot:to-curve", sid)
            .absorb_block(seed)
            .squeeze_p256_point()
            .unwrap();
        assert_eq!(hex_encode(&t), fixture["T"].as_str().unwrap());

        let r = 0x12345;
        let z = group.mul_gen(r).unwrap();
        assert_eq!(hex_encode(&z), fixture["z"].as_str().unwrap());
        let t_r_neg = group.point_inv(&group.point_mul(&t, r).unwrap()).unwrap();

        let length = fixture["length"].as_u64().unwrap() as usize;
        let mut b_points = Vec::with_capacity(length);
        let mut p0 = Vec::with_capacity(length);
        let mut p1 = Vec::with_capacity(length);
        let mut h0 = Vec::with_capacity(length);
        let mut chi = Vec::with_capacity(length);
        let mut c0 = Vec::with_capacity(length);
        let mut c1 = Vec::with_capacity(length);
        let mut recovered = Vec::with_capacity(length);

        for i in 0..length {
            let alpha = 0x2000 + i as u64 * 17;
            let mut b = group.mul_gen(alpha).unwrap();
            if csw_choice(i) {
                b = group.point_add(&b, &t).unwrap();
            }
            let rho0 = group.point_mul(&b, r).unwrap();
            let rho1 = group.point_add(&rho0, &t_r_neg).unwrap();
            let pad0 = csw_pad(sid, i, &rho0);
            let pad1 = csw_pad(sid, i, &rho1);
            p0.push(pad0);
            p1.push(pad1);
            h0.push(csw_short(sid, pad0));
            b_points.push(b);
        }

        let otans = EmpRo::new("emp-ot:csw-base-ot:agg", sid)
            .absorb_bytes(&blocks_bytes(&h0))
            .squeeze_block();
        let proof = csw_short(sid, otans);
        assert_eq!(block_json(otans), fixture["otans"].as_str().unwrap());
        assert_eq!(block_json(proof), fixture["proof"].as_str().unwrap());

        for i in 0..length {
            let h1 = csw_short(sid, p1[i]);
            chi.push(h0[i].xor(h1));
            c0.push(p0[i].xor(csw_data0(i)));
            c1.push(p1[i].xor(csw_data1(i)));

            let alpha = 0x2000 + i as u64 * 17;
            let z_alpha = group.point_mul(&z, alpha).unwrap();
            let p_bi = csw_pad(sid, i, &z_alpha);
            recovered.push(p_bi.xor(if csw_choice(i) { c1[i] } else { c0[i] }));
        }

        assert_eq!(
            hex_encode(&b_points[0]),
            fixture["B_first"].as_str().unwrap()
        );
        assert_eq!(
            hex_encode(b_points.last().unwrap()),
            fixture["B_last"].as_str().unwrap()
        );
        assert_eq!(
            blocks_digest_json(&p0),
            fixture["p0_digest"].as_str().unwrap()
        );
        assert_eq!(
            blocks_digest_json(&p1),
            fixture["p1_digest"].as_str().unwrap()
        );
        assert_eq!(
            blocks_digest_json(&h0),
            fixture["h0_digest"].as_str().unwrap()
        );
        assert_eq!(
            blocks_digest_json(&chi),
            fixture["chi_digest"].as_str().unwrap()
        );
        assert_eq!(
            blocks_digest_json(&c0),
            fixture["c0_digest"].as_str().unwrap()
        );
        assert_eq!(
            blocks_digest_json(&c1),
            fixture["c1_digest"].as_str().unwrap()
        );
        assert_eq!(
            blocks_digest_json(&recovered),
            fixture["recovered_digest"].as_str().unwrap()
        );
        assert_eq!(block_json(p0[0]), fixture["p0_first"].as_str().unwrap());
        assert_eq!(block_json(p1[0]), fixture["p1_first"].as_str().unwrap());
        assert_eq!(block_json(chi[0]), fixture["chi_first"].as_str().unwrap());
        assert_eq!(block_json(c0[0]), fixture["c0_first"].as_str().unwrap());
        assert_eq!(block_json(c1[0]), fixture["c1_first"].as_str().unwrap());
        assert_eq!(
            block_json(recovered[0]),
            fixture["recovered_first"].as_str().unwrap()
        );
        assert_eq!(
            block_json(*recovered.last().unwrap()),
            fixture["recovered_last"].as_str().unwrap()
        );
        for (i, block) in recovered.iter().enumerate() {
            let expected = if csw_choice(i) {
                csw_data1(i)
            } else {
                csw_data0(i)
            };
            assert_eq!(*block, expected, "CSW recovered[{i}]");
        }
    }

    #[test]
    fn mitccrh_helper_matches_cpp_fixture() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../../compat/ag2pc/mitccrh-helper-v1.json"
        ))
        .unwrap();
        let seed = Block::make(0x0102_0304_0506_0708, 0x1112_1314_1516_1718);

        let mut h8 = Mitccrh8::new(seed);
        let mut hash_8x2: Vec<Block> = (0..16)
            .map(|i| Block::make(0x1000_0000_0000_0000 | i, 0x2000_0000_0000_0000 | i))
            .collect();
        let mut hash_8x2_second: Vec<Block> = (0..16)
            .map(|i| Block::make(0x3000_0000_0000_0000 | i, 0x4000_0000_0000_0000 | i))
            .collect();
        h8.hash(&mut hash_8x2, 8, 2);
        h8.hash(&mut hash_8x2_second, 8, 2);

        let mut h4 = Mitccrh8::new(seed);
        let mut hash_4x2_first: Vec<Block> = (0..8)
            .map(|i| Block::make(0x5000_0000_0000_0000 | i, 0x6000_0000_0000_0000 | i))
            .collect();
        let mut hash_4x2_second: Vec<Block> = (0..8)
            .map(|i| Block::make(0x7000_0000_0000_0000 | i, 0x8000_0000_0000_0000 | i))
            .collect();
        h4.hash(&mut hash_4x2_first, 4, 2);
        h4.hash(&mut hash_4x2_second, 4, 2);

        let mut hc = Mitccrh8::new(seed);
        let mut hash_cir_8x2: Vec<Block> = (0..16)
            .map(|i| Block::make(0x9000_0000_0000_0000 | i, 0xa000_0000_0000_0000 | i))
            .collect();
        hc.hash_cir(&mut hash_cir_8x2, 8, 2);

        assert_block_json_array(&fixture, "hash_8x2", &hash_8x2);
        assert_block_json_array(&fixture, "hash_8x2_second", &hash_8x2_second);
        assert_block_json_array(&fixture, "hash_4x2_first", &hash_4x2_first);
        assert_block_json_array(&fixture, "hash_4x2_second", &hash_4x2_second);
        assert_block_json_array(&fixture, "hash_cir_8x2", &hash_cir_8x2);
        assert_eq!(
            blocks_digest_json(&hash_8x2),
            fixture["hash_8x2_digest"].as_str().unwrap()
        );
        assert_eq!(
            blocks_digest_json(&hash_8x2_second),
            fixture["hash_8x2_second_digest"].as_str().unwrap()
        );
        assert_eq!(
            blocks_digest_json(&hash_4x2_first),
            fixture["hash_4x2_first_digest"].as_str().unwrap()
        );
        assert_eq!(
            blocks_digest_json(&hash_4x2_second),
            fixture["hash_4x2_second_digest"].as_str().unwrap()
        );
        assert_eq!(
            blocks_digest_json(&hash_cir_8x2),
            fixture["hash_cir_8x2_digest"].as_str().unwrap()
        );
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rust_csw_base_ot_roundtrip() {
        let port = free_port();
        let choices: Vec<bool> = (0..80).map(csw_choice).collect();
        let expected: Vec<Block> = choices
            .iter()
            .enumerate()
            .map(|(i, choice)| if *choice { csw_data1(i) } else { csw_data0(i) })
            .collect();
        let receiver_choices = choices.clone();
        let receiver = tokio::spawn(async move {
            let mut stream = EmpStream::listen(port).await.unwrap();
            csw_recv(&mut stream, &receiver_choices).await.unwrap()
        });

        let data0: Vec<Block> = (0..80).map(csw_data0).collect();
        let data1: Vec<Block> = (0..80).map(csw_data1).collect();
        let mut sender = EmpStream::connect(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
            .await
            .unwrap();
        csw_send(&mut sender, &data0, &data1).await.unwrap();

        let out = timeout(LIVE_INTEROP_TIMEOUT, receiver)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(out, expected);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rust_softspoken4_roundtrip() {
        let port = free_port();
        let alice = tokio::spawn(async move {
            let mut stream = EmpStream::listen(port).await.unwrap();
            let mut soft = SoftSpoken4::new(Role::Alice, true).unwrap();
            let out = soft.run(&mut stream, LIVE_SOFTSPOKEN_LENGTH).await.unwrap();
            (soft.delta(), out)
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        let bob = tokio::spawn(async move {
            let mut stream = EmpStream::connect(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
                .await
                .unwrap();
            let mut soft = SoftSpoken4::new(Role::Bob, true).unwrap();
            soft.run(&mut stream, LIVE_SOFTSPOKEN_LENGTH).await.unwrap()
        });
        let ((delta, sender), receiver) = timeout(LIVE_INTEROP_TIMEOUT, async {
            (alice.await.unwrap(), bob.await.unwrap())
        })
        .await
        .unwrap();
        assert_softspoken_relation(&receiver, delta, &sender);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn rust_ag2pc_triple_pool_draw_roundtrip() {
        let port = free_port();
        let alice = tokio::spawn(async move {
            let mut streams =
                Ag2pcStreams::open(Role::Alice, port, IpAddr::V4(Ipv4Addr::LOCALHOST))
                    .await
                    .unwrap();
            let mut pool = Ag2pcTriplePool::setup(&mut streams, Role::Alice, 40)
                .await
                .unwrap();
            let bundle = pool
                .draw(&mut streams, LIVE_AG2PC_DRAW_LENGTH)
                .await
                .unwrap();
            pool.flush_cot_check(&mut streams).await.unwrap();
            (pool.delta(), bundle)
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        let bob = tokio::spawn(async move {
            let mut streams = Ag2pcStreams::open(Role::Bob, port, IpAddr::V4(Ipv4Addr::LOCALHOST))
                .await
                .unwrap();
            let mut pool = Ag2pcTriplePool::setup(&mut streams, Role::Bob, 40)
                .await
                .unwrap();
            let bundle = pool
                .draw(&mut streams, LIVE_AG2PC_DRAW_LENGTH)
                .await
                .unwrap();
            pool.flush_cot_check(&mut streams).await.unwrap();
            (pool.delta(), bundle)
        });
        let ((alice_delta, alice_bundle), (bob_delta, bob_bundle)) =
            timeout(LIVE_INTEROP_TIMEOUT, async {
                (alice.await.unwrap(), bob.await.unwrap())
            })
            .await
            .unwrap();
        assert!(verify_ag2pc_share_relation(
            &alice_bundle,
            alice_delta,
            &bob_bundle,
            bob_delta
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn rust_ag2pc_protocol_process_inputs_and_decode_roundtrip() {
        let port = free_port();
        let alice = tokio::spawn(async move {
            let mut streams =
                Ag2pcStreams::open(Role::Alice, port, IpAddr::V4(Ipv4Addr::LOCALHOST))
                    .await
                    .unwrap();
            run_rust_ag2pc_protocol_script(&mut streams, Role::Alice)
                .await
                .unwrap()
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        let bob = tokio::spawn(async move {
            let mut streams = Ag2pcStreams::open(Role::Bob, port, IpAddr::V4(Ipv4Addr::LOCALHOST))
                .await
                .unwrap();
            run_rust_ag2pc_protocol_script(&mut streams, Role::Bob)
                .await
                .unwrap()
        });
        let (alice_out, bob_out) = timeout(LIVE_INTEROP_TIMEOUT, async {
            (alice.await.unwrap(), bob.await.unwrap())
        })
        .await
        .unwrap();
        assert_eq!(alice_out, bob_out);
        assert_eq!(alice_out, vec![1, 0, 1, 1, 0, 1]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn rust_ag2pc_compute_inplace_random_masks_roundtrip() {
        let port = free_port();
        let alice = tokio::spawn(async move {
            let mut streams =
                Ag2pcStreams::open(Role::Alice, port, IpAddr::V4(Ipv4Addr::LOCALHOST))
                    .await
                    .unwrap();
            let mut pool = Ag2pcTriplePool::setup(&mut streams, Role::Alice, 40)
                .await
                .unwrap();
            let rep_a = pool
                .draw(&mut streams, LIVE_AG2PC_DRAW_LENGTH)
                .await
                .unwrap();
            let rep_b = pool
                .draw(&mut streams, LIVE_AG2PC_DRAW_LENGTH)
                .await
                .unwrap();
            let sigma = pool
                .compute_inplace(&mut streams, &rep_a, &rep_b)
                .await
                .unwrap();
            pool.flush_cot_check(&mut streams).await.unwrap();
            (pool.delta(), rep_a, rep_b, sigma)
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        let bob = tokio::spawn(async move {
            let mut streams = Ag2pcStreams::open(Role::Bob, port, IpAddr::V4(Ipv4Addr::LOCALHOST))
                .await
                .unwrap();
            let mut pool = Ag2pcTriplePool::setup(&mut streams, Role::Bob, 40)
                .await
                .unwrap();
            let rep_a = pool
                .draw(&mut streams, LIVE_AG2PC_DRAW_LENGTH)
                .await
                .unwrap();
            let rep_b = pool
                .draw(&mut streams, LIVE_AG2PC_DRAW_LENGTH)
                .await
                .unwrap();
            let sigma = pool
                .compute_inplace(&mut streams, &rep_a, &rep_b)
                .await
                .unwrap();
            pool.flush_cot_check(&mut streams).await.unwrap();
            (pool.delta(), rep_a, rep_b, sigma)
        });
        let ((alice_delta, alice_a, alice_b, alice_sigma), (bob_delta, bob_a, bob_b, bob_sigma)) =
            timeout(LIVE_INTEROP_TIMEOUT, async {
                (alice.await.unwrap(), bob.await.unwrap())
            })
            .await
            .unwrap();
        assert!(verify_ag2pc_share_relation(
            &alice_sigma,
            alice_delta,
            &bob_sigma,
            bob_delta
        ));
        for i in 0..LIVE_AG2PC_DRAW_LENGTH {
            let a = block_lsb(alice_a[i].mac) ^ block_lsb(bob_a[i].mac);
            let b = block_lsb(alice_b[i].mac) ^ block_lsb(bob_b[i].mac);
            let sigma = block_lsb(alice_sigma[i].mac) ^ block_lsb(bob_sigma[i].mac);
            assert_eq!(sigma, a & b, "sigma relation mismatch at {i}");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn rust_ag2pc_program_roundtrip() {
        let port = free_port();
        let alice = tokio::spawn(async move {
            let mut streams =
                Ag2pcStreams::open(Role::Alice, port, IpAddr::V4(Ipv4Addr::LOCALHOST))
                    .await
                    .unwrap();
            run_rust_ag2pc_program_script(&mut streams, Role::Alice)
                .await
                .unwrap()
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        let bob = tokio::spawn(async move {
            let mut streams = Ag2pcStreams::open(Role::Bob, port, IpAddr::V4(Ipv4Addr::LOCALHOST))
                .await
                .unwrap();
            run_rust_ag2pc_program_script(&mut streams, Role::Bob)
                .await
                .unwrap()
        });
        let (alice_out, bob_out) = timeout(LIVE_INTEROP_TIMEOUT, async {
            (alice.await.unwrap(), bob.await.unwrap())
        })
        .await
        .unwrap();
        assert_eq!(alice_out, ag2pc_expected_output());
        assert_eq!(bob_out, ag2pc_expected_output());
    }

    #[cfg(feature = "cpp-probes")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn live_cpp_csw_base_ot_interop() {
        let _guard = LIVE_CPP_INTEROP_LOCK.lock().await;
        let bin = cpp_csw_probe();
        for transport in [TestTransport::Listen, TestTransport::Connect] {
            run_live_csw_case(&bin, transport, TestOtRole::Send).await;
            run_live_csw_case(&bin, transport, TestOtRole::Recv).await;
        }
    }

    #[cfg(feature = "cpp-probes")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn live_cpp_softspoken4_interop() {
        let _guard = LIVE_CPP_INTEROP_LOCK.lock().await;
        let bin = cpp_softspoken_probe();
        run_live_softspoken_case(&bin, Role::Alice).await;
        run_live_softspoken_case(&bin, Role::Bob).await;
    }

    #[cfg(feature = "cpp-probes")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn live_cpp_ag2pc_triple_pool_draw_interop() {
        let _guard = LIVE_CPP_INTEROP_LOCK.lock().await;
        let bin = cpp_ag2pc_triple_pool_probe();
        run_live_ag2pc_triple_pool_case(&bin, Role::Alice).await;
        run_live_ag2pc_triple_pool_case(&bin, Role::Bob).await;
    }

    #[cfg(feature = "cpp-probes")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn live_cpp_ag2pc_protocol_interop() {
        let _guard = LIVE_CPP_INTEROP_LOCK.lock().await;
        let bin = cpp_ag2pc_protocol_probe();
        run_live_ag2pc_protocol_case(&bin, Role::Alice).await;
        run_live_ag2pc_protocol_case(&bin, Role::Bob).await;
    }

    #[cfg(feature = "cpp-probes")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn live_cpp_ag2pc_compute_inplace_interop() {
        let _guard = LIVE_CPP_INTEROP_LOCK.lock().await;
        let bin = cpp_ag2pc_compute_probe();
        run_live_ag2pc_compute_case(&bin, Role::Alice).await;
        run_live_ag2pc_compute_case(&bin, Role::Bob).await;
    }

    #[cfg(feature = "cpp-probes")]
    async fn run_live_csw_case(bin: &Path, rust_transport: TestTransport, rust_role: TestOtRole) {
        let port = free_port();
        let cpp_transport = match rust_transport {
            TestTransport::Listen => "connect",
            TestTransport::Connect => "listen",
        };
        let cpp_role = match rust_role {
            TestOtRole::Send => "recv",
            TestOtRole::Recv => "send",
        };
        let child = Command::new(bin)
            .current_dir(repo_root())
            .arg(cpp_transport)
            .arg(port.to_string())
            .arg(cpp_role)
            .arg("127.0.0.1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        if matches!(rust_transport, TestTransport::Connect) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let mut stream = open_stream(rust_transport, port).await.unwrap();
        let result = timeout(LIVE_INTEROP_TIMEOUT, run_rust_csw(&mut stream, rust_role)).await;
        let output = child.wait_with_output().unwrap();
        match result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => panic!(
                "Rust CSW failed: {e}\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
            Err(_) => panic!(
                "Rust CSW timed out\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
        }
        assert!(
            output.status.success(),
            "C++ CSW probe failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(feature = "cpp-probes")]
    async fn run_live_softspoken_case(bin: &Path, rust_role: Role) {
        let port = free_port();
        let cpp_role = opposite_role(rust_role);
        let mut child = Command::new(bin)
            .current_dir(repo_root())
            .arg(cpp_role.party_id().to_string())
            .arg(port.to_string())
            .arg("127.0.0.1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        if rust_role == Role::Bob {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let mut stream = if rust_role == Role::Alice {
            EmpStream::listen(port).await.unwrap()
        } else {
            EmpStream::connect(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
                .await
                .unwrap()
        };
        let result = timeout(
            LIVE_INTEROP_TIMEOUT,
            run_rust_softspoken_peer(&mut stream, rust_role),
        )
        .await;
        match result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust SoftSpoken failed: {e}\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Err(_) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust SoftSpoken timed out\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "C++ SoftSpoken probe failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(feature = "cpp-probes")]
    async fn run_live_ag2pc_triple_pool_case(bin: &Path, rust_role: Role) {
        let port = free_port();
        let cpp_role = opposite_role(rust_role);
        let mut child = Command::new(bin)
            .current_dir(repo_root())
            .arg(cpp_role.party_id().to_string())
            .arg(port.to_string())
            .arg("127.0.0.1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        if rust_role == Role::Bob {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let stream_result = timeout(
            LIVE_INTEROP_TIMEOUT,
            Ag2pcStreams::open(rust_role, port, IpAddr::V4(Ipv4Addr::LOCALHOST)),
        )
        .await;
        let mut streams = match stream_result {
            Ok(Ok(streams)) => streams,
            Ok(Err(e)) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust AG2PC triple-pool stream open failed: {e}\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Err(_) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust AG2PC triple-pool stream open timed out\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        };
        let result = timeout(
            LIVE_INTEROP_TIMEOUT,
            run_rust_ag2pc_triple_pool_peer(&mut streams, rust_role),
        )
        .await;
        match result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust AG2PC triple-pool failed: {e}\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Err(_) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust AG2PC triple-pool timed out\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "C++ AG2PC triple-pool probe failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(feature = "cpp-probes")]
    async fn run_live_ag2pc_protocol_case(bin: &Path, rust_role: Role) {
        let port = free_port();
        let cpp_role = opposite_role(rust_role);
        let mut child = Command::new(bin)
            .current_dir(repo_root())
            .arg(cpp_role.party_id().to_string())
            .arg(port.to_string())
            .arg("127.0.0.1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        if rust_role == Role::Bob {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let stream_result = timeout(
            LIVE_INTEROP_TIMEOUT,
            Ag2pcStreams::open(rust_role, port, IpAddr::V4(Ipv4Addr::LOCALHOST)),
        )
        .await;
        let mut streams = match stream_result {
            Ok(Ok(streams)) => streams,
            Ok(Err(e)) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust AG2PC protocol stream open failed: {e}\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Err(_) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust AG2PC protocol stream open timed out\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        };
        let result = timeout(
            LIVE_INTEROP_TIMEOUT,
            run_rust_ag2pc_protocol_script(&mut streams, rust_role),
        )
        .await;
        match result {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust AG2PC protocol failed: {e}\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Err(_) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust AG2PC protocol timed out\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "C++ AG2PC protocol probe failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(feature = "cpp-probes")]
    async fn run_live_ag2pc_compute_case(bin: &Path, rust_role: Role) {
        let port = free_port();
        let cpp_role = opposite_role(rust_role);
        let mut child = Command::new(bin)
            .current_dir(repo_root())
            .arg(cpp_role.party_id().to_string())
            .arg(port.to_string())
            .arg("127.0.0.1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        if rust_role == Role::Bob {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let stream_result = timeout(
            LIVE_INTEROP_TIMEOUT,
            Ag2pcStreams::open(rust_role, port, IpAddr::V4(Ipv4Addr::LOCALHOST)),
        )
        .await;
        let mut streams = match stream_result {
            Ok(Ok(streams)) => streams,
            Ok(Err(e)) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust AG2PC compute stream open failed: {e}\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Err(_) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust AG2PC compute stream open timed out\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        };
        let result = timeout(
            LIVE_INTEROP_TIMEOUT,
            run_rust_ag2pc_compute_peer(&mut streams, rust_role),
        )
        .await;
        match result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust AG2PC compute failed: {e}\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Err(_) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust AG2PC compute timed out\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "C++ AG2PC compute probe failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    async fn open_stream(transport: TestTransport, port: u16) -> Result<EmpStream> {
        match transport {
            TestTransport::Listen => EmpStream::listen(port).await.map_err(Into::into),
            TestTransport::Connect => EmpStream::connect(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
                .await
                .map_err(Into::into),
        }
    }

    #[cfg(feature = "cpp-probes")]
    async fn run_rust_softspoken_peer(stream: &mut EmpStream, role: Role) -> Result<()> {
        let mut soft = SoftSpoken4::new(role, true)?;
        let out = soft.run(stream, LIVE_SOFTSPOKEN_LENGTH).await?;
        if role == Role::Alice {
            stream.send_block(&[soft.delta()]).await?;
            stream.send_block(&out).await?;
            stream.flush().await?;
            let ok = stream.recv_data(1).await?[0];
            assert_eq!(ok, 1);
        } else {
            let delta = stream.recv_block(1).await?[0];
            let sender = stream.recv_block(LIVE_SOFTSPOKEN_LENGTH).await?;
            assert_softspoken_relation(&out, delta, &sender);
            stream.send_data(&[1]).await?;
            stream.flush().await?;
        }
        Ok(())
    }

    #[cfg(feature = "cpp-probes")]
    async fn run_rust_ag2pc_triple_pool_peer(streams: &mut Ag2pcStreams, role: Role) -> Result<()> {
        let mut pool = Ag2pcTriplePool::setup(streams, role, 40).await?;
        let local = pool.draw(streams, LIVE_AG2PC_DRAW_LENGTH).await?;
        pool.flush_cot_check(streams).await?;

        let (peer_delta, peer) = if role == Role::Alice {
            send_ag2pc_bundle(&mut streams.main, pool.delta(), &local).await?;
            recv_ag2pc_bundle(&mut streams.main, LIVE_AG2PC_DRAW_LENGTH).await?
        } else {
            let peer = recv_ag2pc_bundle(&mut streams.main, LIVE_AG2PC_DRAW_LENGTH).await?;
            send_ag2pc_bundle(&mut streams.main, pool.delta(), &local).await?;
            peer
        };
        assert!(verify_ag2pc_share_relation(
            &local,
            pool.delta(),
            &peer,
            peer_delta
        ));
        pool.end(streams).await?;
        Ok(())
    }

    async fn run_rust_ag2pc_protocol_script(
        streams: &mut Ag2pcStreams,
        role: Role,
    ) -> Result<Vec<u8>> {
        let mut protocol = Ag2pcProtocol::setup(streams, role, 40).await?;
        let alice_bits = if role == Role::Alice {
            vec![1, 0]
        } else {
            vec![0, 0]
        };
        let bob_bits = if role == Role::Bob { vec![1] } else { vec![0] };
        let inputs = protocol
            .process_inputs(streams, &[Role::Alice, Role::Bob], &[alice_bits, bob_bits])
            .await?;
        protocol.flush_cot_check(streams).await?;

        let mut out = Vec::new();
        out.extend(
            protocol
                .decode(streams, &inputs[0], Ag2pcRevealRecipient::Public)
                .await?,
        );
        out.extend(
            protocol
                .decode(streams, &inputs[1], Ag2pcRevealRecipient::Public)
                .await?,
        );
        let public = protocol.public_wires(&[1, 0, 1]);
        out.extend(
            protocol
                .decode(streams, &public, Ag2pcRevealRecipient::Public)
                .await?,
        );
        assert_eq!(protocol.process_input_calls(), 1);
        protocol.end(streams).await?;
        Ok(out)
    }

    #[cfg(feature = "cpp-probes")]
    async fn run_rust_ag2pc_compute_peer(streams: &mut Ag2pcStreams, role: Role) -> Result<()> {
        let mut pool = Ag2pcTriplePool::setup(streams, role, 40).await?;
        let rep_a = pool.draw(streams, LIVE_AG2PC_COMPUTE_LENGTH).await?;
        let rep_b = pool.draw(streams, LIVE_AG2PC_COMPUTE_LENGTH).await?;
        let sigma = pool.compute_inplace(streams, &rep_a, &rep_b).await?;
        pool.flush_cot_check(streams).await?;

        let (peer_delta, peer_a, peer_b, peer_sigma) = if role == Role::Alice {
            send_ag2pc_compute_verification(
                &mut streams.main,
                pool.delta(),
                &rep_a,
                &rep_b,
                &sigma,
            )
            .await?;
            recv_ag2pc_compute_verification(&mut streams.main).await?
        } else {
            let peer = recv_ag2pc_compute_verification(&mut streams.main).await?;
            send_ag2pc_compute_verification(
                &mut streams.main,
                pool.delta(),
                &rep_a,
                &rep_b,
                &sigma,
            )
            .await?;
            peer
        };
        assert!(verify_ag2pc_share_relation(
            &sigma,
            pool.delta(),
            &peer_sigma,
            peer_delta
        ));
        for i in 0..LIVE_AG2PC_COMPUTE_LENGTH {
            let a = block_lsb(rep_a[i].mac) ^ block_lsb(peer_a[i].mac);
            let b = block_lsb(rep_b[i].mac) ^ block_lsb(peer_b[i].mac);
            let out = block_lsb(sigma[i].mac) ^ block_lsb(peer_sigma[i].mac);
            assert_eq!(out, a & b, "cross-mode sigma mismatch at {i}");
        }
        pool.end(streams).await?;
        Ok(())
    }

    async fn run_rust_ag2pc_program_script(
        streams: &mut Ag2pcStreams,
        role: Role,
    ) -> Result<Vec<u8>> {
        let program = Ag2pcProgram::from_circuit(&ag2pc_test_circuit())?;
        assert_eq!(program.num_inputs(), 5);
        assert_eq!(program.output_len(), 1);
        assert_eq!(program.num_ands(), 2);

        let input = ag2pc_test_input();
        let bob_bits = input[0..3].to_vec();
        let alice_bits = input[3..5].to_vec();
        let mut session = Ag2pcSession::setup(streams, role, 40).await?;
        let inputs = session
            .process_inputs(streams, &[Role::Bob, Role::Alice], &[bob_bits, alice_bits])
            .await?;
        let all_inputs = Ag2pcSecureWires::concat(&inputs);
        let output = session.run_program(streams, &program, &all_inputs).await?;
        let bits = session.reveal_public(streams, &output).await?;
        session.end(streams).await?;
        Ok(bits)
    }

    #[cfg(feature = "cpp-probes")]
    async fn send_ag2pc_bundle(
        stream: &mut EmpStream,
        delta: Block,
        bundle: &[AShareBundle],
    ) -> Result<()> {
        let mac: Vec<Block> = bundle.iter().map(|item| item.mac).collect();
        let key: Vec<Block> = bundle.iter().map(|item| item.key).collect();
        stream.send_block(&[delta]).await?;
        stream.send_block(&mac).await?;
        stream.send_block(&key).await?;
        stream.flush().await?;
        Ok(())
    }

    #[cfg(feature = "cpp-probes")]
    async fn recv_ag2pc_bundle(
        stream: &mut EmpStream,
        len: usize,
    ) -> Result<(Block, Vec<AShareBundle>)> {
        let delta = stream.recv_block(1).await?[0];
        let mac = stream.recv_block(len).await?;
        let key = stream.recv_block(len).await?;
        Ok((
            delta,
            mac.into_iter()
                .zip(key)
                .map(|(mac, key)| AShareBundle { mac, key })
                .collect(),
        ))
    }

    #[cfg(feature = "cpp-probes")]
    async fn send_ag2pc_compute_verification(
        stream: &mut EmpStream,
        delta: Block,
        rep_a: &[AShareBundle],
        rep_b: &[AShareBundle],
        sigma: &[AShareBundle],
    ) -> Result<()> {
        stream.send_block(&[delta]).await?;
        send_ag2pc_bundle_without_delta(stream, rep_a).await?;
        send_ag2pc_bundle_without_delta(stream, rep_b).await?;
        send_ag2pc_bundle_without_delta(stream, sigma).await?;
        stream.flush().await?;
        Ok(())
    }

    #[cfg(feature = "cpp-probes")]
    async fn recv_ag2pc_compute_verification(
        stream: &mut EmpStream,
    ) -> Result<(
        Block,
        Vec<AShareBundle>,
        Vec<AShareBundle>,
        Vec<AShareBundle>,
    )> {
        let delta = stream.recv_block(1).await?[0];
        let rep_a = recv_ag2pc_bundle_without_delta(stream, LIVE_AG2PC_COMPUTE_LENGTH).await?;
        let rep_b = recv_ag2pc_bundle_without_delta(stream, LIVE_AG2PC_COMPUTE_LENGTH).await?;
        let sigma = recv_ag2pc_bundle_without_delta(stream, LIVE_AG2PC_COMPUTE_LENGTH).await?;
        Ok((delta, rep_a, rep_b, sigma))
    }

    #[cfg(feature = "cpp-probes")]
    async fn send_ag2pc_bundle_without_delta(
        stream: &mut EmpStream,
        bundle: &[AShareBundle],
    ) -> Result<()> {
        let mac: Vec<Block> = bundle.iter().map(|item| item.mac).collect();
        let key: Vec<Block> = bundle.iter().map(|item| item.key).collect();
        stream.send_block(&mac).await?;
        stream.send_block(&key).await?;
        Ok(())
    }

    #[cfg(feature = "cpp-probes")]
    async fn recv_ag2pc_bundle_without_delta(
        stream: &mut EmpStream,
        len: usize,
    ) -> Result<Vec<AShareBundle>> {
        let mac = stream.recv_block(len).await?;
        let key = stream.recv_block(len).await?;
        Ok(mac
            .into_iter()
            .zip(key)
            .map(|(mac, key)| AShareBundle { mac, key })
            .collect())
    }

    fn assert_softspoken_relation(receiver_data: &[Block], delta: Block, sender_data: &[Block]) {
        assert_eq!(receiver_data.len(), sender_data.len());
        for i in 0..receiver_data.len() {
            let expected = if receiver_data[i].get_lsb() {
                sender_data[i].xor(delta)
            } else {
                sender_data[i]
            };
            assert_eq!(receiver_data[i], expected, "SoftSpoken COT item {i}");
        }
    }

    #[cfg(feature = "cpp-probes")]
    async fn run_rust_csw(stream: &mut EmpStream, role: TestOtRole) -> Result<()> {
        let data0: Vec<Block> = (0..80).map(csw_data0).collect();
        let data1: Vec<Block> = (0..80).map(csw_data1).collect();
        match role {
            TestOtRole::Send => csw_send(stream, &data0, &data1).await,
            TestOtRole::Recv => {
                let choices: Vec<bool> = (0..80).map(csw_choice).collect();
                let out = csw_recv(stream, &choices).await?;
                let expected: Vec<Block> = choices
                    .iter()
                    .enumerate()
                    .map(|(i, choice)| if *choice { data1[i] } else { data0[i] })
                    .collect();
                assert_eq!(out, expected);
                Ok(())
            }
        }
    }

    #[cfg(feature = "cpp-probes")]
    fn cpp_csw_probe() -> PathBuf {
        let root = repo_root();
        let bin = root.join(".build/csw_probe");
        if !bin.exists() {
            let status = Command::new("make")
                .arg(".build/csw_probe")
                .current_dir(&root)
                .status()
                .unwrap();
            assert!(status.success(), "failed to build .build/csw_probe");
        }
        assert!(
            bin.exists(),
            ".build/csw_probe was not built by the Cargo build script or test setup"
        );
        bin
    }

    #[cfg(feature = "cpp-probes")]
    fn cpp_softspoken_probe() -> PathBuf {
        let root = repo_root();
        let bin = root.join(".build/softspoken_probe");
        if !bin.exists() {
            let status = Command::new("make")
                .arg(".build/softspoken_probe")
                .current_dir(&root)
                .status()
                .unwrap();
            assert!(status.success(), "failed to build .build/softspoken_probe");
        }
        assert!(
            bin.exists(),
            ".build/softspoken_probe was not built by the Cargo build script or test setup"
        );
        bin
    }

    #[cfg(feature = "cpp-probes")]
    fn cpp_ag2pc_triple_pool_probe() -> PathBuf {
        let root = repo_root();
        let bin = root.join(".build/ag2pc_triple_pool_probe");
        if !bin.exists() {
            let status = Command::new("make")
                .arg(".build/ag2pc_triple_pool_probe")
                .current_dir(&root)
                .status()
                .unwrap();
            assert!(
                status.success(),
                "failed to build .build/ag2pc_triple_pool_probe"
            );
        }
        assert!(
            bin.exists(),
            ".build/ag2pc_triple_pool_probe was not built by the Cargo build script or test setup"
        );
        bin
    }

    #[cfg(feature = "cpp-probes")]
    fn cpp_ag2pc_protocol_probe() -> PathBuf {
        let root = repo_root();
        let bin = root.join(".build/ag2pc_protocol_probe");
        if !bin.exists() {
            let status = Command::new("make")
                .arg(".build/ag2pc_protocol_probe")
                .current_dir(&root)
                .status()
                .unwrap();
            assert!(
                status.success(),
                "failed to build .build/ag2pc_protocol_probe"
            );
        }
        assert!(
            bin.exists(),
            ".build/ag2pc_protocol_probe was not built by the Cargo build script or test setup"
        );
        bin
    }

    #[cfg(feature = "cpp-probes")]
    fn cpp_ag2pc_compute_probe() -> PathBuf {
        let root = repo_root();
        let bin = root.join(".build/ag2pc_compute_probe");
        if !bin.exists() {
            let status = Command::new("make")
                .arg(".build/ag2pc_compute_probe")
                .current_dir(&root)
                .status()
                .unwrap();
            assert!(
                status.success(),
                "failed to build .build/ag2pc_compute_probe"
            );
        }
        assert!(
            bin.exists(),
            ".build/ag2pc_compute_probe was not built by the Cargo build script or test setup"
        );
        bin
    }

    fn free_port() -> u16 {
        StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }
}
