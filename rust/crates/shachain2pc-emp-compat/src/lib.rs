use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;
use openssl::bn::{BigNum, BigNumContext, BigNumRef};
use openssl::ec::{EcGroup, EcPoint, EcPointRef, PointConversionForm};
use openssl::error::ErrorStack;
use openssl::nid::Nid;
use openssl::rand::rand_bytes;
use sha2::{Digest, Sha256};
use shachain2pc_circuit::{Circuit, GateType};
use shachain2pc_emp_wire::{Block, EmpStream, EmpStreams, WireError, BLOCK_BYTES};
use shachain2pc_types::Role;
use std::env;
use std::fmt;
use std::sync::OnceLock;
use std::time::Instant;
use zeroize::Zeroize;

pub const HASH_DIGEST_BYTES: usize = 32;
pub const POINT_BYTES: usize = 65;
pub const IKNP_SECURITY_BITS: usize = 128;
pub const IKNP_BLOCK_SIZE: usize = 2048;
pub const FPRE_THREADS: usize = 1;
const C2PC_SSP_BYTES: usize = 5;

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
    BadFpreCheckIndex(usize),
    BadFpreGeneratedLength {
        expected: usize,
        mac: usize,
        key: usize,
    },
    BadC2pcCircuit(String),
    BadC2pcInputLength {
        expected: usize,
        actual: usize,
    },
    BadAuthenticatedSlice {
        len: usize,
        start: usize,
        end: usize,
    },
    C2pcInvalidMaskBit {
        wire: usize,
        value: u8,
    },
    C2pcMaskMismatch(usize),
    C2pcGarbledTableMismatch(usize),
    C2pcOutputMacMismatch(usize),
    C2pcOutputLabelMismatch(usize),
    C2pcLambdaMismatch(usize),
    CoinTossMismatch,
    FeqMismatch,
    LengthOverflow(&'static str),
    MissingDelta(&'static str),
    BadIknpSetupLength {
        name: &'static str,
        len: usize,
    },
    IknpWrongRole(&'static str),
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
            Self::Wire(e) => write!(f, "{e}"),
            Self::BadPointLength(len) => write!(f, "expected {POINT_BYTES} point bytes, got {len}"),
            Self::BadPointWireLength(len) => {
                write!(f, "expected EMP point wire length {POINT_BYTES}, got {len}")
            }
            Self::BadOtLength { data0, data1 } => {
                write!(f, "OTCO data length mismatch: data0={data0}, data1={data1}")
            }
            Self::BadFpreCheckIndex(index) => {
                write!(f, "Fpre check index must be 0 or 1, got {index}")
            }
            Self::BadFpreGeneratedLength { expected, mac, key } => write!(
                f,
                "Fpre generated data length mismatch: expected={expected}, mac={mac}, key={key}"
            ),
            Self::BadC2pcCircuit(msg) => write!(f, "bad C2PC circuit: {msg}"),
            Self::BadC2pcInputLength { expected, actual } => write!(
                f,
                "C2PC online input length mismatch: expected={expected}, actual={actual}"
            ),
            Self::BadAuthenticatedSlice { len, start, end } => write!(
                f,
                "authenticated bit slice [{start}, {end}) is out of range for length {len}"
            ),
            Self::C2pcInvalidMaskBit { wire, value } => {
                write!(f, "C2PC mask byte at wire {wire} is not a bit: {value}")
            }
            Self::C2pcMaskMismatch(index) => {
                write!(f, "C2PC input mask commitment mismatch at wire {index}")
            }
            Self::C2pcGarbledTableMismatch(index) => {
                write!(f, "C2PC garbled-table row mismatch at AND gate {index}")
            }
            Self::C2pcOutputMacMismatch(index) => {
                write!(f, "C2PC output MAC commitment mismatch at output {index}")
            }
            Self::C2pcOutputLabelMismatch(index) => {
                write!(f, "C2PC output label commitment mismatch at output {index}")
            }
            Self::C2pcLambdaMismatch(index) => {
                write!(f, "C2PC public mask mismatch at output {index}")
            }
            Self::CoinTossMismatch => write!(f, "Fpre coin-toss commitment mismatch"),
            Self::FeqMismatch => write!(f, "Fpre equality check mismatch"),
            Self::LengthOverflow(name) => write!(f, "{name} length overflow"),
            Self::MissingDelta(name) => write!(f, "{name} setup did not produce Delta"),
            Self::BadIknpSetupLength { name, len } => {
                write!(
                    f,
                    "IKNP setup field {name} must have length {IKNP_SECURITY_BITS}, got {len}"
                )
            }
            Self::IknpWrongRole(role) => write!(f, "IKNP state is not initialized for {role}"),
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

impl From<WireError> for CompatError {
    fn from(value: WireError) -> Self {
        Self::Wire(value)
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
            *block = self.permute_one(*block);
        }
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

struct CompatPhaseTiming {
    enabled: bool,
    role: Role,
    scope: &'static str,
    start: Instant,
    last: Instant,
}

impl CompatPhaseTiming {
    fn new(role: Role, scope: &'static str) -> Self {
        let now = Instant::now();
        Self {
            enabled: compat_timing_enabled(),
            role,
            scope,
            start: now,
            last: now,
        }
    }

    fn mark(&mut self, phase: &'static str) {
        if !self.enabled {
            return;
        }
        let now = Instant::now();
        let phase_ms = now.duration_since(self.last).as_secs_f64() * 1000.0;
        let total_ms = now.duration_since(self.start).as_secs_f64() * 1000.0;
        eprintln!(
            "TIMING compat role={} scope={} phase={} phase_ms={:.3} total_ms={:.3}",
            self.role.party_id(),
            self.scope,
            phase,
            phase_ms,
            total_ms
        );
        self.last = now;
    }
}

fn compat_timing_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        env::var("SHACHAIN2PC_COMPAT_TIMING")
            .map(|value| !value.is_empty() && value != "0")
            .unwrap_or(false)
    })
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
}

pub async fn otco_send(stream: &mut EmpStream, data0: &[Block], data1: &[Block]) -> Result<()> {
    if data0.len() != data1.len() {
        return Err(CompatError::BadOtLength {
            data0: data0.len(),
            data1: data1.len(),
        });
    }

    let group = P256::new()?;
    let a = group.random_scalar()?;
    let a_point = {
        let mut ctx = BigNumContext::new()?;
        group.mul_gen_bn(&a, &mut ctx)?
    };
    send_point(stream, &a_point).await?;
    stream.flush().await?;

    let aa = group.point_mul_bn(&a_point, &a)?;
    let aa_inv = group.point_inv(&aa)?;
    let mut masks = Vec::with_capacity(data0.len());
    for i in 0..data0.len() {
        let b_point = recv_point(stream).await?;
        let mask0_point = group.point_mul_bn(&b_point, &a)?;
        let mask1_point = group.point_add(&mask0_point, &aa_inv)?;
        masks.push((
            group.kdf(&mask0_point, i as u64)?,
            group.kdf(&mask1_point, i as u64)?,
        ));
    }
    stream.flush().await?;

    for i in 0..data0.len() {
        let pair = [masks[i].0.xor(data0[i]), masks[i].1.xor(data1[i])];
        stream.send_block(&pair).await?;
    }
    stream.flush().await?;
    Ok(())
}

pub async fn otco_recv(stream: &mut EmpStream, choices: &[bool]) -> Result<Vec<Block>> {
    let group = P256::new()?;
    let a_point = recv_point(stream).await?;
    let mut receiver_mask_points = Vec::with_capacity(choices.len());
    for choice in choices {
        let scalar = group.random_scalar()?;
        let mut b_point = {
            let mut ctx = BigNumContext::new()?;
            group.mul_gen_bn(&scalar, &mut ctx)?
        };
        if *choice {
            b_point = group.point_add(&b_point, &a_point)?;
        }
        send_point(stream, &b_point).await?;
        receiver_mask_points.push(group.point_mul_bn(&a_point, &scalar)?);
    }
    stream.flush().await?;

    let mut out = Vec::with_capacity(choices.len());
    for i in 0..choices.len() {
        let ciphertexts = stream.recv_block(2).await?;
        let mask = group.kdf(&receiver_mask_points[i], i as u64)?;
        out.push(mask.xor(if choices[i] {
            ciphertexts[1]
        } else {
            ciphertexts[0]
        }));
    }
    Ok(out)
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

struct IknpSendState {
    s: [bool; IKNP_SECURITY_BITS],
    delta: Block,
    g0: Vec<Prg>,
}

struct IknpRecvState {
    g0: Vec<Prg>,
    g1: Vec<Prg>,
}

impl Drop for IknpSendState {
    fn drop(&mut self) {
        self.s.fill(false);
        self.delta.zeroize();
        self.g0.clear();
    }
}

impl Drop for IknpRecvState {
    fn drop(&mut self) {
        self.g0.clear();
        self.g1.clear();
    }
}

pub struct Iknp {
    send: Option<IknpSendState>,
    recv: Option<IknpRecvState>,
}

impl Iknp {
    pub fn new() -> Self {
        Self {
            send: None,
            recv: None,
        }
    }

    pub fn delta(&self) -> Option<Block> {
        self.send.as_ref().map(|state| state.delta)
    }

    pub async fn setup_send(&mut self, stream: &mut EmpStream) -> Result<()> {
        let s = random_bools_array()?;
        self.setup_send_with_choices(stream, &s).await
    }

    pub async fn setup_send_with_choices(
        &mut self,
        stream: &mut EmpStream,
        s: &[bool],
    ) -> Result<()> {
        validate_iknp_len("s", s.len())?;
        let mut choices = [false; IKNP_SECURITY_BITS];
        choices.copy_from_slice(s);
        let k0 = otco_recv(stream, &choices).await?;
        self.set_send_state(&choices, &k0)
    }

    pub fn setup_send_from_base_ot(&mut self, s: &[bool], k0: &[Block]) -> Result<()> {
        validate_iknp_len("s", s.len())?;
        validate_iknp_len("k0", k0.len())?;
        let mut choices = [false; IKNP_SECURITY_BITS];
        choices.copy_from_slice(s);
        self.set_send_state(&choices, k0)
    }

    pub async fn setup_recv(&mut self, stream: &mut EmpStream) -> Result<()> {
        let k0 = random_blocks(IKNP_SECURITY_BITS)?;
        let k1 = random_blocks(IKNP_SECURITY_BITS)?;
        otco_send(stream, &k0, &k1).await?;
        self.setup_recv_from_base_ot(&k0, &k1)
    }

    pub fn setup_recv_from_base_ot(&mut self, k0: &[Block], k1: &[Block]) -> Result<()> {
        validate_iknp_len("k0", k0.len())?;
        validate_iknp_len("k1", k1.len())?;
        let g0 = k0.iter().copied().map(|seed| Prg::new(seed, 0)).collect();
        let g1 = k1.iter().copied().map(|seed| Prg::new(seed, 0)).collect();
        self.recv = Some(IknpRecvState { g0, g1 });
        Ok(())
    }

    pub async fn send_cot(&mut self, stream: &mut EmpStream, length: usize) -> Result<Vec<Block>> {
        if self.send.is_none() {
            self.setup_send(stream).await?;
        }
        let state = self
            .send
            .as_mut()
            .ok_or(CompatError::IknpWrongRole("send_cot"))?;
        send_pre(state, stream, length).await
    }

    pub async fn recv_cot(
        &mut self,
        stream: &mut EmpStream,
        choices: &[bool],
    ) -> Result<Vec<Block>> {
        if self.recv.is_none() {
            self.setup_recv(stream).await?;
        }
        let state = self
            .recv
            .as_mut()
            .ok_or(CompatError::IknpWrongRole("recv_cot"))?;
        recv_pre(state, stream, choices).await
    }

    fn set_send_state(&mut self, s: &[bool; IKNP_SECURITY_BITS], k0: &[Block]) -> Result<()> {
        validate_iknp_len("k0", k0.len())?;
        let delta = bool_to_block(s);
        let g0 = k0.iter().copied().map(|seed| Prg::new(seed, 0)).collect();
        self.send = Some(IknpSendState { s: *s, delta, g0 });
        Ok(())
    }
}

impl Default for Iknp {
    fn default() -> Self {
        Self::new()
    }
}

pub struct LeakyDeltaOt {
    iknp: Iknp,
}

impl LeakyDeltaOt {
    pub fn new() -> Self {
        Self { iknp: Iknp::new() }
    }

    pub fn delta(&self) -> Option<Block> {
        self.iknp.delta()
    }

    pub async fn setup_send_with_choices(
        &mut self,
        stream: &mut EmpStream,
        s: &[bool],
    ) -> Result<()> {
        self.iknp.setup_send_with_choices(stream, s).await
    }

    pub async fn setup_recv(&mut self, stream: &mut EmpStream) -> Result<()> {
        self.iknp.setup_recv(stream).await
    }

    pub async fn send_dot(&mut self, stream: &mut EmpStream, length: usize) -> Result<Vec<Block>> {
        let mut data = self.iknp.send_cot(stream, length).await?;
        stream.flush().await?;
        let one = leaky_delta_mask();
        for block in &mut data {
            *block = block.and(one);
        }
        Ok(data)
    }

    pub async fn recv_dot(&mut self, stream: &mut EmpStream, length: usize) -> Result<Vec<Block>> {
        let choices = random_bools(length)?;
        let mut data = self.iknp.recv_cot(stream, &choices).await?;
        stream.flush().await?;
        let one = leaky_delta_mask();
        for (block, choice) in data.iter_mut().zip(choices) {
            *block = block.and(one);
            if choice {
                *block = block.xor(Block::make(0, 1));
            }
        }
        Ok(data)
    }
}

impl Default for LeakyDeltaOt {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FpreParams {
    pub batch_size: usize,
    pub bucket_size: usize,
    pub permute_batch_size: Option<usize>,
}

impl FpreParams {
    pub fn for_size(size: usize) -> Self {
        let size = size.max(320);
        let batch_size = size.div_ceil(2 * FPRE_THREADS) * FPRE_THREADS * 2;
        if batch_size >= 280_000 {
            Self {
                batch_size,
                bucket_size: 3,
                permute_batch_size: Some(280_000),
            }
        } else if batch_size >= 3_100 {
            Self {
                batch_size,
                bucket_size: 4,
                permute_batch_size: Some(3_100),
            }
        } else {
            Self {
                batch_size,
                bucket_size: 5,
                permute_batch_size: None,
            }
        }
    }
}

pub struct Fpre {
    party: Role,
    abit1: LeakyDeltaOt,
    abit2: LeakyDeltaOt,
    delta: Block,
    z_delta: Block,
    params: FpreParams,
    eq: [Sha256; 2],
    coin_prg_seed: Block,
}

pub struct FpreGenerated {
    pub mac: Vec<Block>,
    pub key: Vec<Block>,
}

impl FpreGenerated {
    pub fn into_parts(mut self) -> (Vec<Block>, Vec<Block>) {
        (std::mem::take(&mut self.mac), std::mem::take(&mut self.key))
    }
}

impl Drop for FpreGenerated {
    fn drop(&mut self) {
        self.mac.zeroize();
        self.key.zeroize();
    }
}

impl Drop for Fpre {
    fn drop(&mut self) {
        self.delta.zeroize();
        self.z_delta.zeroize();
        self.coin_prg_seed.zeroize();
        self.eq = [Sha256::new(), Sha256::new()];
    }
}

impl Fpre {
    pub async fn setup(streams: &mut EmpStreams, party: Role, size: usize) -> Result<Self> {
        let mut abit1 = LeakyDeltaOt::new();
        let mut abit2 = LeakyDeltaOt::new();
        let mut tmp_s = random_bools_array()?;
        tmp_s[0] = true;

        let delta = match party {
            Role::Alice => {
                tmp_s[1] = true;
                abit1
                    .setup_send_with_choices(&mut streams.fpre_io0, &tmp_s)
                    .await?;
                streams.fpre_io0.flush().await?;
                abit2.setup_recv(&mut streams.fpre_io2_0).await?;
                streams.fpre_io2_0.flush().await?;
                abit1
                    .delta()
                    .ok_or(CompatError::MissingDelta("Fpre ALICE abit1"))?
            }
            Role::Bob => {
                tmp_s[1] = false;
                abit1.setup_recv(&mut streams.fpre_io0).await?;
                streams.fpre_io0.flush().await?;
                abit2
                    .setup_send_with_choices(&mut streams.fpre_io2_0, &tmp_s)
                    .await?;
                streams.fpre_io2_0.flush().await?;
                abit2
                    .delta()
                    .ok_or(CompatError::MissingDelta("Fpre BOB abit2"))?
            }
        };

        Ok(Self {
            party,
            abit1,
            abit2,
            delta,
            z_delta: delta.and(leaky_delta_mask()),
            params: FpreParams::for_size(size),
            eq: [Sha256::new(), Sha256::new()],
            coin_prg_seed: random_block()?,
        })
    }

    pub fn party(&self) -> Role {
        self.party
    }

    pub fn delta(&self) -> Block {
        self.delta
    }

    pub fn z_delta(&self) -> Block {
        self.z_delta
    }

    pub fn params(&self) -> FpreParams {
        self.params
    }

    pub fn leaky_instances_ready(&self) -> bool {
        (self.abit1.iknp.send.is_some() || self.abit1.iknp.recv.is_some())
            && (self.abit2.iknp.send.is_some() || self.abit2.iknp.recv.is_some())
    }

    pub async fn generate(
        &mut self,
        streams: &mut EmpStreams,
        length: usize,
    ) -> Result<FpreGenerated> {
        let dot_length = length
            .checked_mul(3)
            .ok_or(CompatError::LengthOverflow("Fpre generate"))?;
        let (key, mac) = match self.party {
            Role::Alice => {
                let (key, mac) = tokio::try_join!(
                    self.abit1.send_dot(&mut streams.fpre_io0, dot_length),
                    self.abit2.recv_dot(&mut streams.fpre_io2_0, dot_length)
                )?;
                (key, mac)
            }
            Role::Bob => {
                let (key, mac) = tokio::try_join!(
                    self.abit2.send_dot(&mut streams.fpre_io2_0, dot_length),
                    self.abit1.recv_dot(&mut streams.fpre_io0, dot_length)
                )?;
                (key, mac)
            }
        };
        Ok(FpreGenerated { mac, key })
    }

    pub async fn check(
        &mut self,
        streams: &mut EmpStreams,
        generated: &mut FpreGenerated,
        length: usize,
        index: usize,
    ) -> Result<()> {
        let expected = length
            .checked_mul(3)
            .ok_or(CompatError::LengthOverflow("Fpre check"))?;
        if generated.mac.len() != expected || generated.key.len() != expected {
            return Err(CompatError::BadFpreGeneratedLength {
                expected,
                mac: generated.mac.len(),
                key: generated.key.len(),
            });
        }
        self.check_slices(
            streams,
            &mut generated.mac,
            &mut generated.key,
            length,
            index,
        )
        .await
    }

    async fn check_slices(
        &mut self,
        streams: &mut EmpStreams,
        mac: &mut [Block],
        key: &mut [Block],
        length: usize,
        index: usize,
    ) -> Result<()> {
        let expected = length
            .checked_mul(3)
            .ok_or(CompatError::LengthOverflow("Fpre check"))?;
        if mac.len() != expected || key.len() != expected {
            return Err(CompatError::BadFpreGeneratedLength {
                expected,
                mac: mac.len(),
                key: key.len(),
            });
        }
        let stream = match index {
            0 => &mut streams.fpre_io0,
            1 => &mut streams.fpre_io2_0,
            _ => return Err(CompatError::BadFpreCheckIndex(index)),
        };
        let ctx = FpreCheckContext {
            party: self.party,
            delta: self.delta,
            z_delta: self.z_delta,
            eq: &mut self.eq[index],
            stream,
            index,
        };
        fpre_check_on_stream(ctx, mac, key, length).await
    }

    pub fn check_digest(&self, index: usize) -> Result<[u8; HASH_DIGEST_BYTES]> {
        let digest = self
            .eq
            .get(index)
            .ok_or(CompatError::BadFpreCheckIndex(index))?
            .clone()
            .finalize();
        Ok(digest.into())
    }

    pub async fn refill(&mut self, streams: &mut EmpStreams) -> Result<FpreGenerated> {
        self.refill_inner(streams, false).await
    }

    async fn refill_inner(
        &mut self,
        streams: &mut EmpStreams,
        tamper_eq_for_test: bool,
    ) -> Result<FpreGenerated> {
        let mut timing = CompatPhaseTiming::new(self.party, "fpre_refill");
        let raw_length = self
            .params
            .batch_size
            .checked_mul(self.params.bucket_size)
            .ok_or(CompatError::LengthOverflow("Fpre refill raw length"))?;
        let mut raw = self.generate(streams, raw_length).await?;
        timing.mark("generate");

        let half_batch = self.params.batch_size / 2;
        let check_length = half_batch
            .checked_mul(self.params.bucket_size)
            .ok_or(CompatError::LengthOverflow("Fpre refill check length"))?;
        let check_blocks = check_length
            .checked_mul(3)
            .ok_or(CompatError::LengthOverflow("Fpre refill check blocks"))?;

        let (mac0, mac1) = raw.mac.split_at_mut(check_blocks);
        let (key0, key1) = raw.key.split_at_mut(check_blocks);
        let (eq0, eq1) = self.eq.split_at_mut(1);
        let ctx0 = FpreCheckContext {
            party: self.party,
            delta: self.delta,
            z_delta: self.z_delta,
            eq: &mut eq0[0],
            stream: &mut streams.fpre_io0,
            index: 0,
        };
        let ctx1 = FpreCheckContext {
            party: self.party,
            delta: self.delta,
            z_delta: self.z_delta,
            eq: &mut eq1[0],
            stream: &mut streams.fpre_io2_0,
            index: 1,
        };
        tokio::try_join!(
            fpre_check_on_stream(ctx0, mac0, key0, check_length),
            fpre_check_on_stream(ctx1, mac1, key1, check_length)
        )?;
        timing.mark("check");

        let seed = coin_tossing(self.coin_prg_seed, &mut streams.fpre_io0, self.party).await?;
        timing.mark("coin_toss");
        let combined = self.combine(seed, streams, &raw).await?;
        timing.mark("combine");
        self.fold_eq_digests();
        if tamper_eq_for_test {
            self.eq[0].update(b"shachain2pc test tamper");
        }
        self.feq_compare(&mut streams.fpre_io0).await?;
        timing.mark("feq_compare");
        Ok(combined)
    }

    async fn combine(
        &self,
        seed: Block,
        streams: &mut EmpStreams,
        raw: &FpreGenerated,
    ) -> Result<FpreGenerated> {
        let length = if self.params.bucket_size > 4 {
            self.params.batch_size
        } else {
            self.params.batch_size.min(
                self.params
                    .permute_batch_size
                    .unwrap_or(self.params.batch_size),
            )
        };
        fpre_combine(
            FpreCombineContext {
                seed,
                index: 0,
                party: self.party,
                stream: &mut streams.fpre_io0,
            },
            &raw.mac,
            &raw.key,
            length,
            self.params.bucket_size,
        )
        .await
    }

    fn fold_eq_digests(&mut self) {
        for i in 1..self.eq.len() {
            let digest = digest_and_reset(&mut self.eq[i]);
            self.eq[0].update(digest);
        }
    }

    async fn feq_compare(&mut self, stream: &mut EmpStream) -> Result<()> {
        let local_digest = digest_and_reset(&mut self.eq[0]);
        let ok = feq_compare(stream, self.party, local_digest).await?;
        if ok {
            Ok(())
        } else {
            Err(CompatError::FeqMismatch)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct C2pcCircuit {
    num_wire: usize,
    n1: usize,
    n2: usize,
    n3: usize,
    gates: Vec<C2pcGate>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct C2pcGate {
    typ: C2pcGateType,
    in0: usize,
    in1: usize,
    out: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum C2pcGateType {
    And,
    Xor,
    Inv,
}

impl C2pcCircuit {
    pub fn from_circuit(circuit: &Circuit) -> Result<Self> {
        let num_wire = checked_nonnegative("num_wire", circuit.num_wire)?;
        let n1 = checked_nonnegative("n1", circuit.n1)?;
        let n2 = checked_nonnegative("n2", circuit.n2)?;
        let n3 = checked_nonnegative("n3", circuit.n3)?;
        if num_wire == 0 || n1 + n2 > num_wire || n3 > num_wire {
            return Err(CompatError::BadC2pcCircuit(
                "inconsistent circuit header".to_owned(),
            ));
        }

        let mut gates = Vec::with_capacity(circuit.gates.len());
        for gate in &circuit.gates {
            let typ = match gate.typ {
                GateType::And => C2pcGateType::And,
                GateType::Xor => C2pcGateType::Xor,
                GateType::Inv => C2pcGateType::Inv,
            };
            let in0 = checked_wire("in0", gate.in0, num_wire)?;
            let in1 = if typ == C2pcGateType::Inv {
                0
            } else {
                checked_wire("in1", gate.in1, num_wire)?
            };
            let out = checked_wire("out", gate.out, num_wire)?;
            gates.push(C2pcGate { typ, in0, in1, out });
        }

        Ok(Self {
            num_wire,
            n1,
            n2,
            n3,
            gates,
        })
    }

    pub fn input_len(&self) -> usize {
        self.n1 + self.n2
    }

    pub fn num_wire(&self) -> usize {
        self.num_wire
    }

    pub fn output_len(&self) -> usize {
        self.n3
    }

    pub fn num_ands(&self) -> usize {
        self.gates
            .iter()
            .filter(|gate| gate.typ == C2pcGateType::And)
            .count()
    }

    pub fn total_pre(&self) -> usize {
        self.input_len() + self.num_ands()
    }
}

pub struct C2pc {
    party: Role,
    circuit: C2pcCircuit,
    fpre: Fpre,
    mac: Vec<Block>,
    key: Vec<Block>,
    preprocess_mac: Vec<Block>,
    preprocess_key: Vec<Block>,
    ands_mac: Vec<Block>,
    ands_key: Vec<Block>,
    sigma_mac: Vec<Block>,
    sigma_key: Vec<Block>,
    gt: Vec<[[Block; 2]; 4]>,
    gtk: Vec<[Block; 4]>,
    gtm: Vec<[Block; 4]>,
    labels: Vec<Block>,
    mask: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedBits {
    mac: Vec<Block>,
    key: Vec<Block>,
    lambda: Vec<u8>,
    label: Vec<Block>,
}

impl AuthenticatedBits {
    pub fn len(&self) -> usize {
        self.lambda.len()
    }

    pub fn is_empty(&self) -> bool {
        self.lambda.is_empty()
    }

    pub fn lambda(&self) -> &[u8] {
        &self.lambda
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
            mac: self.mac[start..end].to_vec(),
            key: self.key[start..end].to_vec(),
            lambda: self.lambda[start..end].to_vec(),
            label: self.label[start..end].to_vec(),
        })
    }
}

impl Drop for AuthenticatedBits {
    fn drop(&mut self) {
        self.mac.zeroize();
        self.key.zeroize();
        self.lambda.zeroize();
        self.label.zeroize();
    }
}

impl C2pc {
    pub async fn new(streams: &mut EmpStreams, party: Role, circuit: C2pcCircuit) -> Result<Self> {
        Self::new_with_setup_size(streams, party, circuit.clone(), circuit.num_ands()).await
    }

    pub async fn new_with_setup_size(
        streams: &mut EmpStreams,
        party: Role,
        circuit: C2pcCircuit,
        setup_num_ands: usize,
    ) -> Result<Self> {
        let fpre = Fpre::setup(streams, party, c2pc_fpre_setup_size(setup_num_ands)).await?;
        Ok(Self::from_fpre(party, circuit, fpre))
    }

    fn from_fpre(party: Role, circuit: C2pcCircuit, fpre: Fpre) -> Self {
        let num_ands = circuit.num_ands();
        let total_pre = circuit.total_pre();
        Self {
            party,
            mac: vec![Block::zero(); circuit.num_wire],
            key: vec![Block::zero(); circuit.num_wire],
            preprocess_mac: vec![Block::zero(); total_pre],
            preprocess_key: vec![Block::zero(); total_pre],
            ands_mac: vec![Block::zero(); num_ands * 3],
            ands_key: vec![Block::zero(); num_ands * 3],
            sigma_mac: vec![Block::zero(); num_ands],
            sigma_key: vec![Block::zero(); num_ands],
            gt: vec![[[Block::zero(); 2]; 4]; num_ands],
            gtk: vec![[Block::zero(); 4]; num_ands],
            gtm: vec![[Block::zero(); 4]; num_ands],
            labels: vec![Block::zero(); circuit.num_wire],
            mask: vec![0; circuit.input_len()],
            circuit,
            fpre,
        }
    }

    pub fn reset_circuit(&mut self, circuit: C2pcCircuit) {
        let num_ands = circuit.num_ands();
        let total_pre = circuit.total_pre();
        self.mac = vec![Block::zero(); circuit.num_wire];
        self.key = vec![Block::zero(); circuit.num_wire];
        self.preprocess_mac = vec![Block::zero(); total_pre];
        self.preprocess_key = vec![Block::zero(); total_pre];
        self.ands_mac = vec![Block::zero(); num_ands * 3];
        self.ands_key = vec![Block::zero(); num_ands * 3];
        self.sigma_mac = vec![Block::zero(); num_ands];
        self.sigma_key = vec![Block::zero(); num_ands];
        self.gt = vec![[[Block::zero(); 2]; 4]; num_ands];
        self.gtk = vec![[Block::zero(); 4]; num_ands];
        self.gtm = vec![[Block::zero(); 4]; num_ands];
        self.labels = vec![Block::zero(); circuit.num_wire];
        self.mask = vec![0; circuit.input_len()];
        self.circuit = circuit;
    }

    pub async fn function_independent(&mut self, streams: &mut EmpStreams) -> Result<()> {
        let mut timing = CompatPhaseTiming::new(self.party, "function_independent");
        if self.party == Role::Alice {
            self.labels = random_blocks(self.circuit.num_wire)?;
        }
        timing.mark("random_labels");

        self.ands_mac.clear();
        self.ands_key.clear();
        let ands_len = self.ands_block_len();
        if ands_len != 0 {
            while self.ands_mac.len() < ands_len {
                let (mut batch_mac, mut batch_key) = self.fpre.refill(streams).await?.into_parts();
                let take = (ands_len - self.ands_mac.len()).min(batch_mac.len());
                self.ands_mac.extend_from_slice(&batch_mac[..take]);
                self.ands_key.extend_from_slice(&batch_key[..take]);
                batch_mac.zeroize();
                batch_key.zeroize();
            }
        }
        timing.mark("fpre_refill");

        let total_pre = self.circuit.total_pre();
        let (preprocess_key, preprocess_mac) = match self.party {
            Role::Alice => {
                let key = self
                    .fpre
                    .abit1
                    .send_dot(&mut streams.fpre_io0, total_pre)
                    .await?;
                let mac = self
                    .fpre
                    .abit2
                    .recv_dot(&mut streams.fpre_io2_0, total_pre)
                    .await?;
                (key, mac)
            }
            Role::Bob => {
                let mac = self
                    .fpre
                    .abit1
                    .recv_dot(&mut streams.fpre_io0, total_pre)
                    .await?;
                let key = self
                    .fpre
                    .abit2
                    .send_dot(&mut streams.fpre_io2_0, total_pre)
                    .await?;
                (key, mac)
            }
        };
        self.preprocess_key = preprocess_key;
        self.preprocess_mac = preprocess_mac;

        let input_len = self.circuit.input_len();
        self.key[..input_len].copy_from_slice(&self.preprocess_key[..input_len]);
        self.mac[..input_len].copy_from_slice(&self.preprocess_mac[..input_len]);
        timing.mark("preprocess_dot");
        Ok(())
    }

    pub fn apply_carried_inputs(&mut self, carried: &AuthenticatedBits) -> Result<()> {
        let input_len = self.circuit.input_len();
        if carried.len() != input_len {
            return Err(CompatError::BadC2pcInputLength {
                expected: input_len,
                actual: carried.len(),
            });
        }
        self.mac[..input_len].copy_from_slice(&carried.mac);
        self.key[..input_len].copy_from_slice(&carried.key);
        self.labels[..input_len].copy_from_slice(&carried.label);
        Ok(())
    }

    pub async fn function_dependent(&mut self, streams: &mut EmpStreams) -> Result<()> {
        self.function_dependent_inner(streams, true).await
    }

    pub async fn function_dependent_carried(&mut self, streams: &mut EmpStreams) -> Result<()> {
        self.function_dependent_inner(streams, false).await
    }

    async fn function_dependent_inner(
        &mut self,
        streams: &mut EmpStreams,
        commit_input_masks: bool,
    ) -> Result<()> {
        let input_len = self.circuit.input_len();
        let mut pre_index = input_len;
        for gate in &self.circuit.gates {
            if gate.typ == C2pcGateType::And {
                self.key[gate.out] = self.preprocess_key[pre_index];
                self.mac[gate.out] = self.preprocess_mac[pre_index];
                pre_index += 1;
            }
        }

        for gate in &self.circuit.gates {
            match gate.typ {
                C2pcGateType::Xor => {
                    self.key[gate.out] = self.key[gate.in0].xor(self.key[gate.in1]);
                    self.mac[gate.out] = self.mac[gate.in0].xor(self.mac[gate.in1]);
                    if self.party == Role::Alice {
                        self.labels[gate.out] = self.labels[gate.in0].xor(self.labels[gate.in1]);
                    }
                }
                C2pcGateType::Inv => {
                    self.key[gate.out] = self.key[gate.in0];
                    self.mac[gate.out] = self.mac[gate.in0];
                    if self.party == Role::Alice {
                        self.labels[gate.out] = self.labels[gate.in0].xor(self.fpre.delta);
                    }
                }
                C2pcGateType::And => {}
            }
        }

        let num_ands = self.circuit.num_ands();
        let mut x = Vec::with_capacity(num_ands);
        let mut y = Vec::with_capacity(num_ands);
        let mut and_index = 0;
        for gate in &self.circuit.gates {
            if gate.typ == C2pcGateType::And {
                x.push(u8::from(
                    self.mac[gate.in0]
                        .xor(self.ands_mac[3 * and_index])
                        .get_lsb(),
                ));
                y.push(u8::from(
                    self.mac[gate.in1]
                        .xor(self.ands_mac[3 * and_index + 1])
                        .get_lsb(),
                ));
                and_index += 1;
            }
        }

        let (xr, yr) = match self.party {
            Role::Alice => {
                streams.main.send_bool_bytes(&x, 0).await?;
                streams.main.send_bool_bytes(&y, 0).await?;
                let xr = streams.main.recv_bool_bytes(num_ands, 0).await?;
                let yr = streams.main.recv_bool_bytes(num_ands, 0).await?;
                (xr, yr)
            }
            Role::Bob => {
                let xr = streams.main.recv_bool_bytes(num_ands, 0).await?;
                let yr = streams.main.recv_bool_bytes(num_ands, 0).await?;
                streams.main.send_bool_bytes(&x, 0).await?;
                streams.main.send_bool_bytes(&y, 0).await?;
                (xr, yr)
            }
        };
        streams.main.flush().await?;

        for i in 0..num_ands {
            let x_i = (x[i] != 0) != (xr[i] != 0);
            let y_i = (y[i] != 0) != (yr[i] != 0);
            self.sigma_mac[i] = self.ands_mac[3 * i + 2];
            self.sigma_key[i] = self.ands_key[3 * i + 2];
            if x_i {
                self.sigma_mac[i] = self.sigma_mac[i].xor(self.ands_mac[3 * i + 1]);
                self.sigma_key[i] = self.sigma_key[i].xor(self.ands_key[3 * i + 1]);
            }
            if y_i {
                self.sigma_mac[i] = self.sigma_mac[i].xor(self.ands_mac[3 * i]);
                self.sigma_key[i] = self.sigma_key[i].xor(self.ands_key[3 * i]);
            }
            if x_i && y_i {
                match self.party {
                    Role::Alice => {
                        self.sigma_key[i] = self.sigma_key[i].xor(self.fpre.z_delta);
                    }
                    Role::Bob => {
                        self.sigma_mac[i] = self.sigma_mac[i].xor(Block::make(0, 1));
                    }
                }
            }
        }

        let table_len = num_ands
            .checked_mul(4)
            .and_then(|n| n.checked_mul(C2PC_SSP_BYTES + BLOCK_BYTES))
            .ok_or(CompatError::LengthOverflow("C2PC garbled table wire"))?;
        match self.party {
            Role::Alice => {
                let mut wire = Vec::with_capacity(table_len);
                and_index = 0;
                for (gate_index, gate) in self.circuit.gates.iter().enumerate() {
                    if gate.typ == C2pcGateType::And {
                        let (m, k) = self.and_row_masks(gate, and_index);
                        let rows = self.alice_garbled_rows(gate, gate_index, and_index, &m, &k);
                        for row in rows {
                            wire.extend_from_slice(&row[0].as_bytes()[..C2PC_SSP_BYTES]);
                            wire.extend_from_slice(row[1].as_bytes());
                        }
                        and_index += 1;
                    }
                }
                streams.main.send_data(&wire).await?;
                wire.zeroize();
            }
            Role::Bob => {
                let mut wire = streams.main.recv_data(table_len).await?;
                let mut pos = 0;
                and_index = 0;
                for gate in &self.circuit.gates {
                    if gate.typ == C2pcGateType::And {
                        let (m, k) = self.and_row_masks(gate, and_index);
                        self.gtm[and_index] = m;
                        self.gtk[and_index] = k;
                        for row in 0..4 {
                            let mut row0 = [0u8; BLOCK_BYTES];
                            row0[..C2PC_SSP_BYTES]
                                .copy_from_slice(&wire[pos..pos + C2PC_SSP_BYTES]);
                            pos += C2PC_SSP_BYTES;
                            let row1 = wire[pos..pos + BLOCK_BYTES]
                                .try_into()
                                .expect("garbled row block length");
                            pos += BLOCK_BYTES;
                            self.gt[and_index][row][0] = Block::from_bytes(row0);
                            self.gt[and_index][row][1] = Block::from_bytes(row1);
                        }
                        and_index += 1;
                    }
                }
                debug_assert_eq!(pos, wire.len());
                wire.zeroize();
            }
        }

        if commit_input_masks {
            match self.party {
                Role::Alice => {
                    streams
                        .main
                        .send_partial_blocks(&self.mac[..self.circuit.n1], C2PC_SSP_BYTES)
                        .await?;
                    for i in self.circuit.n1..input_len {
                        let received =
                            streams.main.recv_partial_blocks(1, C2PC_SSP_BYTES).await?[0];
                        self.mask[i] = self.resolve_mask(i, received)?;
                    }
                }
                Role::Bob => {
                    for i in 0..self.circuit.n1 {
                        let received =
                            streams.main.recv_partial_blocks(1, C2PC_SSP_BYTES).await?[0];
                        self.mask[i] = self.resolve_mask(i, received)?;
                    }
                    streams
                        .main
                        .send_partial_blocks(&self.mac[self.circuit.n1..input_len], C2PC_SSP_BYTES)
                        .await?;
                }
            }
            streams.main.flush().await?;
        }
        Ok(())
    }

    pub async fn online(
        &mut self,
        streams: &mut EmpStreams,
        input: &[u8],
        alice_output: bool,
    ) -> Result<Vec<u8>> {
        let input_len = self.circuit.input_len();
        if input.len() != input_len {
            return Err(CompatError::BadC2pcInputLength {
                expected: input_len,
                actual: input.len(),
            });
        }

        let mut mask_input = vec![0u8; self.circuit.num_wire];
        match self.party {
            Role::Alice => {
                for i in self.circuit.n1..input_len {
                    mask_input[i] = u8::from((input[i] != 0) != self.mac[i].get_lsb());
                    mask_input[i] ^= self.mask[i];
                }
                let bob_mask = streams.main.recv_data(self.circuit.n1).await?;
                mask_input[..self.circuit.n1].copy_from_slice(&bob_mask);
                streams
                    .main
                    .send_data(&mask_input[self.circuit.n1..input_len])
                    .await?;

                for (i, bit) in mask_input.iter().copied().enumerate().take(input_len) {
                    let mut label = self.labels[i];
                    if Self::mask_bit(bit, i)? != 0 {
                        label = label.xor(self.fpre.delta);
                    }
                    streams.main.send_block(&[label]).await?;
                }

                let out_start = self.output_start();
                streams
                    .main
                    .send_partial_blocks(&self.mac[out_start..], C2PC_SSP_BYTES)
                    .await?;
            }
            Role::Bob => {
                for i in 0..self.circuit.n1 {
                    mask_input[i] = u8::from((input[i] != 0) != self.mac[i].get_lsb());
                    mask_input[i] ^= self.mask[i];
                }
                streams
                    .main
                    .send_data(&mask_input[..self.circuit.n1])
                    .await?;
                let alice_mask = streams.main.recv_data(self.circuit.n2).await?;
                mask_input[self.circuit.n1..input_len].copy_from_slice(&alice_mask);
                let input_labels = streams.main.recv_block(input_len).await?;
                self.labels[..input_len].copy_from_slice(&input_labels);
            }
        }

        if self.party == Role::Bob {
            self.evaluate_garbled_circuit(&mut mask_input)?;
        }

        let mut output = vec![0u8; self.circuit.n3];
        match self.party {
            Role::Bob => {
                let out_start = self.output_start();
                let output_macs = streams
                    .main
                    .recv_partial_blocks(self.circuit.n3, C2PC_SSP_BYTES)
                    .await?;
                for (i, received) in output_macs.iter().copied().enumerate() {
                    let wire = out_start + i;
                    let bit = self.resolve_online_output_bit(i, wire, received)?;
                    output[i] = bit
                        ^ Self::mask_bit(mask_input[wire], wire)?
                        ^ u8::from(self.mac[wire].get_lsb());
                }
                if alice_output {
                    streams
                        .main
                        .send_partial_blocks(&self.mac[out_start..], C2PC_SSP_BYTES)
                        .await?;
                    streams
                        .main
                        .send_partial_blocks(&self.labels[out_start..], C2PC_SSP_BYTES)
                        .await?;
                    streams
                        .main
                        .send_data(&mask_input[out_start..out_start + self.circuit.n3])
                        .await?;
                    streams.main.flush().await?;
                }
            }
            Role::Alice => {
                if alice_output {
                    let out_start = self.output_start();
                    let output_macs = streams
                        .main
                        .recv_partial_blocks(self.circuit.n3, C2PC_SSP_BYTES)
                        .await?;
                    let output_labels = streams
                        .main
                        .recv_partial_blocks(self.circuit.n3, C2PC_SSP_BYTES)
                        .await?;
                    let output_masks = streams.main.recv_data(self.circuit.n3).await?;
                    streams.main.flush().await?;
                    for i in 0..self.circuit.n3 {
                        let wire = out_start + i;
                        let bit = self.resolve_online_output_bit(i, wire, output_macs[i])?;
                        let mut label = output_labels[i];
                        let output_mask = Self::mask_bit(output_masks[i], wire)?;
                        if output_mask != 0 {
                            label = label.xor(self.fpre.delta);
                        }
                        let label = label.and(c2pc_mask());
                        let expected = self.labels[wire].and(c2pc_mask());
                        if label != expected {
                            return Err(CompatError::C2pcOutputLabelMismatch(i));
                        }
                        output[i] = bit ^ output_mask ^ u8::from(self.mac[wire].get_lsb());
                    }
                }
            }
        }
        Ok(output)
    }

    pub async fn online_authenticated_clear(
        &mut self,
        streams: &mut EmpStreams,
        input: &[u8],
    ) -> Result<AuthenticatedBits> {
        let input_len = self.circuit.input_len();
        if input.len() != input_len {
            return Err(CompatError::BadC2pcInputLength {
                expected: input_len,
                actual: input.len(),
            });
        }

        let mut mask_input = vec![0u8; self.circuit.num_wire];
        match self.party {
            Role::Alice => {
                for i in self.circuit.n1..input_len {
                    mask_input[i] = u8::from((input[i] != 0) != self.mac[i].get_lsb());
                    mask_input[i] ^= self.mask[i];
                }
                let bob_mask = streams.main.recv_data(self.circuit.n1).await?;
                mask_input[..self.circuit.n1].copy_from_slice(&bob_mask);
                streams
                    .main
                    .send_data(&mask_input[self.circuit.n1..input_len])
                    .await?;

                for (i, bit) in mask_input.iter().copied().enumerate().take(input_len) {
                    let mut label = self.labels[i];
                    if Self::mask_bit(bit, i)? != 0 {
                        label = label.xor(self.fpre.delta);
                    }
                    streams.main.send_block(&[label]).await?;
                }
            }
            Role::Bob => {
                for i in 0..self.circuit.n1 {
                    mask_input[i] = u8::from((input[i] != 0) != self.mac[i].get_lsb());
                    mask_input[i] ^= self.mask[i];
                }
                streams
                    .main
                    .send_data(&mask_input[..self.circuit.n1])
                    .await?;
                let alice_mask = streams.main.recv_data(self.circuit.n2).await?;
                mask_input[self.circuit.n1..input_len].copy_from_slice(&alice_mask);
                let input_labels = streams.main.recv_block(input_len).await?;
                self.labels[..input_len].copy_from_slice(&input_labels);
            }
        }

        if self.party == Role::Bob {
            self.evaluate_garbled_circuit(&mut mask_input)?;
        }
        self.authenticated_output_from_mask(streams, &mask_input)
            .await
    }

    pub async fn online_authenticated_carried(
        &mut self,
        streams: &mut EmpStreams,
        carried: &AuthenticatedBits,
    ) -> Result<AuthenticatedBits> {
        let input_len = self.circuit.input_len();
        if carried.len() != input_len {
            return Err(CompatError::BadC2pcInputLength {
                expected: input_len,
                actual: carried.len(),
            });
        }

        let mut mask_input = vec![0u8; self.circuit.num_wire];
        mask_input[..input_len].copy_from_slice(&carried.lambda);
        if self.party == Role::Bob {
            self.labels[..input_len].copy_from_slice(&carried.label);
            self.evaluate_garbled_circuit(&mut mask_input)?;
        }
        self.authenticated_output_from_mask(streams, &mask_input)
            .await
    }

    pub async fn reveal_authenticated_public(
        &self,
        streams: &mut EmpStreams,
        wires: &AuthenticatedBits,
    ) -> Result<Vec<u8>> {
        let n = wires.len();
        let mut output = vec![0u8; n];
        match self.party {
            Role::Alice => {
                streams
                    .main
                    .send_partial_blocks(&wires.mac, C2PC_SSP_BYTES)
                    .await?;
                let peer_macs = streams.main.recv_partial_blocks(n, C2PC_SSP_BYTES).await?;
                let peer_labels = streams.main.recv_partial_blocks(n, C2PC_SSP_BYTES).await?;
                let peer_lambda = streams.main.recv_data(n).await?;
                streams.main.flush().await?;
                for i in 0..n {
                    let peer_bit =
                        Self::resolve_key_bit(&wires.key[i], self.fpre.delta, peer_macs[i], i)?;
                    let lambda = Self::mask_bit(peer_lambda[i], i)?;
                    if lambda != wires.lambda[i] {
                        return Err(CompatError::C2pcLambdaMismatch(i));
                    }
                    self.verify_peer_label(i, wires, peer_labels[i], lambda)?;
                    output[i] = peer_bit ^ lambda ^ u8::from(wires.mac[i].get_lsb());
                }
            }
            Role::Bob => {
                let peer_macs = streams.main.recv_partial_blocks(n, C2PC_SSP_BYTES).await?;
                for (i, received) in peer_macs.iter().copied().enumerate() {
                    let peer_bit =
                        Self::resolve_key_bit(&wires.key[i], self.fpre.delta, received, i)?;
                    let lambda = Self::mask_bit(wires.lambda[i], i)?;
                    output[i] = peer_bit ^ lambda ^ u8::from(wires.mac[i].get_lsb());
                }
                streams
                    .main
                    .send_partial_blocks(&wires.mac, C2PC_SSP_BYTES)
                    .await?;
                streams
                    .main
                    .send_partial_blocks(&wires.label, C2PC_SSP_BYTES)
                    .await?;
                streams.main.send_data(&wires.lambda).await?;
                streams.main.flush().await?;
            }
        }
        Ok(output)
    }

    pub fn party(&self) -> Role {
        self.party
    }

    pub fn delta(&self) -> Block {
        self.fpre.delta()
    }

    pub fn circuit(&self) -> &C2pcCircuit {
        &self.circuit
    }

    pub fn input_mac(&self) -> &[Block] {
        &self.mac[..self.circuit.input_len()]
    }

    pub fn input_key(&self) -> &[Block] {
        &self.key[..self.circuit.input_len()]
    }

    pub fn wire_mac(&self) -> &[Block] {
        &self.mac
    }

    pub fn wire_key(&self) -> &[Block] {
        &self.key
    }

    pub fn preprocess_mac(&self) -> &[Block] {
        &self.preprocess_mac
    }

    pub fn preprocess_key(&self) -> &[Block] {
        &self.preprocess_key
    }

    pub fn ands_mac(&self) -> &[Block] {
        &self.ands_mac[..self.ands_block_len()]
    }

    pub fn ands_key(&self) -> &[Block] {
        &self.ands_key[..self.ands_block_len()]
    }

    pub fn sigma_mac(&self) -> &[Block] {
        &self.sigma_mac
    }

    pub fn sigma_key(&self) -> &[Block] {
        &self.sigma_key
    }

    pub fn garbled_table_wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.circuit.num_ands() * 4 * (C2PC_SSP_BYTES + 16));
        let mut and_index = 0;
        for (gate_index, gate) in self.circuit.gates.iter().enumerate() {
            if gate.typ == C2pcGateType::And {
                let rows = match self.party {
                    Role::Alice => {
                        let (m, k) = self.and_row_masks(gate, and_index);
                        self.alice_garbled_rows(gate, gate_index, and_index, &m, &k)
                    }
                    Role::Bob => self.gt[and_index],
                };
                for row in rows {
                    out.extend_from_slice(&row[0].as_bytes()[..C2PC_SSP_BYTES]);
                    out.extend_from_slice(row[1].as_bytes());
                }
                and_index += 1;
            }
        }
        out
    }

    fn ands_block_len(&self) -> usize {
        self.circuit.num_ands() * 3
    }

    fn output_start(&self) -> usize {
        self.circuit.num_wire - self.circuit.n3
    }

    fn mask_bit(value: u8, wire: usize) -> Result<u8> {
        match value {
            0 | 1 => Ok(value),
            _ => Err(CompatError::C2pcInvalidMaskBit { wire, value }),
        }
    }

    fn evaluate_garbled_circuit(&mut self, mask_input: &mut [u8]) -> Result<()> {
        let mut and_index = 0;
        for (gate_index, gate) in self.circuit.gates.iter().enumerate() {
            match gate.typ {
                C2pcGateType::Xor => {
                    self.labels[gate.out] = self.labels[gate.in0].xor(self.labels[gate.in1]);
                    mask_input[gate.out] = Self::mask_bit(mask_input[gate.in0], gate.in0)?
                        ^ Self::mask_bit(mask_input[gate.in1], gate.in1)?;
                }
                C2pcGateType::Inv => {
                    mask_input[gate.out] =
                        u8::from(Self::mask_bit(mask_input[gate.in0], gate.in0)? == 0);
                    self.labels[gate.out] = self.labels[gate.in0];
                }
                C2pcGateType::And => {
                    let row = 2 * usize::from(Self::mask_bit(mask_input[gate.in0], gate.in0)?)
                        + usize::from(Self::mask_bit(mask_input[gate.in1], gate.in1)?);
                    let hash = garble_hash_online(
                        self.labels[gate.in0],
                        self.labels[gate.in1],
                        gate_index as u64,
                        row as u64,
                    );
                    let row0 = self.gt[and_index][row][0].xor(hash[0]).and(c2pc_mask());
                    let row1 = self.gt[and_index][row][1].xor(hash[1]);
                    let key = self.gtk[and_index][row].and(c2pc_mask());
                    let key_delta = self.gtk[and_index][row]
                        .xor(self.fpre.delta)
                        .and(c2pc_mask());
                    let mut bit = if row0 == key {
                        0
                    } else if row0 == key_delta {
                        1
                    } else {
                        return Err(CompatError::C2pcGarbledTableMismatch(and_index));
                    };
                    bit ^= u8::from(self.gtm[and_index][row].get_lsb());
                    mask_input[gate.out] = bit;
                    self.labels[gate.out] = row1.xor(self.gtm[and_index][row]);
                    and_index += 1;
                }
            }
        }
        Ok(())
    }

    fn and_row_masks(&self, gate: &C2pcGate, and_index: usize) -> ([Block; 4], [Block; 4]) {
        let mut m = [Block::zero(); 4];
        m[0] = self.sigma_mac[and_index].xor(self.mac[gate.out]);
        m[1] = m[0].xor(self.mac[gate.in0]);
        m[2] = m[0].xor(self.mac[gate.in1]);
        m[3] = m[1].xor(self.mac[gate.in1]);
        if self.party == Role::Bob {
            m[3] = m[3].xor(Block::make(0, 1));
        }

        let mut k = [Block::zero(); 4];
        k[0] = self.sigma_key[and_index].xor(self.key[gate.out]);
        k[1] = k[0].xor(self.key[gate.in0]);
        k[2] = k[0].xor(self.key[gate.in1]);
        k[3] = k[1].xor(self.key[gate.in1]);
        if self.party == Role::Alice {
            k[3] = k[3].xor(self.fpre.z_delta);
        }
        (m, k)
    }

    fn alice_garbled_rows(
        &self,
        gate: &C2pcGate,
        gate_index: usize,
        and_index: usize,
        m: &[Block; 4],
        k: &[Block; 4],
    ) -> [[Block; 2]; 4] {
        let mut rows = garble_hash_preprocess(
            self.labels[gate.in0],
            self.labels[gate.in1],
            self.fpre.delta,
            gate_index as u64,
        );
        for row in 0..4 {
            rows[row][0] = rows[row][0].xor(m[row]);
            rows[row][1] = rows[row][1].xor(k[row]).xor(self.labels[gate.out]);
            if m[row].get_lsb() {
                rows[row][1] = rows[row][1].xor(self.fpre.delta);
            }
        }
        debug_assert!(and_index < self.circuit.num_ands());
        rows
    }

    fn resolve_mask(&self, index: usize, received: Block) -> Result<u8> {
        let received = received.and(c2pc_mask());
        let key = self.key[index].and(c2pc_mask());
        let key_delta = self.key[index].xor(self.fpre.delta).and(c2pc_mask());
        if received == key {
            Ok(0)
        } else if received == key_delta {
            Ok(1)
        } else {
            Err(CompatError::C2pcMaskMismatch(index))
        }
    }

    fn resolve_online_output_bit(
        &self,
        output_index: usize,
        wire_index: usize,
        received: Block,
    ) -> Result<u8> {
        let received = received.and(c2pc_mask());
        let key = self.key[wire_index].and(c2pc_mask());
        let key_delta = self.key[wire_index].xor(self.fpre.delta).and(c2pc_mask());
        if received == key {
            Ok(0)
        } else if received == key_delta {
            Ok(1)
        } else {
            Err(CompatError::C2pcOutputMacMismatch(output_index))
        }
    }

    async fn authenticated_output_from_mask(
        &self,
        streams: &mut EmpStreams,
        mask_input: &[u8],
    ) -> Result<AuthenticatedBits> {
        let out_start = self.output_start();
        let out_end = out_start + self.circuit.n3;
        let lambda = match self.party {
            Role::Alice => {
                let peer_labels = streams
                    .main
                    .recv_partial_blocks(self.circuit.n3, C2PC_SSP_BYTES)
                    .await?;
                let peer_lambda = streams.main.recv_data(self.circuit.n3).await?;
                streams.main.flush().await?;
                for i in 0..self.circuit.n3 {
                    let lambda = Self::mask_bit(peer_lambda[i], out_start + i)?;
                    self.verify_output_label(i, out_start + i, peer_labels[i], lambda)?;
                }
                peer_lambda
            }
            Role::Bob => {
                let lambda = mask_input[out_start..out_end].to_vec();
                streams
                    .main
                    .send_partial_blocks(&self.labels[out_start..out_end], C2PC_SSP_BYTES)
                    .await?;
                streams.main.send_data(&lambda).await?;
                streams.main.flush().await?;
                lambda
            }
        };
        Ok(self.authenticated_bits_from_range(out_start, out_end, lambda))
    }

    fn authenticated_bits_from_range(
        &self,
        start: usize,
        end: usize,
        lambda: Vec<u8>,
    ) -> AuthenticatedBits {
        AuthenticatedBits {
            mac: self.mac[start..end].to_vec(),
            key: self.key[start..end].to_vec(),
            lambda,
            label: self.labels[start..end].to_vec(),
        }
    }

    fn verify_peer_label(
        &self,
        output_index: usize,
        wires: &AuthenticatedBits,
        received: Block,
        lambda: u8,
    ) -> Result<()> {
        let mut label = received;
        if lambda != 0 {
            label = label.xor(self.fpre.delta);
        }
        if label.and(c2pc_mask()) == wires.label[output_index].and(c2pc_mask()) {
            Ok(())
        } else {
            Err(CompatError::C2pcOutputLabelMismatch(output_index))
        }
    }

    fn verify_output_label(
        &self,
        output_index: usize,
        wire_index: usize,
        received: Block,
        lambda: u8,
    ) -> Result<()> {
        let mut label = received;
        if lambda != 0 {
            label = label.xor(self.fpre.delta);
        }
        if label.and(c2pc_mask()) == self.labels[wire_index].and(c2pc_mask()) {
            Ok(())
        } else {
            Err(CompatError::C2pcOutputLabelMismatch(output_index))
        }
    }

    fn resolve_key_bit(
        key: &Block,
        delta: Block,
        received: Block,
        output_index: usize,
    ) -> Result<u8> {
        let received = received.and(c2pc_mask());
        let key = key.and(c2pc_mask());
        let key_delta = key.xor(delta).and(c2pc_mask());
        if received == key {
            Ok(0)
        } else if received == key_delta {
            Ok(1)
        } else {
            Err(CompatError::C2pcOutputMacMismatch(output_index))
        }
    }
}

impl Drop for C2pc {
    fn drop(&mut self) {
        self.mac.zeroize();
        self.key.zeroize();
        self.preprocess_mac.zeroize();
        self.preprocess_key.zeroize();
        self.ands_mac.zeroize();
        self.ands_key.zeroize();
        self.sigma_mac.zeroize();
        self.sigma_key.zeroize();
        for gate in &mut self.gt {
            for row in gate {
                row[0].zeroize();
                row[1].zeroize();
            }
        }
        for gate in &mut self.gtk {
            gate.zeroize();
        }
        for gate in &mut self.gtm {
            gate.zeroize();
        }
        self.labels.zeroize();
        self.mask.zeroize();
    }
}

fn c2pc_fpre_setup_size(num_ands: usize) -> usize {
    let params = FpreParams::for_size(num_ands);
    // With fpre_threads=1, bucket-3/4 refill combines at most
    // permute_batch_size triples. Repeated C2PC refills should therefore size
    // the raw bucket to that usable output instead of regenerating a
    // num_ands-sized raw bucket for each chunk.
    if params.bucket_size <= 4 {
        params
            .permute_batch_size
            .map(|size| size.min(num_ands))
            .unwrap_or(num_ands)
    } else {
        num_ands
    }
}

fn checked_nonnegative(name: &'static str, value: i32) -> Result<usize> {
    if value < 0 {
        Err(CompatError::BadC2pcCircuit(format!(
            "{name} must be nonnegative"
        )))
    } else {
        Ok(value as usize)
    }
}

fn checked_wire(name: &'static str, wire: i32, num_wire: usize) -> Result<usize> {
    if wire < 0 || wire as usize >= num_wire {
        Err(CompatError::BadC2pcCircuit(format!(
            "{name} wire {wire} out of range 0..{num_wire}"
        )))
    } else {
        Ok(wire as usize)
    }
}

fn c2pc_mask() -> Block {
    Block::make(0, 0xFFFFF)
}

struct FpreCheckContext<'a> {
    party: Role,
    delta: Block,
    z_delta: Block,
    eq: &'a mut Sha256,
    stream: &'a mut EmpStream,
    index: usize,
}

struct FpreCombineContext<'a> {
    seed: Block,
    index: u64,
    party: Role,
    stream: &'a mut EmpStream,
}

async fn fpre_check_on_stream(
    ctx: FpreCheckContext<'_>,
    mac: &mut [Block],
    key: &mut [Block],
    length: usize,
) -> Result<()> {
    let mut g = Vec::with_capacity(length);
    let mut c = Vec::with_capacity(length);
    for i in 0..length {
        let mut c_i = key[3 * i + 1].xor(mac[3 * i + 1]);
        if mac[3 * i + 1].get_lsb() {
            c_i = c_i.xor(ctx.delta);
        }
        c.push(c_i);
        g.push(h2d(key[3 * i], ctx.delta, ctx.index).xor(c_i));
    }

    let gr = match ctx.party {
        Role::Alice => {
            ctx.stream.send_block(&g).await?;
            ctx.stream.recv_block(length).await?
        }
        Role::Bob => {
            let gr = ctx.stream.recv_block(length).await?;
            ctx.stream.send_block(&g).await?;
            gr
        }
    };
    ctx.stream.flush().await?;

    let mut d = Vec::with_capacity(length);
    for i in 0..length {
        let mut s = h2(mac[3 * i], key[3 * i], ctx.index)
            .xor(mac[3 * i + 2])
            .xor(key[3 * i + 2]);
        if mac[3 * i].get_lsb() {
            s = s.xor(gr[i].xor(c[i]));
        }
        g[i] = s;
        if mac[3 * i + 2].get_lsb() {
            g[i] = g[i].xor(ctx.delta);
        }
        d.push(u8::from(get_l2sb(g[i])));
    }

    let dr = match ctx.party {
        Role::Alice => {
            ctx.stream.send_bool_bytes(&d, 0).await?;
            ctx.stream.recv_bool_bytes(length, 0).await?
        }
        Role::Bob => {
            let dr = ctx.stream.recv_bool_bytes(length, 0).await?;
            ctx.stream.send_bool_bytes(&d, 0).await?;
            dr
        }
    };
    ctx.stream.flush().await?;

    for i in 0..length {
        if (d[i] != 0) != (dr[i] != 0) {
            match ctx.party {
                Role::Alice => {
                    mac[3 * i + 2] = mac[3 * i + 2].xor(Block::make(0, 1));
                }
                Role::Bob => {
                    key[3 * i + 2] = key[3 * i + 2].xor(ctx.z_delta);
                }
            }
            g[i] = g[i].xor(ctx.delta);
        }
        ctx.eq.update(g[i].as_bytes());
    }
    Ok(())
}

fn h2d(a: Block, b: Block, _index: usize) -> Block {
    let mut d = [a, a.xor(b)];
    zero_key_prp().permute_block(&mut d);
    d[0].xor(d[1]).xor(b)
}

fn h2(a: Block, b: Block, _index: usize) -> Block {
    let mut d = [a, b];
    zero_key_prp().permute_block(&mut d);
    d[0].xor(d[1]).xor(a).xor(b)
}

fn get_l2sb(block: Block) -> bool {
    ((block.as_bytes()[0] >> 1) & 1) == 1
}

async fn coin_tossing(seed: Block, stream: &mut EmpStream, party: Role) -> Result<Block> {
    let mut prg = Prg::new(seed, 0);
    let local = prg.random_block(1)[0];
    let remote = match party {
        Role::Alice => {
            let commitment = hash_once(local.as_bytes());
            stream.send_data(&commitment).await?;
            let remote = stream.recv_block(1).await?[0];
            stream.send_block(&[local]).await?;
            remote
        }
        Role::Bob => {
            let peer_commitment = stream.recv_data(HASH_DIGEST_BYTES).await?;
            stream.send_block(&[local]).await?;
            let remote = stream.recv_block(1).await?[0];
            let commitment = hash_once(remote.as_bytes());
            if peer_commitment != commitment {
                return Err(CompatError::CoinTossMismatch);
            }
            remote
        }
    };
    stream.flush().await?;
    Ok(local.xor(remote))
}

async fn fpre_combine(
    ctx: FpreCombineContext<'_>,
    mac: &[Block],
    key: &[Block],
    length: usize,
    bucket_size: usize,
) -> Result<FpreGenerated> {
    let raw_len = length
        .checked_mul(bucket_size)
        .ok_or(CompatError::LengthOverflow("Fpre combine raw length"))?;
    let expected = raw_len
        .checked_mul(3)
        .ok_or(CompatError::LengthOverflow("Fpre combine blocks"))?;
    if mac.len() < expected || key.len() < expected {
        return Err(CompatError::BadFpreGeneratedLength {
            expected,
            mac: mac.len(),
            key: key.len(),
        });
    }

    let location = fpre_permutation(ctx.seed, ctx.index, raw_len);
    let mut data = vec![0u8; raw_len];
    for i in 0..length {
        for j in 1..bucket_size {
            let first = location[i * bucket_size] * 3 + 1;
            let next = location[i * bucket_size + j] * 3 + 1;
            data[i * bucket_size + j] = u8::from(mac[first].xor(mac[next]).get_lsb());
        }
    }

    let data2 = match ctx.party {
        Role::Alice => {
            ctx.stream.send_bool_bytes(&data, 0).await?;
            ctx.stream.recv_bool_bytes(raw_len, 0).await?
        }
        Role::Bob => {
            let data2 = ctx.stream.recv_bool_bytes(raw_len, 0).await?;
            ctx.stream.send_bool_bytes(&data, 0).await?;
            data2
        }
    };
    ctx.stream.flush().await?;

    for i in 0..length {
        for j in 1..bucket_size {
            let offset = i * bucket_size + j;
            data[offset] = u8::from((data[offset] != 0) != (data2[offset] != 0));
        }
    }

    let mut mac_res = vec![Block::zero(); length * 3];
    let mut key_res = vec![Block::zero(); length * 3];
    for i in 0..length {
        let first = location[i * bucket_size] * 3;
        for j in 0..3 {
            mac_res[i * 3 + j] = mac[first + j];
            key_res[i * 3 + j] = key[first + j];
        }
        for j in 1..bucket_size {
            let loc = location[i * bucket_size + j] * 3;
            mac_res[i * 3] = mac_res[i * 3].xor(mac[loc]);
            key_res[i * 3] = key_res[i * 3].xor(key[loc]);
            mac_res[i * 3 + 2] = mac_res[i * 3 + 2].xor(mac[loc + 2]);
            key_res[i * 3 + 2] = key_res[i * 3 + 2].xor(key[loc + 2]);

            if data[i * bucket_size + j] != 0 {
                key_res[i * 3 + 2] = key_res[i * 3 + 2].xor(key[loc]);
                mac_res[i * 3 + 2] = mac_res[i * 3 + 2].xor(mac[loc]);
            }
        }
    }

    Ok(FpreGenerated {
        mac: mac_res,
        key: key_res,
    })
}

fn fpre_permutation(seed: Block, index: u64, len: usize) -> Vec<usize> {
    let mut location: Vec<usize> = (0..len).collect();
    let mut prg = Prg::new(seed, index);
    let ind = prg.random_data(len * 4);
    for i in (0..len).rev() {
        let start = i * 4;
        let raw = i32::from_ne_bytes(ind[start..start + 4].try_into().expect("int length"));
        let modulo = raw % (i as i32 + 1);
        let chosen = if modulo > 0 { modulo } else { -modulo } as usize;
        location.swap(i, chosen);
    }
    location
}

async fn feq_compare(
    stream: &mut EmpStream,
    party: Role,
    local_digest: [u8; HASH_DIGEST_BYTES],
) -> Result<bool> {
    match party {
        Role::Alice => {
            let mut nonce = [0u8; BLOCK_BYTES];
            rand_bytes(&mut nonce)?;
            let commitment = feq_commitment(&local_digest, &nonce);
            stream.send_data(&commitment).await?;
            let remote_digest = stream.recv_data(HASH_DIGEST_BYTES).await?;
            stream.send_data(&nonce).await?;
            stream.flush().await?;
            Ok(remote_digest == local_digest)
        }
        Role::Bob => {
            let peer_commitment = stream.recv_data(HASH_DIGEST_BYTES).await?;
            stream.send_data(&local_digest).await?;
            let nonce: [u8; BLOCK_BYTES] = stream
                .recv_data(BLOCK_BYTES)
                .await?
                .try_into()
                .expect("nonce length");
            stream.flush().await?;
            Ok(peer_commitment == feq_commitment(&local_digest, &nonce))
        }
    }
}

fn feq_commitment(digest: &[u8; HASH_DIGEST_BYTES], nonce: &[u8; BLOCK_BYTES]) -> [u8; 32] {
    let mut data = [0u8; HASH_DIGEST_BYTES + BLOCK_BYTES];
    data[..HASH_DIGEST_BYTES].copy_from_slice(digest);
    data[HASH_DIGEST_BYTES..].copy_from_slice(nonce);
    hash_once(&data)
}

fn digest_and_reset(hasher: &mut Sha256) -> [u8; HASH_DIGEST_BYTES] {
    let digest = hasher.clone().finalize();
    *hasher = Sha256::new();
    digest.into()
}

async fn send_pre(
    state: &mut IknpSendState,
    stream: &mut EmpStream,
    length: usize,
) -> Result<Vec<Block>> {
    let mut out = Vec::with_capacity(length);
    let mut done = 0;
    while done + IKNP_BLOCK_SIZE <= length {
        out.extend(send_pre_block(state, stream, IKNP_BLOCK_SIZE).await?);
        done += IKNP_BLOCK_SIZE;
    }
    let remain = length - done;
    if remain != 0 {
        let block = send_pre_block(state, stream, remain).await?;
        out.extend_from_slice(&block[..remain]);
    }
    Ok(out)
}

async fn send_pre_block(
    state: &mut IknpSendState,
    stream: &mut EmpStream,
    len: usize,
) -> Result<Vec<Block>> {
    let local_block_size = round_up_128(len);
    let row_bytes = local_block_size / 8;
    let mut rows = vec![0u8; IKNP_SECURITY_BITS * row_bytes];
    let received_rows = stream.recv_data(IKNP_SECURITY_BITS * row_bytes).await?;
    for i in 0..IKNP_SECURITY_BITS {
        let start = i * row_bytes;
        let end = start + row_bytes;
        let row = &mut rows[start..end];
        state.g0[i].fill_random_data(row);
        let received = &received_rows[i * row_bytes..(i + 1) * row_bytes];
        if state.s[i] {
            xor_bytes_in_place(row, received);
        }
    }
    Ok(transpose_128_rows(&rows, row_bytes, local_block_size))
}

async fn recv_pre(
    state: &mut IknpRecvState,
    stream: &mut EmpStream,
    choices: &[bool],
) -> Result<Vec<Block>> {
    let mut choice_blocks = Vec::with_capacity(round_up_128(choices.len()) / IKNP_SECURITY_BITS);
    for chunk in choices.chunks(IKNP_SECURITY_BITS) {
        let mut padded = [false; IKNP_SECURITY_BITS];
        padded[..chunk.len()].copy_from_slice(chunk);
        choice_blocks.push(bool_to_block(&padded));
    }

    let mut out = Vec::with_capacity(choices.len());
    let mut done = 0;
    while done + IKNP_BLOCK_SIZE <= choices.len() {
        out.extend(
            recv_pre_block(
                state,
                stream,
                &choice_blocks[done / IKNP_SECURITY_BITS..],
                IKNP_BLOCK_SIZE,
            )
            .await?,
        );
        done += IKNP_BLOCK_SIZE;
    }
    let remain = choices.len() - done;
    if remain != 0 {
        let block = recv_pre_block(
            state,
            stream,
            &choice_blocks[done / IKNP_SECURITY_BITS..],
            remain,
        )
        .await?;
        out.extend_from_slice(&block[..remain]);
    }
    Ok(out)
}

async fn recv_pre_block(
    state: &mut IknpRecvState,
    stream: &mut EmpStream,
    r: &[Block],
    len: usize,
) -> Result<Vec<Block>> {
    let local_block_size = round_up_128(len);
    let blocks_per_row = local_block_size / IKNP_SECURITY_BITS;
    let row_bytes = local_block_size / 8;
    let mut rows = vec![0u8; IKNP_SECURITY_BITS * row_bytes];
    let mut messages = vec![0u8; IKNP_SECURITY_BITS * row_bytes];
    let mut row1 = vec![0u8; row_bytes];
    for i in 0..IKNP_SECURITY_BITS {
        let start = i * row_bytes;
        let end = start + row_bytes;
        let row0 = &mut rows[start..end];
        let message = &mut messages[start..end];
        state.g0[i].fill_random_data(row0);
        state.g1[i].fill_random_data(&mut row1);
        for (j, r_block) in r.iter().enumerate().take(blocks_per_row) {
            let start = j * BLOCK_BYTES;
            let r_bytes = r_block.as_bytes();
            for k in 0..BLOCK_BYTES {
                message[start + k] = row0[start + k] ^ row1[start + k] ^ r_bytes[k];
            }
        }
    }
    stream.send_data(&messages).await?;
    row1.zeroize();
    messages.zeroize();
    Ok(transpose_128_rows(&rows, row_bytes, local_block_size))
}

fn validate_iknp_len(name: &'static str, len: usize) -> Result<()> {
    if len == IKNP_SECURITY_BITS {
        Ok(())
    } else {
        Err(CompatError::BadIknpSetupLength { name, len })
    }
}

fn random_blocks(length: usize) -> Result<Vec<Block>> {
    let byte_len = length
        .checked_mul(BLOCK_BYTES)
        .ok_or(CompatError::LengthOverflow("random blocks"))?;
    let mut bytes = vec![0u8; byte_len];
    rand_bytes(&mut bytes)?;
    let out = bytes
        .chunks_exact(BLOCK_BYTES)
        .map(|chunk| Block::from_bytes(chunk.try_into().expect("block length")))
        .collect();
    bytes.zeroize();
    Ok(out)
}

fn random_block() -> Result<Block> {
    let mut bytes = [0u8; BLOCK_BYTES];
    rand_bytes(&mut bytes)?;
    Ok(Block::from_bytes(bytes))
}

fn random_bools(length: usize) -> Result<Vec<bool>> {
    let mut bytes = vec![0u8; length];
    rand_bytes(&mut bytes)?;
    Ok(bytes.into_iter().map(|byte| (byte & 1) != 0).collect())
}

fn random_bools_array() -> Result<[bool; IKNP_SECURITY_BITS]> {
    let mut out = [false; IKNP_SECURITY_BITS];
    for (dst, src) in out.iter_mut().zip(random_bools(IKNP_SECURITY_BITS)?) {
        *dst = src;
    }
    Ok(out)
}

fn bool_to_block(bits: &[bool; IKNP_SECURITY_BITS]) -> Block {
    let mut bytes = [0u8; BLOCK_BYTES];
    for (i, bit) in bits.iter().enumerate() {
        if *bit {
            bytes[i / 8] |= 1 << (i % 8);
        }
    }
    Block::from_bytes(bytes)
}

fn round_up_128(length: usize) -> usize {
    length.div_ceil(IKNP_SECURITY_BITS) * IKNP_SECURITY_BITS
}

fn xor_bytes_in_place(dst: &mut [u8], rhs: &[u8]) {
    for (dst, rhs) in dst.iter_mut().zip(rhs) {
        *dst ^= rhs;
    }
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

fn leaky_delta_mask() -> Block {
    Block::make(u64::MAX, u64::MAX - 1)
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
    use shachain2pc_circuit::Gate;
    use shachain2pc_emp_wire::EMP_STREAM_COUNT;
    use std::net::{IpAddr, Ipv4Addr, TcpListener as StdTcpListener};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::net::TcpListener as TokioTcpListener;
    use tokio::sync::Mutex;
    use tokio::time::{timeout, Duration};

    const LIVE_INTEROP_TIMEOUT: Duration = Duration::from_secs(60);
    const LIVE_C2PC_TIMEOUT: Duration = Duration::from_secs(120);
    const LIVE_IKNP_LENGTH: usize = 2051;
    const LIVE_LEAKY_LENGTH: usize = 257;
    const LIVE_FPRE_REQUESTED_SIZE: usize = 321;
    const LIVE_FPRE_GENERATE_LENGTH: usize = 683;
    const LIVE_FPRE_CHECK_LENGTH: usize = 683;
    static LIVE_CPP_INTEROP_LOCK: Mutex<()> = Mutex::const_new(());

    #[test]
    fn iknp_transpose_matches_bit_reference() {
        for row_bytes in [1usize, 16, 32, 256] {
            let output_len = row_bytes * 8;
            let mut rows = vec![0u8; IKNP_SECURITY_BITS * row_bytes];
            for (i, byte) in rows.iter_mut().enumerate() {
                *byte = ((i * 37 + i / 7 + 0x5a) & 0xff) as u8;
            }
            assert_eq!(
                transpose_128_rows(&rows, row_bytes, output_len),
                transpose_128_rows_bit_reference(&rows, row_bytes, output_len)
            );
        }
    }

    #[test]
    fn c2pc_fpre_setup_size_caps_bucketed_refills() {
        assert_eq!(c2pc_fpre_setup_size(2), 2);
        assert_eq!(c2pc_fpre_setup_size(3_100), 3_100);
        assert_eq!(c2pc_fpre_setup_size(22_272), 3_100);
        assert_eq!(c2pc_fpre_setup_size(1_069_056), 280_000);
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
            for row in 0..IKNP_SECURITY_BITS {
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

    #[derive(Clone, Copy, Debug)]
    enum TestExtendedOt {
        Iknp,
        Leaky,
    }

    #[derive(Clone, Copy, Debug)]
    enum C2pcTamperCase {
        GarbledTable,
        OutputMac,
        OutputLabel,
    }

    impl C2pcTamperCase {
        fn rust_role(self) -> Role {
            match self {
                Self::GarbledTable | Self::OutputMac => Role::Bob,
                Self::OutputLabel => Role::Alice,
            }
        }

        fn cpp_role(self) -> Role {
            opposite_role(self.rust_role())
        }

        fn sync_args(self) -> &'static [&'static str] {
            match self {
                Self::GarbledTable => &["sync-before-dependent"],
                Self::OutputMac | Self::OutputLabel => &["sync-before-online"],
            }
        }

        fn tamper_offsets(self, circuit: &C2pcCircuit) -> Vec<usize> {
            match self {
                Self::GarbledTable => {
                    let selector_bytes = 2 * circuit.num_ands();
                    (0..4)
                        .map(|row| selector_bytes + row * (C2PC_SSP_BYTES + BLOCK_BYTES))
                        .collect()
                }
                Self::OutputMac => vec![circuit.n2 + circuit.input_len() * BLOCK_BYTES],
                Self::OutputLabel => vec![circuit.n1 + C2PC_SSP_BYTES],
            }
        }
    }

    #[derive(Clone, Copy, Debug)]
    struct FpreVerification {
        delta: Block,
        batch_size: u32,
        bucket_size: u32,
        permute_batch_size: u32,
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

    fn otco_data() -> ([Block; 8], [Block; 8]) {
        let data0 = std::array::from_fn(|i| {
            Block::make(
                0x1000_0000_0000_0000 | i as u64,
                0x0000_0000_0000_0100 | i as u64,
            )
        });
        let data1 = std::array::from_fn(|i| {
            Block::make(
                0x2000_0000_0000_0000 | i as u64,
                0x0000_0000_0000_0200 | i as u64,
            )
        });
        (data0, data1)
    }

    fn otco_choices() -> [bool; 8] {
        [false, true, true, false, true, false, false, true]
    }

    fn otco_expected() -> Vec<Block> {
        let (data0, data1) = otco_data();
        otco_choices()
            .into_iter()
            .enumerate()
            .map(|(i, choice)| if choice { data1[i] } else { data0[i] })
            .collect()
    }

    fn iknp_choices(length: usize) -> Vec<bool> {
        (0..length).map(|i| ((i * 7 + 3) % 11) < 5).collect()
    }

    fn leaky_send_choices() -> [bool; IKNP_SECURITY_BITS] {
        // The recv-side choices intentionally differ across peers; the relation is choice-agnostic.
        let mut out = [false; IKNP_SECURITY_BITS];
        for (i, value) in out.iter_mut().enumerate() {
            *value = ((i * 5 + 1) % 9) < 4;
        }
        out[0] = true;
        out
    }

    fn opposite_role(role: Role) -> Role {
        match role {
            Role::Alice => Role::Bob,
            Role::Bob => Role::Alice,
        }
    }

    fn c2pc_test_circuit() -> Circuit {
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

    fn c2pc_test_input() -> [u8; 5] {
        [1, 0, 1, 1, 1]
    }

    fn c2pc_expected_output() -> [u8; 1] {
        [1]
    }

    fn carried_stage_one_circuit() -> Circuit {
        Circuit {
            num_wire: 3,
            n1: 1,
            n2: 1,
            n3: 1,
            gates: vec![Gate {
                typ: GateType::And,
                in0: 0,
                in1: 1,
                out: 2,
            }],
        }
    }

    fn carried_stage_two_circuit() -> Circuit {
        Circuit {
            num_wire: 2,
            n1: 1,
            n2: 0,
            n3: 1,
            gates: vec![Gate {
                typ: GateType::Inv,
                in0: 0,
                in1: -1,
                out: 1,
            }],
        }
    }

    fn carried_stage_two_and_self_circuit() -> Circuit {
        Circuit {
            num_wire: 2,
            n1: 1,
            n2: 0,
            n3: 1,
            gates: vec![Gate {
                typ: GateType::And,
                in0: 0,
                in1: 0,
                out: 1,
            }],
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rust_c2pc_authenticated_carry_reuses_one_delta() {
        let port = free_port();
        let alice = tokio::spawn(run_rust_c2pc_authenticated_carry(Role::Alice, port));
        tokio::time::sleep(Duration::from_millis(50)).await;
        let bob = tokio::spawn(run_rust_c2pc_authenticated_carry(Role::Bob, port));
        let (alice, bob) = timeout(LIVE_C2PC_TIMEOUT, async {
            (alice.await.unwrap(), bob.await.unwrap())
        })
        .await
        .unwrap();
        assert_eq!(alice.unwrap(), vec![0]);
        assert_eq!(bob.unwrap(), vec![0]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rust_c2pc_carried_label_tamper_rejects_before_reveal() {
        let port = free_port();
        let alice = tokio::spawn(run_rust_c2pc_carried_label_tamper(Role::Alice, port));
        tokio::time::sleep(Duration::from_millis(50)).await;
        let bob = tokio::spawn(run_rust_c2pc_carried_label_tamper(Role::Bob, port));
        let (alice, bob) = timeout(LIVE_C2PC_TIMEOUT, async {
            (alice.await.unwrap(), bob.await.unwrap())
        })
        .await
        .unwrap();
        assert!(alice.is_err());
        assert!(matches!(bob, Err(CompatError::C2pcGarbledTableMismatch(0))));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rust_c2pc_reveal_lambda_tamper_is_rejected_by_peer() {
        let port = free_port();
        let alice = tokio::spawn(run_rust_c2pc_reveal_lambda_tamper(Role::Alice, port));
        tokio::time::sleep(Duration::from_millis(50)).await;
        let bob = tokio::spawn(run_rust_c2pc_reveal_lambda_tamper(Role::Bob, port));
        let (alice, bob) = timeout(LIVE_C2PC_TIMEOUT, async {
            (alice.await.unwrap(), bob.await.unwrap())
        })
        .await
        .unwrap();
        assert!(matches!(alice, Err(CompatError::C2pcLambdaMismatch(0))));
        // PUBLIC reveal is intentionally Bob-unfair: Bob may locally finish
        // after sending bad reveal material, but Alice must reject it.
        drop(bob);
    }

    #[test]
    fn authenticated_bits_slice_is_bounds_checked() {
        let wires = AuthenticatedBits {
            mac: (0..4).map(|i| Block::make(0, i)).collect(),
            key: (0..4).map(|i| Block::make(1, i)).collect(),
            lambda: vec![0, 1, 0, 1],
            label: (0..4).map(|i| Block::make(2, i)).collect(),
        };
        let slice = wires.slice(1, 3).unwrap();
        assert_eq!(slice.len(), 2);
        assert_eq!(slice.mac, vec![Block::make(0, 1), Block::make(0, 2)]);
        assert_eq!(slice.key, vec![Block::make(1, 1), Block::make(1, 2)]);
        assert_eq!(slice.lambda, vec![1, 0]);
        assert_eq!(slice.label, vec![Block::make(2, 1), Block::make(2, 2)]);

        assert!(matches!(
            wires.slice(3, 5),
            Err(CompatError::BadAuthenticatedSlice {
                len: 4,
                start: 3,
                end: 5
            })
        ));
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

    #[test]
    fn fpre_params_fixture_matches_cpp() {
        let record = fixture_records()
            .into_iter()
            .find(|r| r["probe"] == "fpre_params")
            .unwrap();
        for case in record["outputs"]["cases"].as_array().unwrap() {
            let requested = case["requested"].as_u64().unwrap() as usize;
            let params = FpreParams::for_size(requested);
            assert_eq!(
                params.batch_size,
                case["batch_size"].as_u64().unwrap() as usize
            );
            assert_eq!(
                params.bucket_size,
                case["bucket_size"].as_u64().unwrap() as usize
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "old C++ probe target is not built by the new emp-ag2pc Makefile"]
    async fn live_cpp_otco_interop() {
        let _guard = LIVE_CPP_INTEROP_LOCK.lock().await;
        let bin = cpp_otco_probe();
        for transport in [TestTransport::Listen, TestTransport::Connect] {
            run_live_otco_case(&bin, transport, TestOtRole::Send).await;
            run_live_otco_case(&bin, transport, TestOtRole::Recv).await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "old C++ probe target is not built by the new emp-ag2pc Makefile"]
    async fn live_cpp_fpre_setup_interop() {
        let _guard = LIVE_CPP_INTEROP_LOCK.lock().await;
        let bin = cpp_fpre_setup_probe();
        run_live_fpre_setup_case(&bin, Role::Alice).await;
        run_live_fpre_setup_case(&bin, Role::Bob).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "old C++ probe target is not built by the new emp-ag2pc Makefile"]
    async fn live_cpp_fpre_generate_interop() {
        let _guard = LIVE_CPP_INTEROP_LOCK.lock().await;
        let bin = cpp_fpre_generate_probe();
        run_live_fpre_generate_case(&bin, Role::Alice).await;
        run_live_fpre_generate_case(&bin, Role::Bob).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "old C++ probe target is not built by the new emp-ag2pc Makefile"]
    async fn live_cpp_fpre_check_interop() {
        let _guard = LIVE_CPP_INTEROP_LOCK.lock().await;
        let bin = cpp_fpre_check_probe();
        for check_index in [0, 1] {
            run_live_fpre_check_case(&bin, Role::Alice, check_index).await;
            run_live_fpre_check_case(&bin, Role::Bob, check_index).await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "old C++ probe target is not built by the new emp-ag2pc Makefile"]
    async fn live_cpp_fpre_refill_interop() {
        let _guard = LIVE_CPP_INTEROP_LOCK.lock().await;
        let bin = cpp_fpre_refill_probe();
        run_live_fpre_refill_case(&bin, Role::Alice, false).await;
        run_live_fpre_refill_case(&bin, Role::Bob, false).await;
        run_live_fpre_refill_case(&bin, Role::Alice, true).await;
        run_live_fpre_refill_case(&bin, Role::Bob, true).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "old C++ probe target is not built by the new emp-ag2pc Makefile"]
    async fn live_cpp_c2pc_function_independent_interop() {
        let _guard = LIVE_CPP_INTEROP_LOCK.lock().await;
        let bin = cpp_c2pc_independent_probe();
        run_live_c2pc_independent_case(&bin, Role::Alice).await;
        run_live_c2pc_independent_case(&bin, Role::Bob).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "old C++ probe target is not built by the new emp-ag2pc Makefile"]
    async fn live_cpp_c2pc_function_dependent_interop() {
        let _guard = LIVE_CPP_INTEROP_LOCK.lock().await;
        let bin = cpp_c2pc_dependent_probe();
        run_live_c2pc_dependent_case(&bin, Role::Alice).await;
        run_live_c2pc_dependent_case(&bin, Role::Bob).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "old C++ probe target is not built by the new emp-ag2pc Makefile"]
    async fn live_cpp_c2pc_online_interop() {
        let _guard = LIVE_CPP_INTEROP_LOCK.lock().await;
        let bin = cpp_c2pc_online_probe();
        run_live_c2pc_online_case(&bin, Role::Alice).await;
        run_live_c2pc_online_case(&bin, Role::Bob).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "old C++ probe target is not built by the new emp-ag2pc Makefile"]
    async fn live_cpp_c2pc_online_tamper_rejects() {
        let _guard = LIVE_CPP_INTEROP_LOCK.lock().await;
        let bin = cpp_c2pc_online_probe();
        for case in [
            C2pcTamperCase::GarbledTable,
            C2pcTamperCase::OutputMac,
            C2pcTamperCase::OutputLabel,
        ] {
            run_live_c2pc_online_tamper_case(&bin, case).await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "old C++ probe target is not built by the new emp-ag2pc Makefile"]
    async fn live_cpp_iknp_and_leaky_interop() {
        let _guard = LIVE_CPP_INTEROP_LOCK.lock().await;
        let bin = cpp_iknp_probe();
        for kind in [TestExtendedOt::Iknp, TestExtendedOt::Leaky] {
            for transport in [TestTransport::Listen, TestTransport::Connect] {
                run_live_extended_ot_case(&bin, kind, transport, TestOtRole::Send).await;
                run_live_extended_ot_case(&bin, kind, transport, TestOtRole::Recv).await;
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rust_otco_accepts_zero_length_batch() {
        let port = free_port();
        let receiver = tokio::spawn(async move {
            let mut stream = EmpStream::listen(port).await.unwrap();
            otco_recv(&mut stream, &[]).await.unwrap()
        });

        let mut sender = EmpStream::connect(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
            .await
            .unwrap();
        otco_send(&mut sender, &[], &[]).await.unwrap();

        let out = receiver.await.unwrap();
        assert!(out.is_empty());
    }

    async fn run_live_otco_case(bin: &Path, rust_transport: TestTransport, rust_role: TestOtRole) {
        let port = free_port();
        let cpp_transport = match rust_transport {
            TestTransport::Listen => "connect",
            TestTransport::Connect => "listen",
        };
        let cpp_role = match rust_role {
            TestOtRole::Send => "recv",
            TestOtRole::Recv => "send",
        };
        let mut child = Command::new(bin)
            .current_dir(repo_root())
            .arg(cpp_transport)
            .arg(port.to_string())
            .arg(cpp_role)
            .arg("127.0.0.1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        let stream_result = timeout(LIVE_INTEROP_TIMEOUT, open_stream(rust_transport, port)).await;
        let mut stream = match stream_result {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust OTCO stream open failed ({rust_transport:?}, {rust_role:?}): {e}\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Err(_) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust OTCO stream open timed out ({rust_transport:?}, {rust_role:?})\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        };

        let ot_result = timeout(LIVE_INTEROP_TIMEOUT, run_rust_otco(&mut stream, rust_role)).await;
        match ot_result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust OTCO failed ({rust_transport:?}, {rust_role:?}): {e}\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Err(_) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust OTCO timed out ({rust_transport:?}, {rust_role:?})\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }

        drop(stream);
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "C++ OTCO probe failed ({rust_transport:?}, {rust_role:?})\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    async fn run_live_extended_ot_case(
        bin: &Path,
        kind: TestExtendedOt,
        rust_transport: TestTransport,
        rust_role: TestOtRole,
    ) {
        let port = free_port();
        let cpp_transport = match rust_transport {
            TestTransport::Listen => "connect",
            TestTransport::Connect => "listen",
        };
        let cpp_role = match (kind, rust_role) {
            (TestExtendedOt::Iknp, TestOtRole::Send) => "iknp-recv",
            (TestExtendedOt::Iknp, TestOtRole::Recv) => "iknp-send",
            (TestExtendedOt::Leaky, TestOtRole::Send) => "leaky-recv",
            (TestExtendedOt::Leaky, TestOtRole::Recv) => "leaky-send",
        };
        let mut child = Command::new(bin)
            .current_dir(repo_root())
            .arg(cpp_transport)
            .arg(port.to_string())
            .arg(cpp_role)
            .arg("127.0.0.1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        let stream_result = timeout(LIVE_INTEROP_TIMEOUT, open_stream(rust_transport, port)).await;
        let mut stream = match stream_result {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust extended OT stream open failed ({kind:?}, {rust_transport:?}, {rust_role:?}): {e}\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Err(_) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust extended OT stream open timed out ({kind:?}, {rust_transport:?}, {rust_role:?})\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        };

        let ot_result = timeout(
            LIVE_INTEROP_TIMEOUT,
            run_rust_extended_ot(&mut stream, kind, rust_role),
        )
        .await;
        match ot_result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust extended OT failed ({kind:?}, {rust_transport:?}, {rust_role:?}): {e}\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Err(_) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust extended OT timed out ({kind:?}, {rust_transport:?}, {rust_role:?})\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }

        drop(stream);
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "C++ extended OT probe failed ({kind:?}, {rust_transport:?}, {rust_role:?})\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    async fn run_live_fpre_setup_case(bin: &Path, rust_role: Role) {
        let port = free_port();
        let cpp_role = opposite_role(rust_role);
        let cpp_transport = match rust_role {
            Role::Alice => "connect",
            Role::Bob => "listen",
        };
        let mut child = Command::new(bin)
            .current_dir(repo_root())
            .arg(cpp_transport)
            .arg(port.to_string())
            .arg(cpp_role.party_id().to_string())
            .arg("127.0.0.1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        let stream_result = timeout(
            LIVE_C2PC_TIMEOUT,
            EmpStreams::open(rust_role, port, IpAddr::V4(Ipv4Addr::LOCALHOST)),
        )
        .await;
        let mut streams = match stream_result {
            Ok(Ok(streams)) => streams,
            Ok(Err(e)) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust Fpre stream open failed ({rust_role:?}): {e}\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Err(_) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust Fpre stream open timed out ({rust_role:?})\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        };

        let setup_result = timeout(
            LIVE_INTEROP_TIMEOUT,
            run_rust_fpre_setup(&mut streams, rust_role),
        )
        .await;
        match setup_result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust Fpre setup failed ({rust_role:?}): {e}\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Err(_) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust Fpre setup timed out ({rust_role:?})\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }

        drop(streams);
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "C++ Fpre setup probe failed ({rust_role:?})\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    async fn run_live_fpre_generate_case(bin: &Path, rust_role: Role) {
        let port = free_port();
        let cpp_role = opposite_role(rust_role);
        let cpp_transport = match rust_role {
            Role::Alice => "connect",
            Role::Bob => "listen",
        };
        let mut child = Command::new(bin)
            .current_dir(repo_root())
            .arg(cpp_transport)
            .arg(port.to_string())
            .arg(cpp_role.party_id().to_string())
            .arg("127.0.0.1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        let stream_result = timeout(
            LIVE_INTEROP_TIMEOUT,
            EmpStreams::open(rust_role, port, IpAddr::V4(Ipv4Addr::LOCALHOST)),
        )
        .await;
        let mut streams = match stream_result {
            Ok(Ok(streams)) => streams,
            Ok(Err(e)) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust Fpre generate stream open failed ({rust_role:?}): {e}\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Err(_) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust Fpre generate stream open timed out ({rust_role:?})\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        };

        let generate_result = timeout(
            LIVE_INTEROP_TIMEOUT,
            run_rust_fpre_generate(&mut streams, rust_role),
        )
        .await;
        match generate_result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust Fpre generate failed ({rust_role:?}): {e}\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Err(_) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust Fpre generate timed out ({rust_role:?})\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }

        drop(streams);
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "C++ Fpre generate probe failed ({rust_role:?})\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    async fn run_live_fpre_check_case(bin: &Path, rust_role: Role, check_index: usize) {
        let port = free_port();
        let cpp_role = opposite_role(rust_role);
        let cpp_transport = match rust_role {
            Role::Alice => "connect",
            Role::Bob => "listen",
        };
        let mut child = Command::new(bin)
            .current_dir(repo_root())
            .arg(cpp_transport)
            .arg(port.to_string())
            .arg(cpp_role.party_id().to_string())
            .arg(check_index.to_string())
            .arg("127.0.0.1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        let stream_result = timeout(
            LIVE_INTEROP_TIMEOUT,
            EmpStreams::open(rust_role, port, IpAddr::V4(Ipv4Addr::LOCALHOST)),
        )
        .await;
        let mut streams = match stream_result {
            Ok(Ok(streams)) => streams,
            Ok(Err(e)) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust Fpre check stream open failed ({rust_role:?}, {check_index}): {e}\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Err(_) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust Fpre check stream open timed out ({rust_role:?}, {check_index})\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        };

        let check_result = timeout(
            LIVE_INTEROP_TIMEOUT,
            run_rust_fpre_check(&mut streams, rust_role, check_index),
        )
        .await;
        match check_result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust Fpre check failed ({rust_role:?}, {check_index}): {e}\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Err(_) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust Fpre check timed out ({rust_role:?}, {check_index})\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }

        drop(streams);
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "C++ Fpre check probe failed ({rust_role:?}, {check_index})\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    async fn run_live_fpre_refill_case(bin: &Path, rust_role: Role, tamper_eq: bool) {
        let port = free_port();
        let cpp_role = opposite_role(rust_role);
        let cpp_transport = match rust_role {
            Role::Alice => "connect",
            Role::Bob => "listen",
        };
        let mut child = Command::new(bin)
            .current_dir(repo_root())
            .arg(cpp_transport)
            .arg(port.to_string())
            .arg(cpp_role.party_id().to_string())
            .arg("127.0.0.1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        let stream_result = timeout(
            LIVE_INTEROP_TIMEOUT,
            EmpStreams::open(rust_role, port, IpAddr::V4(Ipv4Addr::LOCALHOST)),
        )
        .await;
        let mut streams = match stream_result {
            Ok(Ok(streams)) => streams,
            Ok(Err(e)) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust Fpre refill stream open failed ({rust_role:?}, tamper={tamper_eq}): {e}\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Err(_) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust Fpre refill stream open timed out ({rust_role:?}, tamper={tamper_eq})\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        };

        let refill_result = timeout(
            LIVE_INTEROP_TIMEOUT,
            run_rust_fpre_refill(&mut streams, rust_role, tamper_eq),
        )
        .await;
        match (tamper_eq, refill_result) {
            (false, Ok(Ok(()))) => {}
            (false, Ok(Err(e))) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust Fpre refill failed ({rust_role:?}): {e}\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            (false, Err(_)) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust Fpre refill timed out ({rust_role:?})\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            (true, Ok(Err(CompatError::FeqMismatch))) => {}
            (true, Ok(Ok(()))) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "tampered Rust Fpre refill unexpectedly succeeded ({rust_role:?})\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            (true, Ok(Err(e))) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "tampered Rust Fpre refill failed with wrong error ({rust_role:?}): {e}\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            (true, Err(_)) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "tampered Rust Fpre refill timed out ({rust_role:?})\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }

        drop(streams);
        let output = child.wait_with_output().unwrap();
        if tamper_eq {
            assert!(
                !output.status.success(),
                "C++ Fpre refill probe unexpectedly accepted tamper ({rust_role:?})\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        } else {
            assert!(
                output.status.success(),
                "C++ Fpre refill probe failed ({rust_role:?})\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    async fn run_live_c2pc_independent_case(bin: &Path, rust_role: Role) {
        let port = free_port();
        let cpp_role = opposite_role(rust_role);
        let cpp_transport = match rust_role {
            Role::Alice => "connect",
            Role::Bob => "listen",
        };
        let mut child = Command::new(bin)
            .current_dir(repo_root())
            .arg(cpp_transport)
            .arg(port.to_string())
            .arg(cpp_role.party_id().to_string())
            .arg("127.0.0.1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        let stream_result = timeout(
            LIVE_INTEROP_TIMEOUT,
            EmpStreams::open(rust_role, port, IpAddr::V4(Ipv4Addr::LOCALHOST)),
        )
        .await;
        let mut streams = match stream_result {
            Ok(Ok(streams)) => streams,
            Ok(Err(e)) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust C2PC independent stream open failed ({rust_role:?}): {e}\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Err(_) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust C2PC independent stream open timed out ({rust_role:?})\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        };

        let independent_result = timeout(
            LIVE_C2PC_TIMEOUT,
            run_rust_c2pc_independent(&mut streams, rust_role),
        )
        .await;
        match independent_result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust C2PC independent failed ({rust_role:?}): {e}\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Err(_) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust C2PC independent timed out ({rust_role:?})\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }

        drop(streams);
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "C++ C2PC independent probe failed ({rust_role:?})\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    async fn run_live_c2pc_dependent_case(bin: &Path, rust_role: Role) {
        let port = free_port();
        let cpp_role = opposite_role(rust_role);
        let cpp_transport = match rust_role {
            Role::Alice => "connect",
            Role::Bob => "listen",
        };
        let mut child = Command::new(bin)
            .current_dir(repo_root())
            .arg(cpp_transport)
            .arg(port.to_string())
            .arg(cpp_role.party_id().to_string())
            .arg("127.0.0.1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        let stream_result = timeout(
            LIVE_C2PC_TIMEOUT,
            EmpStreams::open(rust_role, port, IpAddr::V4(Ipv4Addr::LOCALHOST)),
        )
        .await;
        let mut streams = match stream_result {
            Ok(Ok(streams)) => streams,
            Ok(Err(e)) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust C2PC dependent stream open failed ({rust_role:?}): {e}\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Err(_) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust C2PC dependent stream open timed out ({rust_role:?})\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        };

        let dependent_result = timeout(
            LIVE_C2PC_TIMEOUT,
            run_rust_c2pc_dependent(&mut streams, rust_role),
        )
        .await;
        match dependent_result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust C2PC dependent failed ({rust_role:?}): {e}\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Err(_) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust C2PC dependent timed out ({rust_role:?})\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }

        drop(streams);
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "C++ C2PC dependent probe failed ({rust_role:?})\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    async fn run_live_c2pc_online_case(bin: &Path, rust_role: Role) {
        let port = free_port();
        let cpp_role = opposite_role(rust_role);
        let cpp_transport = match rust_role {
            Role::Alice => "connect",
            Role::Bob => "listen",
        };
        let mut child = Command::new(bin)
            .current_dir(repo_root())
            .arg(cpp_transport)
            .arg(port.to_string())
            .arg(cpp_role.party_id().to_string())
            .arg("127.0.0.1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        let stream_result = timeout(
            LIVE_C2PC_TIMEOUT,
            EmpStreams::open(rust_role, port, IpAddr::V4(Ipv4Addr::LOCALHOST)),
        )
        .await;
        let mut streams = match stream_result {
            Ok(Ok(streams)) => streams,
            Ok(Err(e)) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust C2PC online stream open failed ({rust_role:?}): {e}\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Err(_) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust C2PC online stream open timed out ({rust_role:?})\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        };

        let online_result = timeout(
            LIVE_C2PC_TIMEOUT,
            run_rust_c2pc_online(&mut streams, rust_role),
        )
        .await;
        match online_result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust C2PC online failed ({rust_role:?}): {e}\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Err(_) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "Rust C2PC online timed out ({rust_role:?})\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }

        drop(streams);
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "C++ C2PC online probe failed ({rust_role:?})\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    async fn run_live_c2pc_online_tamper_case(bin: &Path, case: C2pcTamperCase) {
        let rust_listener = TokioTcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let rust_port = rust_listener.local_addr().unwrap().port();
        let cpp_listener = TokioTcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let cpp_port = cpp_listener.local_addr().unwrap().port();
        let arm_tamper = Arc::new(AtomicBool::new(false));
        let tampered = Arc::new(AtomicBool::new(false));
        let test_circuit = C2pcCircuit::from_circuit(&c2pc_test_circuit()).unwrap();
        let tamper_offsets = case.tamper_offsets(&test_circuit);

        let mut child = Command::new(bin)
            .current_dir(repo_root())
            .arg("connect")
            .arg(cpp_port.to_string())
            .arg(case.cpp_role().party_id().to_string())
            .arg("127.0.0.1")
            .args(case.sync_args())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        let proxy = tokio::spawn(run_three_stream_tamper_proxy(
            rust_listener,
            cpp_listener,
            arm_tamper.clone(),
            tampered.clone(),
            tamper_offsets,
        ));

        let stream_result = timeout(
            LIVE_C2PC_TIMEOUT,
            EmpStreams::connect(IpAddr::V4(Ipv4Addr::LOCALHOST), rust_port),
        )
        .await;
        let mut streams = match stream_result {
            Ok(Ok(streams)) => streams,
            Ok(Err(e)) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                proxy.abort();
                panic!(
                    "Rust C2PC tamper stream open failed ({case:?}): {e}\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Err(_) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                proxy.abort();
                panic!(
                    "Rust C2PC tamper stream open timed out ({case:?})\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        };

        let tamper_result = timeout(
            LIVE_C2PC_TIMEOUT,
            run_rust_c2pc_online_tamper(&mut streams, case, arm_tamper),
        )
        .await;
        match tamper_result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                proxy.abort();
                panic!(
                    "Rust C2PC online tamper failed with wrong error ({case:?}): {e}\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Err(_) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                proxy.abort();
                panic!(
                    "Rust C2PC online tamper timed out ({case:?})\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
        assert!(
            tampered.load(Ordering::SeqCst),
            "tamper proxy did not flip a C++->Rust byte ({case:?})"
        );

        drop(streams);
        let _ = child.kill();
        let _ = child.wait_with_output();
        proxy.abort();
    }

    async fn run_three_stream_tamper_proxy(
        rust_listener: TokioTcpListener,
        cpp_listener: TokioTcpListener,
        arm_tamper: Arc<AtomicBool>,
        tampered: Arc<AtomicBool>,
        tamper_offsets: Vec<usize>,
    ) -> std::io::Result<()> {
        let mut relay_handles = Vec::new();
        let tamper_offsets = Arc::new(tamper_offsets);
        for stream_index in 0..EMP_STREAM_COUNT {
            let (rust_stream, _) = rust_listener.accept().await?;
            rust_stream.set_nodelay(true)?;
            let (cpp_stream, _) = cpp_listener.accept().await?;
            cpp_stream.set_nodelay(true)?;
            let (rust_read, rust_write) = rust_stream.into_split();
            let (cpp_read, cpp_write) = cpp_stream.into_split();
            relay_handles.push(tokio::spawn(relay_tcp(rust_read, cpp_write, None)));

            let tamper = (stream_index == 0).then(|| TamperPlan {
                arm: arm_tamper.clone(),
                tampered: tampered.clone(),
                offsets: tamper_offsets.clone(),
                bytes_seen: Arc::new(AtomicUsize::new(0)),
                next_offset: Arc::new(AtomicUsize::new(0)),
            });
            relay_handles.push(tokio::spawn(relay_tcp(cpp_read, rust_write, tamper)));
        }

        for handle in relay_handles {
            let _ = handle.await;
        }
        Ok(())
    }

    #[derive(Clone)]
    struct TamperPlan {
        arm: Arc<AtomicBool>,
        tampered: Arc<AtomicBool>,
        offsets: Arc<Vec<usize>>,
        bytes_seen: Arc<AtomicUsize>,
        next_offset: Arc<AtomicUsize>,
    }

    async fn relay_tcp<R, W>(
        mut reader: R,
        mut writer: W,
        tamper: Option<TamperPlan>,
    ) -> std::io::Result<()>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut buf = [0u8; 8192];
        loop {
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            if let Some(plan) = &tamper {
                maybe_tamper_chunk(&mut buf[..n], plan);
            }
            writer.write_all(&buf[..n]).await?;
        }
        let _ = writer.shutdown().await;
        Ok(())
    }

    fn maybe_tamper_chunk(buf: &mut [u8], plan: &TamperPlan) {
        if !plan.arm.load(Ordering::SeqCst) {
            return;
        }

        let start = plan.bytes_seen.fetch_add(buf.len(), Ordering::SeqCst);
        let end = start + buf.len();
        loop {
            let idx = plan.next_offset.load(Ordering::SeqCst);
            let Some(offset) = plan.offsets.get(idx).copied() else {
                return;
            };
            if offset >= end {
                return;
            }
            if offset >= start
                && plan
                    .next_offset
                    .compare_exchange(idx, idx + 1, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
            {
                buf[offset - start] ^= 0x01;
                plan.tampered.store(true, Ordering::SeqCst);
            } else if offset < start {
                let _ = plan.next_offset.compare_exchange(
                    idx,
                    idx + 1,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                );
            }
        }
    }

    async fn open_stream(transport: TestTransport, port: u16) -> Result<EmpStream> {
        match transport {
            TestTransport::Listen => EmpStream::listen(port).await.map_err(Into::into),
            TestTransport::Connect => EmpStream::connect(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
                .await
                .map_err(Into::into),
        }
    }

    async fn run_rust_otco(stream: &mut EmpStream, role: TestOtRole) -> Result<()> {
        match role {
            TestOtRole::Send => {
                let (data0, data1) = otco_data();
                otco_send(stream, &data0, &data1).await
            }
            TestOtRole::Recv => {
                let out = otco_recv(stream, &otco_choices()).await?;
                assert_eq!(out, otco_expected());
                Ok(())
            }
        }
    }

    async fn run_rust_extended_ot(
        stream: &mut EmpStream,
        kind: TestExtendedOt,
        role: TestOtRole,
    ) -> Result<()> {
        match (kind, role) {
            (TestExtendedOt::Iknp, TestOtRole::Send) => {
                let mut iknp = Iknp::new();
                let sender_data = iknp.send_cot(stream, LIVE_IKNP_LENGTH).await?;
                let delta = iknp
                    .delta()
                    .ok_or(CompatError::IknpWrongRole("IKNP verification"))?;
                send_sender_verification(stream, delta, &sender_data).await
            }
            (TestExtendedOt::Iknp, TestOtRole::Recv) => {
                let choices = iknp_choices(LIVE_IKNP_LENGTH);
                let mut iknp = Iknp::new();
                let receiver_data = iknp.recv_cot(stream, &choices).await?;
                let (delta, sender_data) =
                    recv_sender_verification(stream, LIVE_IKNP_LENGTH).await?;
                assert_iknp_relation(&receiver_data, &choices, delta, &sender_data);
                Ok(())
            }
            (TestExtendedOt::Leaky, TestOtRole::Send) => {
                let mut dot = LeakyDeltaOt::new();
                dot.setup_send_with_choices(stream, &leaky_send_choices())
                    .await?;
                stream.flush().await?;
                let sender_data = dot.send_dot(stream, LIVE_LEAKY_LENGTH).await?;
                let delta = dot
                    .delta()
                    .ok_or(CompatError::IknpWrongRole("LeakyDeltaOT verification"))?;
                send_sender_verification(stream, delta, &sender_data).await
            }
            (TestExtendedOt::Leaky, TestOtRole::Recv) => {
                let mut dot = LeakyDeltaOt::new();
                dot.setup_recv(stream).await?;
                stream.flush().await?;
                let receiver_data = dot.recv_dot(stream, LIVE_LEAKY_LENGTH).await?;
                let (delta, sender_data) =
                    recv_sender_verification(stream, LIVE_LEAKY_LENGTH).await?;
                assert_leaky_relation(&receiver_data, delta, &sender_data);
                Ok(())
            }
        }
    }

    async fn run_rust_fpre_setup(streams: &mut EmpStreams, role: Role) -> Result<()> {
        let fpre = Fpre::setup(streams, role, LIVE_FPRE_REQUESTED_SIZE).await?;
        assert_eq!(fpre.party(), role);
        assert!(fpre.leaky_instances_ready());
        assert_fpre_delta_bits(fpre.delta(), role);
        assert_eq!(fpre.z_delta(), fpre.delta().and(leaky_delta_mask()));
        let local = fpre_verification(&fpre);
        let remote = match role {
            Role::Alice => {
                send_fpre_verification(&mut streams.main, local).await?;
                recv_fpre_verification(&mut streams.main).await?
            }
            Role::Bob => {
                let remote = recv_fpre_verification(&mut streams.main).await?;
                send_fpre_verification(&mut streams.main, local).await?;
                remote
            }
        };
        assert_fpre_delta_bits(remote.delta, opposite_role(role));
        assert_fpre_params(remote);
        Ok(())
    }

    async fn run_rust_fpre_generate(streams: &mut EmpStreams, role: Role) -> Result<()> {
        let mut fpre = Fpre::setup(streams, role, LIVE_FPRE_REQUESTED_SIZE).await?;
        let generated = fpre.generate(streams, LIVE_FPRE_GENERATE_LENGTH).await?;
        assert_eq!(generated.mac.len(), LIVE_FPRE_GENERATE_LENGTH * 3);
        assert_eq!(generated.key.len(), LIVE_FPRE_GENERATE_LENGTH * 3);

        let (remote_delta, remote_key) = match role {
            Role::Alice => {
                send_fpre_generate_verification(&mut streams.main, fpre.delta(), &generated.key)
                    .await?;
                recv_fpre_generate_verification(&mut streams.main, LIVE_FPRE_GENERATE_LENGTH * 3)
                    .await?
            }
            Role::Bob => {
                let remote = recv_fpre_generate_verification(
                    &mut streams.main,
                    LIVE_FPRE_GENERATE_LENGTH * 3,
                )
                .await?;
                send_fpre_generate_verification(&mut streams.main, fpre.delta(), &generated.key)
                    .await?;
                remote
            }
        };
        assert_fpre_generate_relation(&generated.mac, remote_delta, &remote_key);
        Ok(())
    }

    async fn run_rust_fpre_check(
        streams: &mut EmpStreams,
        role: Role,
        check_index: usize,
    ) -> Result<()> {
        let mut fpre = Fpre::setup(streams, role, LIVE_FPRE_REQUESTED_SIZE).await?;
        let mut generated = fpre.generate(streams, LIVE_FPRE_CHECK_LENGTH).await?;
        fpre.check(streams, &mut generated, LIVE_FPRE_CHECK_LENGTH, check_index)
            .await?;
        let local_digest = fpre.check_digest(check_index)?;

        let (remote_delta, remote_key, remote_digest) = match role {
            Role::Alice => {
                send_fpre_check_verification(
                    &mut streams.main,
                    fpre.delta(),
                    &generated.key,
                    local_digest,
                )
                .await?;
                recv_fpre_check_verification(&mut streams.main, LIVE_FPRE_CHECK_LENGTH * 3).await?
            }
            Role::Bob => {
                let remote =
                    recv_fpre_check_verification(&mut streams.main, LIVE_FPRE_CHECK_LENGTH * 3)
                        .await?;
                send_fpre_check_verification(
                    &mut streams.main,
                    fpre.delta(),
                    &generated.key,
                    local_digest,
                )
                .await?;
                remote
            }
        };
        assert_fpre_generate_relation(&generated.mac, remote_delta, &remote_key);
        assert_eq!(local_digest, remote_digest);
        Ok(())
    }

    async fn run_rust_fpre_refill(
        streams: &mut EmpStreams,
        role: Role,
        tamper_eq: bool,
    ) -> Result<()> {
        let mut fpre = Fpre::setup(streams, role, LIVE_FPRE_REQUESTED_SIZE).await?;
        let generated = fpre.refill_inner(streams, tamper_eq).await?;
        if tamper_eq {
            return Ok(());
        }

        let params = fpre.params();
        assert_eq!(generated.mac.len(), params.batch_size * 3);
        assert_eq!(generated.key.len(), params.batch_size * 3);
        let local_bits = fpre_mac_bits(&generated.mac);
        let (remote_delta, remote_key, remote_bits) = match role {
            Role::Alice => {
                send_fpre_refill_verification(
                    &mut streams.main,
                    fpre.delta(),
                    &generated.key,
                    &local_bits,
                )
                .await?;
                recv_fpre_refill_verification(&mut streams.main, params.batch_size * 3).await?
            }
            Role::Bob => {
                let remote =
                    recv_fpre_refill_verification(&mut streams.main, params.batch_size * 3).await?;
                send_fpre_refill_verification(
                    &mut streams.main,
                    fpre.delta(),
                    &generated.key,
                    &local_bits,
                )
                .await?;
                remote
            }
        };
        assert_fpre_generate_relation(&generated.mac, remote_delta, &remote_key);
        assert_fpre_triple_relation(&local_bits, &remote_bits);
        Ok(())
    }

    async fn run_rust_c2pc_independent(streams: &mut EmpStreams, role: Role) -> Result<()> {
        let circuit = C2pcCircuit::from_circuit(&c2pc_test_circuit())?;
        assert_eq!(circuit.input_len(), 5);
        assert_eq!(circuit.output_len(), 1);
        assert_eq!(circuit.num_ands(), 2);
        assert_eq!(circuit.total_pre(), 7);

        let mut c2pc = C2pc::new(streams, role, circuit).await?;
        c2pc.function_independent(streams).await?;
        assert_eq!(c2pc.party(), role);
        assert_eq!(c2pc.input_mac().len(), c2pc.circuit().input_len());
        assert_eq!(c2pc.input_key().len(), c2pc.circuit().input_len());
        assert_eq!(c2pc.preprocess_mac().len(), c2pc.circuit().total_pre());
        assert_eq!(c2pc.preprocess_key().len(), c2pc.circuit().total_pre());
        assert_eq!(c2pc.ands_mac().len(), c2pc.circuit().num_ands() * 3);
        assert_eq!(c2pc.ands_key().len(), c2pc.circuit().num_ands() * 3);

        let local_ands_bits = fpre_mac_bits(c2pc.ands_mac());
        let (remote_delta, remote_input_key, remote_preprocess_key, remote_ands_key, remote_bits) =
            match role {
                Role::Alice => {
                    send_c2pc_independent_verification(
                        &mut streams.main,
                        c2pc.delta(),
                        c2pc.input_key(),
                        c2pc.preprocess_key(),
                        c2pc.ands_key(),
                        &local_ands_bits,
                    )
                    .await?;
                    recv_c2pc_independent_verification(
                        &mut streams.main,
                        c2pc.circuit().input_len(),
                        c2pc.circuit().total_pre(),
                        c2pc.circuit().num_ands() * 3,
                    )
                    .await?
                }
                Role::Bob => {
                    let remote = recv_c2pc_independent_verification(
                        &mut streams.main,
                        c2pc.circuit().input_len(),
                        c2pc.circuit().total_pre(),
                        c2pc.circuit().num_ands() * 3,
                    )
                    .await?;
                    send_c2pc_independent_verification(
                        &mut streams.main,
                        c2pc.delta(),
                        c2pc.input_key(),
                        c2pc.preprocess_key(),
                        c2pc.ands_key(),
                        &local_ands_bits,
                    )
                    .await?;
                    remote
                }
            };

        assert_fpre_generate_relation(c2pc.input_mac(), remote_delta, &remote_input_key);
        assert_fpre_generate_relation(c2pc.preprocess_mac(), remote_delta, &remote_preprocess_key);
        assert_fpre_generate_relation(c2pc.ands_mac(), remote_delta, &remote_ands_key);
        assert_fpre_triple_relation(&local_ands_bits, &remote_bits);
        Ok(())
    }

    async fn run_rust_c2pc_dependent(streams: &mut EmpStreams, role: Role) -> Result<()> {
        let circuit = C2pcCircuit::from_circuit(&c2pc_test_circuit())?;
        let mut c2pc = C2pc::new(streams, role, circuit).await?;
        c2pc.function_independent(streams).await?;
        c2pc.function_dependent(streams).await?;

        let local_table = c2pc.garbled_table_wire();
        let table_len = c2pc.circuit().num_ands() * 4 * (C2PC_SSP_BYTES + 16);
        assert_eq!(local_table.len(), table_len);
        let (remote_delta, remote_key, remote_sigma_key, remote_table) = match role {
            Role::Alice => {
                send_c2pc_dependent_verification(
                    &mut streams.main,
                    c2pc.delta(),
                    c2pc.wire_key(),
                    c2pc.sigma_key(),
                    &local_table,
                )
                .await?;
                recv_c2pc_dependent_verification(
                    &mut streams.main,
                    c2pc.circuit().num_wire(),
                    c2pc.circuit().num_ands(),
                    table_len,
                )
                .await?
            }
            Role::Bob => {
                let remote = recv_c2pc_dependent_verification(
                    &mut streams.main,
                    c2pc.circuit().num_wire(),
                    c2pc.circuit().num_ands(),
                    table_len,
                )
                .await?;
                send_c2pc_dependent_verification(
                    &mut streams.main,
                    c2pc.delta(),
                    c2pc.wire_key(),
                    c2pc.sigma_key(),
                    &local_table,
                )
                .await?;
                remote
            }
        };

        assert_fpre_generate_relation(c2pc.wire_mac(), remote_delta, &remote_key);
        assert_fpre_generate_relation(c2pc.sigma_mac(), remote_delta, &remote_sigma_key);
        assert_eq!(local_table, remote_table);
        Ok(())
    }

    async fn run_rust_c2pc_online(streams: &mut EmpStreams, role: Role) -> Result<()> {
        let circuit = C2pcCircuit::from_circuit(&c2pc_test_circuit())?;
        let mut c2pc = C2pc::new(streams, role, circuit).await?;
        c2pc.function_independent(streams).await?;
        c2pc.function_dependent(streams).await?;
        let output = c2pc.online(streams, &c2pc_test_input(), true).await?;
        assert_eq!(output, c2pc_expected_output());
        match role {
            Role::Alice => {
                streams.main.send_data(&output).await?;
                let remote = streams.main.recv_data(c2pc.circuit().output_len()).await?;
                assert_eq!(remote, output);
            }
            Role::Bob => {
                let remote = streams.main.recv_data(c2pc.circuit().output_len()).await?;
                streams.main.send_data(&output).await?;
                assert_eq!(remote, output);
            }
        }
        streams.main.flush().await?;
        Ok(())
    }

    async fn run_rust_c2pc_authenticated_carry(role: Role, port: u16) -> Result<Vec<u8>> {
        let mut streams = EmpStreams::open(role, port, IpAddr::V4(Ipv4Addr::LOCALHOST)).await?;
        let stage_one = C2pcCircuit::from_circuit(&carried_stage_one_circuit())?;
        let stage_two = C2pcCircuit::from_circuit(&carried_stage_two_circuit())?;
        let mut c2pc = C2pc::new_with_setup_size(&mut streams, role, stage_one, 1).await?;

        c2pc.function_independent(&mut streams).await?;
        c2pc.function_dependent(&mut streams).await?;
        let carried = c2pc
            .online_authenticated_clear(&mut streams, &[1, 1])
            .await?;

        c2pc.reset_circuit(stage_two);
        c2pc.function_independent(&mut streams).await?;
        c2pc.apply_carried_inputs(&carried)?;
        c2pc.function_dependent_carried(&mut streams).await?;
        let carried = c2pc
            .online_authenticated_carried(&mut streams, &carried)
            .await?;
        c2pc.reveal_authenticated_public(&mut streams, &carried)
            .await
    }

    async fn run_rust_c2pc_carried_label_tamper(role: Role, port: u16) -> Result<Vec<u8>> {
        let mut streams = EmpStreams::open(role, port, IpAddr::V4(Ipv4Addr::LOCALHOST)).await?;
        let stage_one = C2pcCircuit::from_circuit(&carried_stage_one_circuit())?;
        let stage_two = C2pcCircuit::from_circuit(&carried_stage_two_and_self_circuit())?;
        let mut c2pc = C2pc::new_with_setup_size(&mut streams, role, stage_one, 1).await?;

        c2pc.function_independent(&mut streams).await?;
        c2pc.function_dependent(&mut streams).await?;
        let mut carried = c2pc
            .online_authenticated_clear(&mut streams, &[1, 1])
            .await?;

        c2pc.reset_circuit(stage_two);
        c2pc.function_independent(&mut streams).await?;
        if role == Role::Bob {
            carried.label[0] = carried.label[0].xor(c2pc_mask());
        }
        c2pc.apply_carried_inputs(&carried)?;
        c2pc.function_dependent_carried(&mut streams).await?;
        let carried = c2pc
            .online_authenticated_carried(&mut streams, &carried)
            .await?;
        c2pc.reveal_authenticated_public(&mut streams, &carried)
            .await
    }

    async fn run_rust_c2pc_reveal_lambda_tamper(role: Role, port: u16) -> Result<Vec<u8>> {
        let mut streams = EmpStreams::open(role, port, IpAddr::V4(Ipv4Addr::LOCALHOST)).await?;
        let stage_one = C2pcCircuit::from_circuit(&carried_stage_one_circuit())?;
        let stage_two = C2pcCircuit::from_circuit(&carried_stage_two_circuit())?;
        let mut c2pc = C2pc::new_with_setup_size(&mut streams, role, stage_one, 1).await?;

        c2pc.function_independent(&mut streams).await?;
        c2pc.function_dependent(&mut streams).await?;
        let carried = c2pc
            .online_authenticated_clear(&mut streams, &[1, 1])
            .await?;

        c2pc.reset_circuit(stage_two);
        c2pc.function_independent(&mut streams).await?;
        c2pc.apply_carried_inputs(&carried)?;
        c2pc.function_dependent_carried(&mut streams).await?;
        let mut carried = c2pc
            .online_authenticated_carried(&mut streams, &carried)
            .await?;
        if role == Role::Bob {
            carried.lambda[0] ^= 1;
        }
        c2pc.reveal_authenticated_public(&mut streams, &carried)
            .await
    }

    async fn run_rust_c2pc_online_tamper(
        streams: &mut EmpStreams,
        case: C2pcTamperCase,
        arm_tamper: Arc<AtomicBool>,
    ) -> Result<()> {
        let circuit = C2pcCircuit::from_circuit(&c2pc_test_circuit())?;
        let mut c2pc = C2pc::new(streams, case.rust_role(), circuit).await?;
        c2pc.function_independent(streams).await?;
        if matches!(case, C2pcTamperCase::GarbledTable) {
            arm_tamper.store(true, Ordering::SeqCst);
            send_phase_sync(&mut streams.main).await?;
        }
        c2pc.function_dependent(streams).await?;

        if !matches!(case, C2pcTamperCase::GarbledTable) {
            arm_tamper.store(true, Ordering::SeqCst);
            send_phase_sync(&mut streams.main).await?;
        }
        match c2pc.online(streams, &c2pc_test_input(), true).await {
            Err(CompatError::C2pcGarbledTableMismatch(0))
                if matches!(case, C2pcTamperCase::GarbledTable) =>
            {
                Ok(())
            }
            Err(CompatError::C2pcOutputMacMismatch(0))
                if matches!(case, C2pcTamperCase::OutputMac) =>
            {
                Ok(())
            }
            Err(CompatError::C2pcOutputLabelMismatch(0))
                if matches!(case, C2pcTamperCase::OutputLabel) =>
            {
                Ok(())
            }
            Err(e) => Err(e),
            Ok(output) => {
                panic!("tampered C2PC online unexpectedly produced output {output:?} ({case:?})")
            }
        }
    }

    async fn send_phase_sync(stream: &mut EmpStream) -> Result<()> {
        stream.send_data(&[0xA5]).await?;
        stream.flush().await?;
        Ok(())
    }

    fn fpre_verification(fpre: &Fpre) -> FpreVerification {
        let params = fpre.params();
        FpreVerification {
            delta: fpre.delta(),
            batch_size: params.batch_size as u32,
            bucket_size: params.bucket_size as u32,
            permute_batch_size: params.permute_batch_size.unwrap_or(0) as u32,
        }
    }

    async fn send_fpre_verification(
        stream: &mut EmpStream,
        verification: FpreVerification,
    ) -> Result<()> {
        stream.send_block(&[verification.delta]).await?;
        stream
            .send_data(&verification.batch_size.to_le_bytes())
            .await?;
        stream
            .send_data(&verification.bucket_size.to_le_bytes())
            .await?;
        stream
            .send_data(&verification.permute_batch_size.to_le_bytes())
            .await?;
        stream.flush().await?;
        Ok(())
    }

    async fn recv_fpre_verification(stream: &mut EmpStream) -> Result<FpreVerification> {
        let delta = stream.recv_block(1).await?[0];
        let batch_size = recv_u32(stream).await?;
        let bucket_size = recv_u32(stream).await?;
        let permute_batch_size = recv_u32(stream).await?;
        Ok(FpreVerification {
            delta,
            batch_size,
            bucket_size,
            permute_batch_size,
        })
    }

    async fn recv_u32(stream: &mut EmpStream) -> Result<u32> {
        let bytes = stream.recv_data(4).await?;
        Ok(u32::from_le_bytes(bytes.try_into().expect("length")))
    }

    async fn send_fpre_generate_verification(
        stream: &mut EmpStream,
        delta: Block,
        key: &[Block],
    ) -> Result<()> {
        stream.send_block(&[delta]).await?;
        stream.send_block(key).await?;
        stream.flush().await?;
        Ok(())
    }

    async fn recv_fpre_generate_verification(
        stream: &mut EmpStream,
        length: usize,
    ) -> Result<(Block, Vec<Block>)> {
        let delta = stream.recv_block(1).await?[0];
        let key = stream.recv_block(length).await?;
        Ok((delta, key))
    }

    async fn send_fpre_check_verification(
        stream: &mut EmpStream,
        delta: Block,
        key: &[Block],
        digest: [u8; HASH_DIGEST_BYTES],
    ) -> Result<()> {
        stream.send_block(&[delta]).await?;
        stream.send_block(key).await?;
        stream.send_data(&digest).await?;
        stream.flush().await?;
        Ok(())
    }

    async fn recv_fpre_check_verification(
        stream: &mut EmpStream,
        length: usize,
    ) -> Result<(Block, Vec<Block>, [u8; HASH_DIGEST_BYTES])> {
        let delta = stream.recv_block(1).await?[0];
        let key = stream.recv_block(length).await?;
        let digest = stream
            .recv_data(HASH_DIGEST_BYTES)
            .await?
            .try_into()
            .expect("digest length");
        Ok((delta, key, digest))
    }

    async fn send_fpre_refill_verification(
        stream: &mut EmpStream,
        delta: Block,
        key: &[Block],
        mac_bits: &[u8],
    ) -> Result<()> {
        stream.send_block(&[delta]).await?;
        stream.send_block(key).await?;
        stream.send_data(mac_bits).await?;
        stream.flush().await?;
        Ok(())
    }

    async fn recv_fpre_refill_verification(
        stream: &mut EmpStream,
        length: usize,
    ) -> Result<(Block, Vec<Block>, Vec<u8>)> {
        let delta = stream.recv_block(1).await?[0];
        let key = stream.recv_block(length).await?;
        let mac_bits = stream.recv_data(length).await?;
        Ok((delta, key, mac_bits))
    }

    async fn send_c2pc_independent_verification(
        stream: &mut EmpStream,
        delta: Block,
        input_key: &[Block],
        preprocess_key: &[Block],
        ands_key: &[Block],
        ands_bits: &[u8],
    ) -> Result<()> {
        stream.send_block(&[delta]).await?;
        stream.send_block(input_key).await?;
        stream.send_block(preprocess_key).await?;
        stream.send_block(ands_key).await?;
        stream.send_data(ands_bits).await?;
        stream.flush().await?;
        Ok(())
    }

    async fn recv_c2pc_independent_verification(
        stream: &mut EmpStream,
        input_len: usize,
        total_pre: usize,
        ands_len: usize,
    ) -> Result<(Block, Vec<Block>, Vec<Block>, Vec<Block>, Vec<u8>)> {
        let delta = stream.recv_block(1).await?[0];
        let input_key = stream.recv_block(input_len).await?;
        let preprocess_key = stream.recv_block(total_pre).await?;
        let ands_key = stream.recv_block(ands_len).await?;
        let ands_bits = stream.recv_data(ands_len).await?;
        Ok((delta, input_key, preprocess_key, ands_key, ands_bits))
    }

    async fn send_c2pc_dependent_verification(
        stream: &mut EmpStream,
        delta: Block,
        key: &[Block],
        sigma_key: &[Block],
        garbled_table: &[u8],
    ) -> Result<()> {
        stream.send_block(&[delta]).await?;
        stream.send_block(key).await?;
        stream.send_block(sigma_key).await?;
        stream.send_data(garbled_table).await?;
        stream.flush().await?;
        Ok(())
    }

    async fn recv_c2pc_dependent_verification(
        stream: &mut EmpStream,
        wire_len: usize,
        sigma_len: usize,
        table_len: usize,
    ) -> Result<(Block, Vec<Block>, Vec<Block>, Vec<u8>)> {
        let delta = stream.recv_block(1).await?[0];
        let key = stream.recv_block(wire_len).await?;
        let sigma_key = stream.recv_block(sigma_len).await?;
        let garbled_table = stream.recv_data(table_len).await?;
        Ok((delta, key, sigma_key, garbled_table))
    }

    fn assert_fpre_delta_bits(delta: Block, role: Role) {
        assert!(delta.get_lsb());
        assert_eq!((delta.as_bytes()[0] & 0b10) != 0, role == Role::Alice);
    }

    fn assert_fpre_params(verification: FpreVerification) {
        let params = FpreParams::for_size(LIVE_FPRE_REQUESTED_SIZE);
        assert_eq!(verification.batch_size, params.batch_size as u32);
        assert_eq!(verification.bucket_size, params.bucket_size as u32);
        assert_eq!(
            verification.permute_batch_size,
            params.permute_batch_size.unwrap_or(0) as u32
        );
    }

    fn assert_fpre_generate_relation(mac: &[Block], remote_delta: Block, remote_key: &[Block]) {
        assert_eq!(mac.len(), remote_key.len());
        for i in 0..mac.len() {
            let expected = if mac[i].get_lsb() {
                remote_key[i].xor(remote_delta)
            } else {
                remote_key[i]
            };
            assert_eq!(mac[i], expected);
        }
    }

    fn fpre_mac_bits(mac: &[Block]) -> Vec<u8> {
        mac.iter().map(|block| u8::from(block.get_lsb())).collect()
    }

    fn assert_fpre_triple_relation(local_bits: &[u8], remote_bits: &[u8]) {
        assert_eq!(local_bits.len(), remote_bits.len());
        assert_eq!(local_bits.len() % 3, 0);
        for i in 0..local_bits.len() / 3 {
            let a = (local_bits[3 * i] != 0) != (remote_bits[3 * i] != 0);
            let b = (local_bits[3 * i + 1] != 0) != (remote_bits[3 * i + 1] != 0);
            let c = (local_bits[3 * i + 2] != 0) != (remote_bits[3 * i + 2] != 0);
            assert_eq!(a & b, c, "Fpre triple relation mismatch at {i}");
        }
    }

    async fn send_sender_verification(
        stream: &mut EmpStream,
        delta: Block,
        sender_data: &[Block],
    ) -> Result<()> {
        stream.send_block(&[delta]).await?;
        stream.send_block(sender_data).await?;
        stream.flush().await?;
        Ok(())
    }

    async fn recv_sender_verification(
        stream: &mut EmpStream,
        length: usize,
    ) -> Result<(Block, Vec<Block>)> {
        let delta = stream.recv_block(1).await?[0];
        let sender_data = stream.recv_block(length).await?;
        Ok((delta, sender_data))
    }

    fn assert_iknp_relation(
        receiver_data: &[Block],
        choices: &[bool],
        delta: Block,
        sender_data: &[Block],
    ) {
        assert_eq!(receiver_data.len(), choices.len());
        assert_eq!(receiver_data.len(), sender_data.len());
        for i in 0..receiver_data.len() {
            let expected = if choices[i] {
                sender_data[i].xor(delta)
            } else {
                sender_data[i]
            };
            assert_eq!(receiver_data[i], expected);
        }
    }

    fn assert_leaky_relation(receiver_data: &[Block], delta: Block, sender_data: &[Block]) {
        assert_eq!(receiver_data.len(), sender_data.len());
        for i in 0..receiver_data.len() {
            let expected = if receiver_data[i].get_lsb() {
                sender_data[i].xor(delta)
            } else {
                sender_data[i]
            };
            assert_eq!(receiver_data[i], expected);
        }
    }

    fn cpp_otco_probe() -> PathBuf {
        let root = repo_root();
        let bin = root.join(".build/otco_probe");
        if !bin.exists() {
            let status = Command::new("make")
                .arg(".build/otco_probe")
                .current_dir(&root)
                .status()
                .unwrap();
            assert!(status.success(), "failed to build .build/otco_probe");
        }
        assert!(
            bin.exists(),
            ".build/otco_probe was not built by the Cargo build script or test setup"
        );
        bin
    }

    fn cpp_iknp_probe() -> PathBuf {
        let root = repo_root();
        let bin = root.join(".build/iknp_probe");
        if !bin.exists() {
            let status = Command::new("make")
                .arg(".build/iknp_probe")
                .current_dir(&root)
                .status()
                .unwrap();
            assert!(status.success(), "failed to build .build/iknp_probe");
        }
        assert!(
            bin.exists(),
            ".build/iknp_probe was not built by the Cargo build script or test setup"
        );
        bin
    }

    fn cpp_fpre_setup_probe() -> PathBuf {
        let root = repo_root();
        let bin = root.join(".build/fpre_setup_probe");
        if !bin.exists() {
            let status = Command::new("make")
                .arg(".build/fpre_setup_probe")
                .current_dir(&root)
                .status()
                .unwrap();
            assert!(status.success(), "failed to build .build/fpre_setup_probe");
        }
        assert!(
            bin.exists(),
            ".build/fpre_setup_probe was not built by the Cargo build script or test setup"
        );
        bin
    }

    fn cpp_fpre_generate_probe() -> PathBuf {
        let root = repo_root();
        let bin = root.join(".build/fpre_generate_probe");
        if !bin.exists() {
            let status = Command::new("make")
                .arg(".build/fpre_generate_probe")
                .current_dir(&root)
                .status()
                .unwrap();
            assert!(
                status.success(),
                "failed to build .build/fpre_generate_probe"
            );
        }
        assert!(
            bin.exists(),
            ".build/fpre_generate_probe was not built by the Cargo build script or test setup"
        );
        bin
    }

    fn cpp_fpre_check_probe() -> PathBuf {
        let root = repo_root();
        let bin = root.join(".build/fpre_check_probe");
        if !bin.exists() {
            let status = Command::new("make")
                .arg(".build/fpre_check_probe")
                .current_dir(&root)
                .status()
                .unwrap();
            assert!(status.success(), "failed to build .build/fpre_check_probe");
        }
        assert!(
            bin.exists(),
            ".build/fpre_check_probe was not built by the Cargo build script or test setup"
        );
        bin
    }

    fn cpp_fpre_refill_probe() -> PathBuf {
        let root = repo_root();
        let bin = root.join(".build/fpre_refill_probe");
        if !bin.exists() {
            let status = Command::new("make")
                .arg(".build/fpre_refill_probe")
                .current_dir(&root)
                .status()
                .unwrap();
            assert!(status.success(), "failed to build .build/fpre_refill_probe");
        }
        assert!(
            bin.exists(),
            ".build/fpre_refill_probe was not built by the Cargo build script or test setup"
        );
        bin
    }

    fn cpp_c2pc_independent_probe() -> PathBuf {
        let root = repo_root();
        let bin = root.join(".build/c2pc_independent_probe");
        if !bin.exists() {
            let status = Command::new("make")
                .arg(".build/c2pc_independent_probe")
                .current_dir(&root)
                .status()
                .unwrap();
            assert!(
                status.success(),
                "failed to build .build/c2pc_independent_probe"
            );
        }
        assert!(
            bin.exists(),
            ".build/c2pc_independent_probe was not built by the Cargo build script or test setup"
        );
        bin
    }

    fn cpp_c2pc_dependent_probe() -> PathBuf {
        let root = repo_root();
        let bin = root.join(".build/c2pc_dependent_probe");
        if !bin.exists() {
            let status = Command::new("make")
                .arg(".build/c2pc_dependent_probe")
                .current_dir(&root)
                .status()
                .unwrap();
            assert!(
                status.success(),
                "failed to build .build/c2pc_dependent_probe"
            );
        }
        assert!(
            bin.exists(),
            ".build/c2pc_dependent_probe was not built by the Cargo build script or test setup"
        );
        bin
    }

    fn cpp_c2pc_online_probe() -> PathBuf {
        let root = repo_root();
        let bin = root.join(".build/c2pc_online_probe");
        if !bin.exists() {
            let status = Command::new("make")
                .arg(".build/c2pc_online_probe")
                .current_dir(&root)
                .status()
                .unwrap();
            assert!(status.success(), "failed to build .build/c2pc_online_probe");
        }
        assert!(
            bin.exists(),
            ".build/c2pc_online_probe was not built by the Cargo build script or test setup"
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
