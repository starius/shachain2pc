use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;
use openssl::bn::{BigNum, BigNumContext, BigNumRef};
use openssl::ec::{EcGroup, EcPoint, EcPointRef, PointConversionForm};
use openssl::error::ErrorStack;
use openssl::nid::Nid;
use openssl::rand::rand_bytes;
use sha2::{Digest, Sha256};
use shachain2pc_emp_wire::{Block, EmpStream, EmpStreams, WireError, BLOCK_BYTES};
use shachain2pc_types::Role;
use std::fmt;
use zeroize::Zeroize;

pub const HASH_DIGEST_BYTES: usize = 32;
pub const POINT_BYTES: usize = 65;
pub const IKNP_SECURITY_BITS: usize = 128;
pub const IKNP_BLOCK_SIZE: usize = 2048;
pub const FPRE_THREADS: usize = 1;

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
}

pub struct FpreGenerated {
    pub mac: Vec<Block>,
    pub key: Vec<Block>,
}

impl Drop for FpreGenerated {
    fn drop(&mut self) {
        self.mac.zeroize();
        self.key.zeroize();
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
    let mut rows = Vec::with_capacity(IKNP_SECURITY_BITS * row_bytes);
    for i in 0..IKNP_SECURITY_BITS {
        let mut row = state.g0[i].random_data(row_bytes);
        let received = stream.recv_data(row_bytes).await?;
        if state.s[i] {
            xor_bytes_in_place(&mut row, &received);
        }
        rows.extend_from_slice(&row);
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
    let mut rows = Vec::with_capacity(IKNP_SECURITY_BITS * row_bytes);
    for i in 0..IKNP_SECURITY_BITS {
        let row0 = state.g0[i].random_data(row_bytes);
        let row1 = state.g1[i].random_data(row_bytes);
        let mut message = vec![0u8; row_bytes];
        for (j, r_block) in r.iter().enumerate().take(blocks_per_row) {
            let start = j * BLOCK_BYTES;
            let r_bytes = r_block.as_bytes();
            for k in 0..BLOCK_BYTES {
                message[start + k] = row0[start + k] ^ row1[start + k] ^ r_bytes[k];
            }
        }
        stream.send_data(&message).await?;
        rows.extend_from_slice(&row0);
    }
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
    let mut out = Vec::with_capacity(length);
    for _ in 0..length {
        let mut bytes = [0u8; BLOCK_BYTES];
        rand_bytes(&mut bytes)?;
        out.push(Block::from_bytes(bytes));
    }
    Ok(out)
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
    use std::net::{IpAddr, Ipv4Addr, TcpListener as StdTcpListener};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use tokio::time::{timeout, Duration};

    const LIVE_INTEROP_TIMEOUT: Duration = Duration::from_secs(60);
    const LIVE_IKNP_LENGTH: usize = 2051;
    const LIVE_LEAKY_LENGTH: usize = 257;
    const LIVE_FPRE_REQUESTED_SIZE: usize = 321;
    const LIVE_FPRE_GENERATE_LENGTH: usize = 683;

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
    async fn live_cpp_otco_interop() {
        let bin = cpp_otco_probe();
        for transport in [TestTransport::Listen, TestTransport::Connect] {
            run_live_otco_case(&bin, transport, TestOtRole::Send).await;
            run_live_otco_case(&bin, transport, TestOtRole::Recv).await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn live_cpp_fpre_setup_interop() {
        let bin = cpp_fpre_setup_probe();
        run_live_fpre_setup_case(&bin, Role::Alice).await;
        run_live_fpre_setup_case(&bin, Role::Bob).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn live_cpp_fpre_generate_interop() {
        let bin = cpp_fpre_generate_probe();
        run_live_fpre_generate_case(&bin, Role::Alice).await;
        run_live_fpre_generate_case(&bin, Role::Bob).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn live_cpp_iknp_and_leaky_interop() {
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

    fn free_port() -> u16 {
        StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }
}
