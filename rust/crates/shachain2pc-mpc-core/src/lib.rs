#![feature(portable_simd)]

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;
use sha2::{Digest, Sha256};
use shachain2pc_emp_wire::{Block, BLOCK_BYTES};
use shachain2pc_mpc_types::{LogicalChannel, MessageKind, MpcFrame, SessionStart, SessionStartAck};
use shachain2pc_types::Role;
use std::fmt;
use zeroize::Zeroize;

const SESSION_ACK_DOMAIN: &[u8] = b"shachain2pc-mpc-core/session-start-ack/v1";
pub const REVEAL_DIGEST_BYTES: usize = 32;

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

pub struct Ag2pcTriplePoolState {
    pub party: Role,
    pub ssp: usize,
    pub delta: Block,
    pub cots_minted_since_check: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Ag2pcTriplePoolError {
    BadInputShape,
    CotLength {
        expected: usize,
        actual: usize,
    },
    PeerBitLength {
        expected: usize,
        actual: usize,
    },
    BufferLength {
        name: &'static str,
        expected: usize,
        actual: usize,
    },
}

impl fmt::Display for Ag2pcTriplePoolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadInputShape => write!(f, "AG2PC input share vectors differ in length"),
            Self::CotLength { expected, actual } => {
                write!(
                    f,
                    "AG2PC COT length mismatch: expected {expected}, got {actual}"
                )
            }
            Self::PeerBitLength { expected, actual } => write!(
                f,
                "AG2PC peer bit length mismatch: expected {expected}, got {actual}"
            ),
            Self::BufferLength {
                name,
                expected,
                actual,
            } => write!(
                f,
                "AG2PC {name} length mismatch: expected {expected}, got {actual}"
            ),
        }
    }
}

impl std::error::Error for Ag2pcTriplePoolError {}

pub struct Ag2pcComputeBuffer {
    l: usize,
    bucket: usize,
    rep_a_lsb: Vec<u8>,
    rep_b_lsb: Vec<u8>,
    pub acc_mac: Vec<Block>,
    pub acc_key: Vec<Block>,
}

impl Ag2pcComputeBuffer {
    pub fn new(
        pool: &Ag2pcTriplePoolState,
        mut rep_a: Vec<AShareBundle>,
        mut rep_b: Vec<AShareBundle>,
    ) -> Result<Self, Ag2pcTriplePoolError> {
        if rep_a.len() != rep_b.len() {
            return Err(Ag2pcTriplePoolError::BadInputShape);
        }
        let l = rep_a.len();
        let bucket = pool.get_bucket_size(l);
        let mut acc_mac = vec![Block::zero(); 3 * l];
        let mut acc_key = vec![Block::zero(); 3 * l];
        let mut rep_a_lsb = Vec::with_capacity(l);
        let mut rep_b_lsb = Vec::with_capacity(l);
        for i in 0..l {
            acc_mac[i] = rep_a[i].mac;
            acc_key[i] = rep_a[i].key;
            acc_mac[l + i] = rep_b[i].mac;
            acc_key[l + i] = rep_b[i].key;
            rep_a_lsb.push(block_lsb(rep_a[i].mac));
            rep_b_lsb.push(block_lsb(rep_b[i].mac));
        }
        rep_a.zeroize();
        rep_b.zeroize();
        Ok(Self {
            l,
            bucket,
            rep_a_lsb,
            rep_b_lsb,
            acc_mac,
            acc_key,
        })
    }

    pub fn l(&self) -> usize {
        self.l
    }

    pub fn bucket(&self) -> usize {
        self.bucket
    }

    pub fn insert_random_cots(
        &mut self,
        mut r_mac: Vec<Block>,
        mut r_key: Vec<Block>,
    ) -> Result<(), Ag2pcTriplePoolError> {
        if r_mac.len() != self.l {
            return Err(Ag2pcTriplePoolError::CotLength {
                expected: self.l,
                actual: r_mac.len(),
            });
        }
        if r_key.len() != self.l {
            return Err(Ag2pcTriplePoolError::CotLength {
                expected: self.l,
                actual: r_key.len(),
            });
        }
        let l = self.l;
        self.acc_mac[2 * l..3 * l].copy_from_slice(&r_mac);
        self.acc_key[2 * l..3 * l].copy_from_slice(&r_key);
        r_mac.zeroize();
        r_key.zeroize();
        Ok(())
    }

    pub fn opening_bits(&self) -> (Vec<u8>, Vec<u8>) {
        let l = self.l;
        let mut xb_me = vec![0u8; l];
        let mut yb_me = vec![0u8; l];
        for i in 0..l {
            xb_me[i] = self.rep_a_lsb[i] ^ block_lsb(self.acc_mac[i]);
            yb_me[i] = self.rep_b_lsb[i] ^ block_lsb(self.acc_mac[l + i]);
        }
        (xb_me, yb_me)
    }

    pub fn finish(
        &self,
        pool: &Ag2pcTriplePoolState,
        xb_me: &[u8],
        yb_me: &[u8],
        xb_peer: &[u8],
        yb_peer: &[u8],
    ) -> Result<Vec<AShareBundle>, Ag2pcTriplePoolError> {
        let l = self.l;
        for bits in [xb_me, yb_me, xb_peer, yb_peer] {
            if bits.len() != l {
                return Err(Ag2pcTriplePoolError::PeerBitLength {
                    expected: l,
                    actual: bits.len(),
                });
            }
        }
        let mut out = vec![AShareBundle::default(); l];
        let dxor = pool.delta.xor(bit0_mask());
        for i in 0..l {
            let xb = xb_me[i] ^ xb_peer[i];
            let yb = yb_me[i] ^ yb_peer[i];
            let mut mac = self.acc_mac[2 * l + i]
                .xor(select_block(xb).and(self.acc_mac[l + i]))
                .xor(select_block(yb).and(self.acc_mac[i]));
            let mut key = self.acc_key[2 * l + i]
                .xor(select_block(xb).and(self.acc_key[l + i]))
                .xor(select_block(yb).and(self.acc_key[i]));
            let both = select_block(xb & yb);
            if pool.party == Role::Alice {
                mac = mac.xor(both.and(bit0_mask()));
            } else {
                key = key.xor(both.and(dxor));
            }
            out[i] = AShareBundle { mac, key };
        }
        Ok(out)
    }
}

impl Drop for Ag2pcComputeBuffer {
    fn drop(&mut self) {
        self.rep_a_lsb.zeroize();
        self.rep_b_lsb.zeroize();
        self.acc_mac.zeroize();
        self.acc_key.zeroize();
    }
}

impl Ag2pcTriplePoolState {
    pub fn new(party: Role, ssp: usize, delta: Block) -> Self {
        Self {
            party,
            ssp,
            delta,
            cots_minted_since_check: false,
        }
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

    pub fn mark_cots_minted(&mut self) {
        self.cots_minted_since_check = true;
    }

    pub fn should_flush_cot_check(&self) -> bool {
        self.cots_minted_since_check
    }

    pub fn mark_cot_check_flushed(&mut self) {
        self.cots_minted_since_check = false;
    }

    pub fn leaky_and_prepare_g(
        &self,
        mac: &[Block],
        key: &[Block],
        l: usize,
        gmitc: &mut Mitccrh8,
    ) -> Result<Vec<Block>, Ag2pcTriplePoolError> {
        require_len("mac", mac.len(), 3 * l)?;
        require_len("key", key.len(), 3 * l)?;
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
            gmitc.hash(&mut pad, 8, 2);
            for j in 0..batch {
                let k = k0 + j;
                let c = select_block(block_lsb(mac[l + k]))
                    .and(self.delta)
                    .xor(key[l + k])
                    .xor(mac[l + k]);
                g_blocks.push(pad[2 * j].xor(pad[2 * j + 1]).xor(c));
            }
        }
        Ok(g_blocks)
    }

    pub fn leaky_and_prepare_s(
        &self,
        mac: &[Block],
        key: &[Block],
        l: usize,
        emitc: &mut Mitccrh8,
        mut w_blocks: Vec<Block>,
    ) -> Result<(Vec<u8>, Vec<Block>), Ag2pcTriplePoolError> {
        require_len("mac", mac.len(), 3 * l)?;
        require_len("key", key.len(), 3 * l)?;
        require_len("W blocks", w_blocks.len(), l)?;
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
            emitc.hash(&mut pad, 8, 2);
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
        w_blocks.zeroize();
        let s_me = sout.iter().map(|block| block_lsb1(*block)).collect();
        Ok((s_me, sout))
    }

    pub fn leaky_and_finish(
        &self,
        mac: &mut [Block],
        key: &mut [Block],
        l: usize,
        s_me: &[u8],
        s_peer: &[u8],
        mut sout: Vec<Block>,
        feq: &mut Sha256,
    ) -> Result<(), Ag2pcTriplePoolError> {
        require_len("mac", mac.len(), 3 * l)?;
        require_len("key", key.len(), 3 * l)?;
        require_len("s_me", s_me.len(), l)?;
        require_len("s_peer", s_peer.len(), l)?;
        require_len("sout", sout.len(), l)?;
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
        feq.update(Block::slice_as_bytes(&sout));
        sout.zeroize();
        Ok(())
    }
}

impl Drop for Ag2pcTriplePoolState {
    fn drop(&mut self) {
        self.delta.zeroize();
    }
}

fn require_len(
    name: &'static str,
    actual: usize,
    expected: usize,
) -> Result<(), Ag2pcTriplePoolError> {
    if actual != expected {
        return Err(Ag2pcTriplePoolError::BufferLength {
            name,
            expected,
            actual,
        });
    }
    Ok(())
}

pub struct Prp {
    cipher: Aes128,
}

impl Prp {
    #[inline]
    pub fn new(key: Block) -> Self {
        Self {
            cipher: Aes128::new(GenericArray::from_slice(key.as_bytes())),
        }
    }

    #[inline]
    pub fn zero_key() -> Self {
        Self::new(Block::zero())
    }

    #[inline]
    pub fn permute_block(&self, blocks: &mut [Block]) {
        // Block is repr(transparent) over [u8; 16], the same layout as
        // aes::Block, so this preserves the existing batched AES-NI path.
        let aes_blocks: &mut [aes::Block] = unsafe {
            std::slice::from_raw_parts_mut(blocks.as_mut_ptr().cast::<aes::Block>(), blocks.len())
        };
        self.cipher.encrypt_blocks(aes_blocks);
    }

    #[inline]
    pub fn permute_one(&self, block: Block) -> Block {
        let mut aes_block = GenericArray::clone_from_slice(block.as_bytes());
        self.cipher.encrypt_block(&mut aes_block);
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&aes_block);
        Block::from_bytes(bytes)
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
        let prp = Prp::new(Block::from_bytes(key));
        key.zeroize();
        Self { prp, counter: 0 }
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

pub const SOFTSPOKEN_K: usize = 4;
pub const SOFTSPOKEN_N: usize = 128 / SOFTSPOKEN_K;
pub const SOFTSPOKEN_Q: usize = 1 << SOFTSPOKEN_K;
pub const SOFTSPOKEN_CHUNK_BLOCKS: usize = 64;
pub const SOFTSPOKEN_CHUNK_OTS: usize = SOFTSPOKEN_CHUNK_BLOCKS * 128;
pub const SOFTSPOKEN_PPRF_CHECK_HIGH: u64 = 0x7050_5246_434b_5f00;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SoftSpokenStateError {
    BadDeltaRole,
    MaliciousCheckMismatch,
    PprfBufferLength { expected: usize, actual: usize },
    PprfDigestLength { expected: usize, actual: usize },
    PprfCheckMismatch,
    BaseOtLength { expected: usize, actual: usize },
}

impl fmt::Display for SoftSpokenStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadDeltaRole => write!(
                f,
                "SoftSpoken delta can only be set before Alice setup starts"
            ),
            Self::MaliciousCheckMismatch => write!(f, "SoftSpoken malicious check mismatch"),
            Self::PprfBufferLength { expected, actual } => write!(
                f,
                "SoftSpoken PPRF buffer length mismatch: expected {expected}, got {actual}"
            ),
            Self::PprfDigestLength { expected, actual } => write!(
                f,
                "SoftSpoken PPRF digest length mismatch: expected {expected}, got {actual}"
            ),
            Self::PprfCheckMismatch => write!(f, "SoftSpoken PPRF check mismatch"),
            Self::BaseOtLength { expected, actual } => write!(
                f,
                "SoftSpoken base OT length mismatch: expected {expected}, got {actual}"
            ),
        }
    }
}

impl std::error::Error for SoftSpokenStateError {}

pub struct SoftSpoken4State {
    pub role: Role,
    pub malicious: bool,
    pub setup_done: bool,
    pub delta: Block,
    pub delta_bool: [bool; 128],
    pub choice_prg: Prg,
    pub session: u64,
    pub cur_send_session: u64,
    pub cur_recv_session: u64,
    pub cur_send_b0: u64,
    pub cur_recv_b0: u64,
    pub leftover: Vec<Block>,
    pub leftover_pos: usize,
    pub leftover_count: usize,
    pub alphas: [usize; SOFTSPOKEN_N],
    pub leaves_recv: Vec<Block>,
    pub leaves_send: Vec<Block>,
    pub check_q: Block,
    pub check_t: Block,
    pub check_x: Block,
}

impl SoftSpoken4State {
    pub fn new(role: Role, malicious: bool, delta: Block, choice_seed: Block) -> Self {
        let (delta, delta_bool) = if role == Role::Alice {
            (delta, block_to_bools(delta))
        } else {
            (Block::zero(), [false; 128])
        };
        Self {
            role,
            malicious,
            setup_done: false,
            delta,
            delta_bool,
            choice_prg: Prg::new(choice_seed, 0),
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
        }
    }

    pub fn set_delta(&mut self, delta: Block) -> Result<(), SoftSpokenStateError> {
        if self.setup_done || self.role != Role::Alice {
            return Err(SoftSpokenStateError::BadDeltaRole);
        }
        self.delta = delta;
        self.delta_bool = block_to_bools(delta);
        Ok(())
    }

    pub fn reset_leftover(&mut self) {
        self.leftover_pos = 0;
        self.leftover_count = 0;
    }

    pub fn drain_leftover(&mut self, out: &mut [Block]) -> usize {
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

    pub fn begin_send_session(&mut self) {
        self.cur_send_session = self.session;
        self.session += 1;
        self.cur_send_b0 = 0;
        if self.malicious {
            self.check_q = Block::zero();
        }
    }

    pub fn begin_recv_session(&mut self) {
        self.cur_recv_session = self.session;
        self.session += 1;
        self.cur_recv_b0 = 0;
        if self.malicious {
            self.check_t = Block::zero();
            self.check_x = Block::zero();
        }
    }

    pub fn verify_send_check(
        &self,
        check_x: Block,
        check_t: Block,
    ) -> Result<(), SoftSpokenStateError> {
        let lhs = self.check_q.xor(gf_mul(check_x, self.delta));
        if lhs != check_t {
            return Err(SoftSpokenStateError::MaliciousCheckMismatch);
        }
        Ok(())
    }

    pub fn recv_check_blocks(&self) -> (Block, Block) {
        (self.check_x, self.check_t)
    }

    pub fn bootstrap_send_choices(&mut self) -> Vec<bool> {
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
        choices
    }

    pub fn bootstrap_send_apply_received(
        &mut self,
        received: &[Block],
    ) -> Result<(), SoftSpokenStateError> {
        if received.len() != SOFTSPOKEN_N * SOFTSPOKEN_K {
            return Err(SoftSpokenStateError::BaseOtLength {
                expected: SOFTSPOKEN_N * SOFTSPOKEN_K,
                actual: received.len(),
            });
        }
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
        Ok(())
    }

    pub fn bootstrap_recv_keys(&mut self) -> (Vec<Block>, Vec<Block>) {
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
        (k0, k1)
    }

    pub fn mark_setup_done(&mut self) {
        self.setup_done = true;
    }

    pub fn pprf_check_send_prepare(&mut self) -> (Vec<Block>, [u8; REVEAL_DIGEST_BYTES]) {
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
        (t_buf, hash.finalize().into())
    }

    pub fn pprf_check_recv_verify(
        &mut self,
        t_buf: &[Block],
        their_digest: &[u8],
    ) -> Result<(), SoftSpokenStateError> {
        if t_buf.len() != SOFTSPOKEN_N * 2 {
            return Err(SoftSpokenStateError::PprfBufferLength {
                expected: SOFTSPOKEN_N * 2,
                actual: t_buf.len(),
            });
        }
        if their_digest.len() != REVEAL_DIGEST_BYTES {
            return Err(SoftSpokenStateError::PprfDigestLength {
                expected: REVEAL_DIGEST_BYTES,
                actual: their_digest.len(),
            });
        }

        let check_key = Prp::new(Block::make(SOFTSPOKEN_PPRF_CHECK_HIGH, 0));
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
        if hash.finalize().as_slice() != their_digest {
            return Err(SoftSpokenStateError::PprfCheckMismatch);
        }
        Ok(())
    }

    pub fn send_chunk_prepare(&mut self, bs: usize) -> Vec<Block> {
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
        planes
    }

    pub fn send_chunk_finish(
        &mut self,
        mut planes: Vec<Block>,
        d_bufs: &[Block],
        transcript_seed: Option<Block>,
        bs: usize,
    ) -> Result<Vec<Block>, SoftSpokenStateError> {
        let expected = (SOFTSPOKEN_N - 1) * bs;
        if d_bufs.len() != expected {
            return Err(SoftSpokenStateError::BaseOtLength {
                expected,
                actual: d_bufs.len(),
            });
        }
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
        if let Some(seed) = transcript_seed {
            self.combine_send_chunk(seed, &out, bs);
        }
        self.cur_send_b0 += bs as u64;
        Ok(out)
    }

    pub fn recv_chunk_prepare(&mut self, bs: usize) -> (Vec<Block>, Vec<Block>, Vec<Block>) {
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
        planes[..bs].copy_from_slice(&u_canonical);
        let out = transpose_softspoken_planes(&planes, bs);
        (d_bufs, out, u_canonical)
    }

    pub fn recv_chunk_finish(
        &mut self,
        transcript_seed: Option<Block>,
        out: &[Block],
        u_canonical: &[Block],
        bs: usize,
    ) {
        if let Some(seed) = transcript_seed {
            self.combine_recv_chunk(seed, out, u_canonical, bs);
        }
        self.cur_recv_b0 += bs as u64;
    }

    fn combine_send_chunk(&mut self, transcript_seed: Block, out: &[Block], bs: usize) {
        let mut chi_prg = Prg::new(transcript_seed, 0);
        let chi = chi_prg.random_block(bs);
        let packed: Vec<Block> = (0..bs)
            .map(|i| gf_pack_128(&out[i * 128..(i + 1) * 128]))
            .collect();
        self.check_q = self.check_q.xor(gf_inner_product(&chi, &packed));
    }

    fn combine_recv_chunk(
        &mut self,
        transcript_seed: Block,
        out: &[Block],
        u_canonical: &[Block],
        bs: usize,
    ) {
        let mut chi_prg = Prg::new(transcript_seed, 0);
        let chi = chi_prg.random_block(bs);
        let packed: Vec<Block> = (0..bs)
            .map(|i| gf_pack_128(&out[i * 128..(i + 1) * 128]))
            .collect();
        self.check_t = self.check_t.xor(gf_inner_product(&chi, &packed));
        self.check_x = self.check_x.xor(gf_inner_product(&chi, u_canonical));
    }
}

const CGGM_LSB_CLEAR_MASK: Block = Block::from_bytes([
    0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
]);

fn ccrh_hash(block: Block) -> Block {
    let sigma = block.sigma();
    Prp::zero_key().permute_one(sigma).xor(sigma)
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
    let mut r = vec![Block::zero(); q];
    let mut inputs = vec![Block::zero(); q];

    for j in 0..bs {
        let ctr = Block::make(0, counter_base + j as u64);
        for (dst, leaf) in inputs.iter_mut().zip(leaves) {
            *dst = ctr.xor(*leaf);
        }
        r.copy_from_slice(&inputs);
        key.permute_block(&mut r);
        for (rx, inp) in r.iter_mut().zip(&inputs) {
            *rx = rx.xor(*inp);
        }

        let mut n = q;
        for b in 0..k {
            let half = n >> 1;
            let mut acc = Block::zero();
            for y in 0..half {
                let lo = r[2 * y];
                let hi = r[2 * y + 1];
                acc = acc.xor(hi);
                r[y] = lo.xor(hi);
            }
            v[b * bs + j] = acc;
            n = half;
        }
        u[j] = r[0];
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
    let mut r = vec![Block::zero(); q];
    let mut inputs = vec![Block::zero(); q];

    for j in 0..bs {
        let ctr = Block::make(0, counter_base + j as u64);
        for (y, dst) in inputs.iter_mut().enumerate() {
            *dst = ctr.xor(leaves[alpha ^ y]);
        }
        r.copy_from_slice(&inputs);
        key.permute_block(&mut r);
        for (rx, inp) in r.iter_mut().zip(&inputs) {
            *rx = rx.xor(*inp);
        }

        let mut n = q;
        for b in 0..k {
            let half = n >> 1;
            let mut acc = Block::zero();
            for y in 0..half {
                let lo = r[2 * y];
                let hi = r[2 * y + 1];
                acc = acc.xor(hi);
                r[y] = lo.xor(hi);
            }
            w[b * bs + j] = acc;
            n = half;
        }
    }
    w
}

pub struct Mitccrh8 {
    start_point: Block,
    gid: u64,
    key_used: usize,
    scheduled_bucket: Option<u64>,
    scheduled_keys: Vec<Prp>,
}

impl Mitccrh8 {
    pub fn new(seed: Block) -> Self {
        Self {
            start_point: seed,
            gid: 0,
            key_used: 8,
            scheduled_bucket: None,
            scheduled_keys: Vec::new(),
        }
    }

    pub fn hash(&mut self, blocks: &mut [Block], k: usize, h: usize) {
        self.hash_inner(blocks, k, h, false);
    }

    #[allow(dead_code)]
    pub fn hash_cir(&mut self, blocks: &mut [Block], k: usize, h: usize) {
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

fn aes_dm(key: &Prp, counter: u64, tweak: Block) -> Block {
    let pt = Block::make(0, counter).xor(tweak);
    key.permute_one(pt).xor(pt)
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

pub fn transpose_softspoken_planes(planes: &[Block], bs: usize) -> Vec<Block> {
    // planes are already 128 contiguous rows of bs blocks each, so view them as
    // bytes directly instead of copying into a scratch buffer first.
    transpose_128_rows(Block::slice_as_bytes(planes), bs * BLOCK_BYTES, bs * 128)
}

pub fn transpose_128_rows(rows: &[u8], row_bytes: usize, output_len: usize) -> Vec<Block> {
    transpose_128_rows_simd(rows, row_bytes, output_len)
}

fn transpose_16x16_bytes(m: [core::simd::u8x16; 16]) -> [core::simd::u8x16; 16] {
    use core::simd::{u16x8, u32x4, u64x2, u8x16};
    let mut t = [u8x16::splat(0); 16];
    for i in 0..8 {
        let (lo, hi) = m[2 * i].interleave(m[2 * i + 1]);
        t[2 * i] = lo;
        t[2 * i + 1] = hi;
    }
    // SAFETY: u8x16/u16x8/u32x4/u64x2 are all 128-bit repr(simd); the [_; 16]
    // arrays have identical size and alignment, so the bitcasts are sound.
    let t16: [u16x8; 16] = unsafe { core::mem::transmute(t) };
    let mut u = [u16x8::splat(0); 16];
    for i in 0..4 {
        let (lo, hi) = t16[4 * i].interleave(t16[4 * i + 2]);
        u[4 * i] = lo;
        u[4 * i + 1] = hi;
        let (lo, hi) = t16[4 * i + 1].interleave(t16[4 * i + 3]);
        u[4 * i + 2] = lo;
        u[4 * i + 3] = hi;
    }
    let u32v: [u32x4; 16] = unsafe { core::mem::transmute(u) };
    let mut v = [u32x4::splat(0); 16];
    for i in 0..2 {
        for k in 0..4 {
            let (lo, hi) = u32v[8 * i + k].interleave(u32v[8 * i + k + 4]);
            v[8 * i + 2 * k] = lo;
            v[8 * i + 2 * k + 1] = hi;
        }
    }
    let v64: [u64x2; 16] = unsafe { core::mem::transmute(v) };
    let mut r = [u64x2::splat(0); 16];
    for k in 0..8 {
        let (lo, hi) = v64[k].interleave(v64[k + 8]);
        r[2 * k] = lo;
        r[2 * k + 1] = hi;
    }
    unsafe { core::mem::transmute(r) }
}

fn transpose_emit_column(
    out: &mut [Block],
    mut col: core::simd::u8x16,
    source_byte: usize,
    row_group: usize,
) {
    use core::simd::cmp::SimdPartialOrd;
    use core::simd::u8x16;
    let msb = u8x16::splat(0x80);
    let one = u8x16::splat(1);
    for bit in (0..8).rev() {
        let mask = col.simd_ge(msb).to_bitmask() as u16;
        let ob = out[source_byte * 8 + bit].as_mut_bytes();
        ob[row_group * 2] = mask as u8;
        ob[row_group * 2 + 1] = (mask >> 8) as u8;
        col <<= one;
    }
}

// Portable-SIMD bit-matrix transpose of a 128-row matrix (std::simd, so the same
// code targets AVX2 on x86_64 and NEON on aarch64). It loads 16 contiguous bytes
// per row, transposes each 16x16 byte tile in registers (transpose_16x16_bytes),
// then peels off the bits with movemask -- avoiding the strided per-byte gather
// of the naive form.
fn transpose_128_rows_simd(rows: &[u8], row_bytes: usize, output_len: usize) -> Vec<Block> {
    use core::simd::u8x16;
    const ROWS: usize = 128;
    const ROW_GROUPS: usize = ROWS / 16;
    debug_assert_eq!(output_len, row_bytes * 8);
    debug_assert_eq!(rows.len(), ROWS * row_bytes);
    let mut out = vec![Block::zero(); output_len];
    let col_tiles = row_bytes / 16;
    for rg in 0..ROW_GROUPS {
        for cg in 0..col_tiles {
            let mut m = [u8x16::splat(0); 16];
            for (r, slot) in m.iter_mut().enumerate() {
                let off = (rg * 16 + r) * row_bytes + cg * 16;
                *slot = u8x16::from_slice(&rows[off..off + 16]);
            }
            let cols = transpose_16x16_bytes(m);
            for (c, col) in cols.into_iter().enumerate() {
                transpose_emit_column(&mut out, col, cg * 16 + c, rg);
            }
        }
    }
    // Tail: any columns past the last full 16-byte tile (only hit when row_bytes
    // is not a multiple of 16, e.g. the row_bytes=1 unit test). Gather per
    // column.
    let mut lane = [0u8; 16];
    for source_byte in (col_tiles * 16)..row_bytes {
        for rg in 0..ROW_GROUPS {
            let base = rg * 16;
            for (i, slot) in lane.iter_mut().enumerate() {
                *slot = rows[(base + i) * row_bytes + source_byte];
            }
            transpose_emit_column(&mut out, u8x16::from_array(lane), source_byte, rg);
        }
    }
    out
}

#[cfg(test)]
fn transpose_128_rows_soft(rows: &[u8], row_bytes: usize, output_len: usize) -> Vec<Block> {
    debug_assert_eq!(output_len, row_bytes * 8);
    let mut out = vec![Block::zero(); output_len];
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
                out[source_byte * 8 + bit].as_mut_bytes()[group] = transposed[bit];
            }
        }
    }
    out
}

#[cfg(test)]
fn transpose_8x8(mut x: u64) -> u64 {
    let mut t = (x ^ (x >> 7)) & 0x00AA_00AA_00AA_00AA;
    x ^= t ^ (t << 7);
    t = (x ^ (x >> 14)) & 0x0000_CCCC_0000_CCCC;
    x ^= t ^ (t << 14);
    t = (x ^ (x >> 28)) & 0x0000_0000_F0F0_F0F0;
    x ^= t ^ (t << 28);
    x
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevealLocalShare {
    pub share_bits: Vec<u8>,
    pub mac_digest: [u8; REVEAL_DIGEST_BYTES],
}

pub fn reveal_local_share(wire_bundle: &[AShareBundle]) -> RevealLocalShare {
    let share_bits = wire_bundle.iter().map(|wire| block_lsb(wire.mac)).collect();
    let mut hash = Sha256::new();
    for wire in wire_bundle {
        hash.update(wire.mac.as_bytes());
    }
    RevealLocalShare {
        share_bits,
        mac_digest: hash.finalize().into(),
    }
}

pub fn reveal_recipient_bits(
    lambda: &[u8],
    wire_bundle: &[AShareBundle],
    peer_share: &[u8],
    peer_digest: [u8; REVEAL_DIGEST_BYTES],
    delta: Block,
) -> RevealResult<Vec<u8>> {
    if lambda.len() != wire_bundle.len() {
        return Err(RevealError::BadWireShape {
            lambda_len: lambda.len(),
            bundle_len: wire_bundle.len(),
        });
    }
    verify_peer_mac_digest(wire_bundle, peer_share, peer_digest, delta)
        .map_err(RevealError::from_peer_check)?;

    let local = reveal_local_share(wire_bundle);
    Ok((0..wire_bundle.len())
        .map(|i| local.share_bits[i] ^ lambda[i] ^ (peer_share[i] & 1))
        .map(|bit| bit & 1)
        .collect())
}

pub fn finalize_input_open(
    wire_bundle: &[AShareBundle],
    own_x_bits: &[u8],
    peer_indices: &[usize],
    peer_share: &[u8],
    peer_digest: [u8; REVEAL_DIGEST_BYTES],
    peer_x_bits: &[u8],
    delta: Block,
) -> InputOpenResult<Vec<u8>> {
    let n = wire_bundle.len();
    if own_x_bits.len() != n {
        return Err(InputOpenError::OwnInputLength {
            expected: n,
            actual: own_x_bits.len(),
        });
    }
    if peer_x_bits.len() != peer_indices.len() {
        return Err(InputOpenError::PeerInputLength {
            expected: peer_indices.len(),
            actual: peer_x_bits.len(),
        });
    }
    for &idx in peer_indices {
        if idx >= n {
            return Err(InputOpenError::PeerInputIndex { index: idx, len: n });
        }
    }
    verify_peer_mac_digest(wire_bundle, peer_share, peer_digest, delta)
        .map_err(InputOpenError::from_peer_check)?;

    let local = reveal_local_share(wire_bundle);
    let mut lambda: Vec<u8> = (0..n)
        .map(|i| local.share_bits[i] ^ (peer_share[i] & 1) ^ (own_x_bits[i] & 1))
        .map(|bit| bit & 1)
        .collect();
    for (i, &wire_index) in peer_indices.iter().enumerate() {
        lambda[wire_index] ^= peer_x_bits[i] & 1;
    }
    Ok(lambda)
}

pub fn verify_share_relation(
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

#[cfg(any(test, not(all(target_arch = "x86_64", target_feature = "pclmulqdq"))))]
fn block_to_u128(block: Block) -> u128 {
    u128::from_le_bytes(block.into_bytes())
}

#[cfg(any(test, not(all(target_arch = "x86_64", target_feature = "pclmulqdq"))))]
fn u128_to_block(value: u128) -> Block {
    Block::from_bytes(value.to_le_bytes())
}

#[cfg(all(target_arch = "x86_64", target_feature = "pclmulqdq"))]
#[inline]
pub fn gf_mul(a: Block, b: Block) -> Block {
    // SAFETY: target_feature(pclmulqdq) and x86_64's baseline SSE2 guarantee the
    // carryless-multiply intrinsics are available.
    unsafe { gf_mul_clmul(a, b) }
}

#[cfg(not(all(target_arch = "x86_64", target_feature = "pclmulqdq")))]
#[inline]
pub fn gf_mul(a: Block, b: Block) -> Block {
    gf_mul_soft(a, b)
}

#[cfg(any(test, not(all(target_arch = "x86_64", target_feature = "pclmulqdq"))))]
fn gf_mul_soft(a: Block, b: Block) -> Block {
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

#[cfg(all(target_arch = "x86_64", target_feature = "pclmulqdq"))]
#[inline]
unsafe fn gf_mul_clmul(a: Block, b: Block) -> Block {
    use core::arch::x86_64::*;

    let a = _mm_loadu_si128(a.as_bytes().as_ptr().cast());
    let b = _mm_loadu_si128(b.as_bytes().as_ptr().cast());
    let g = _mm_set_epi64x(0, 0x87);

    let t0 = _mm_clmulepi64_si128(a, b, 0x00);
    let t3 = _mm_clmulepi64_si128(a, b, 0x11);
    let t1 = _mm_clmulepi64_si128(a, b, 0x01);
    let t2 = _mm_clmulepi64_si128(a, b, 0x10);
    let mid = _mm_xor_si128(t1, t2);
    let p_lo = _mm_xor_si128(t0, _mm_slli_si128(mid, 8));
    let p_hi = _mm_xor_si128(t3, _mm_srli_si128(mid, 8));

    let c0 = _mm_clmulepi64_si128(p_hi, g, 0x00);
    let c1 = _mm_clmulepi64_si128(p_hi, g, 0x01);
    let q_lo = _mm_xor_si128(c0, _mm_slli_si128(c1, 8));
    let q_hi = _mm_srli_si128(c1, 8);
    let e = _mm_clmulepi64_si128(q_hi, g, 0x00);
    let res = _mm_xor_si128(_mm_xor_si128(p_lo, q_lo), e);

    let mut out = [0u8; 16];
    _mm_storeu_si128(out.as_mut_ptr().cast(), res);
    Block::from_bytes(out)
}

#[cfg(any(test, not(all(target_arch = "x86_64", target_feature = "pclmulqdq"))))]
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

#[cfg(any(test, not(all(target_arch = "x86_64", target_feature = "pclmulqdq"))))]
fn gf_bit(words: &[u64; 4], bit: usize) -> bool {
    ((words[bit / 64] >> (bit % 64)) & 1) != 0
}

#[cfg(any(test, not(all(target_arch = "x86_64", target_feature = "pclmulqdq"))))]
fn gf_flip(words: &mut [u64; 4], bit: usize) {
    words[bit / 64] ^= 1u64 << (bit % 64);
}

#[cfg(any(test, not(all(target_arch = "x86_64", target_feature = "pclmulqdq"))))]
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

pub fn gf_inner_product(a: &[Block], b: &[Block]) -> Block {
    assert_eq!(a.len(), b.len());
    a.iter()
        .zip(b)
        .fold(Block::zero(), |acc, (lhs, rhs)| acc.xor(gf_mul(*lhs, *rhs)))
}

#[cfg(all(target_arch = "x86_64", target_feature = "pclmulqdq"))]
pub fn gf_pack_128(data: &[Block]) -> Block {
    // SAFETY: target_feature(pclmulqdq) and x86_64's baseline SSE2 guarantee the
    // intrinsics are available.
    unsafe { gf_pack_128_clmul(data) }
}

#[cfg(not(all(target_arch = "x86_64", target_feature = "pclmulqdq")))]
pub fn gf_pack_128(data: &[Block]) -> Block {
    gf_pack_128_soft(data)
}

#[cfg(any(test, not(all(target_arch = "x86_64", target_feature = "pclmulqdq"))))]
fn gf_pack_128_soft(data: &[Block]) -> Block {
    assert_eq!(data.len(), 128);
    let mut product = [0u64; 4];
    for (shift, block) in data.iter().enumerate() {
        xor_shifted_u128(&mut product, block_to_u128(*block), shift);
    }
    gf_reduce(product)
}

#[cfg(all(target_arch = "x86_64", target_feature = "pclmulqdq"))]
unsafe fn gf_pack_128_clmul(data: &[Block]) -> Block {
    use core::arch::x86_64::*;

    assert_eq!(data.len(), 128);
    let ld = |i: usize| _mm_loadu_si128(data[i].as_bytes().as_ptr().cast());
    let mut lo = _mm_setzero_si128();
    let mut hi = _mm_setzero_si128();

    macro_rules! bit {
        ($base:expr, $b:literal, $clo:ident, $chi:ident) => {{
            let d = ld($base + $b);
            let s = _mm_slli_epi64(d, $b);
            let c = _mm_srli_epi64(d, 64 - $b);
            $clo = _mm_xor_si128($clo, _mm_xor_si128(s, _mm_slli_si128(c, 8)));
            $chi = _mm_xor_si128($chi, _mm_srli_si128(c, 8));
        }};
    }
    macro_rules! pack_byte {
        ($boff:literal) => {{
            let base = $boff * 8;
            let mut clo = ld(base);
            let mut chi = _mm_setzero_si128();
            bit!(base, 1, clo, chi);
            bit!(base, 2, clo, chi);
            bit!(base, 3, clo, chi);
            bit!(base, 4, clo, chi);
            bit!(base, 5, clo, chi);
            bit!(base, 6, clo, chi);
            bit!(base, 7, clo, chi);
            if $boff == 0 {
                lo = _mm_xor_si128(lo, clo);
                hi = _mm_xor_si128(hi, chi);
            } else {
                lo = _mm_xor_si128(lo, _mm_slli_si128(clo, $boff));
                hi = _mm_xor_si128(
                    hi,
                    _mm_xor_si128(_mm_srli_si128(clo, 16 - $boff), _mm_slli_si128(chi, $boff)),
                );
            }
        }};
    }

    pack_byte!(0);
    pack_byte!(1);
    pack_byte!(2);
    pack_byte!(3);
    pack_byte!(4);
    pack_byte!(5);
    pack_byte!(6);
    pack_byte!(7);
    pack_byte!(8);
    pack_byte!(9);
    pack_byte!(10);
    pack_byte!(11);
    pack_byte!(12);
    pack_byte!(13);
    pack_byte!(14);
    pack_byte!(15);

    let g = _mm_set_epi64x(0, 0x87);
    let c0 = _mm_clmulepi64_si128(hi, g, 0x00);
    let c1 = _mm_clmulepi64_si128(hi, g, 0x01);
    let q_lo = _mm_xor_si128(c0, _mm_slli_si128(c1, 8));
    let q_hi = _mm_srli_si128(c1, 8);
    let e = _mm_clmulepi64_si128(q_hi, g, 0x00);
    let res = _mm_xor_si128(_mm_xor_si128(lo, q_lo), e);

    let mut out = [0u8; 16];
    _mm_storeu_si128(out.as_mut_ptr().cast(), res);
    Block::from_bytes(out)
}

pub type RevealResult<T> = std::result::Result<T, RevealError>;
pub type InputOpenResult<T> = std::result::Result<T, InputOpenError>;

#[derive(Clone, Debug, Eq, PartialEq)]
enum PeerMacCheckError {
    PeerShareLength { expected: usize, actual: usize },
    MacDigestMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RevealError {
    BadWireShape {
        lambda_len: usize,
        bundle_len: usize,
    },
    PeerShareLength {
        expected: usize,
        actual: usize,
    },
    MacDigestMismatch,
}

impl RevealError {
    fn from_peer_check(value: PeerMacCheckError) -> Self {
        match value {
            PeerMacCheckError::PeerShareLength { expected, actual } => {
                Self::PeerShareLength { expected, actual }
            }
            PeerMacCheckError::MacDigestMismatch => Self::MacDigestMismatch,
        }
    }
}

impl fmt::Display for RevealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadWireShape {
                lambda_len,
                bundle_len,
            } => write!(
                f,
                "bad reveal wire shape: lambda={lambda_len}, bundle={bundle_len}"
            ),
            Self::PeerShareLength { expected, actual } => write!(
                f,
                "bad reveal peer share length: expected {expected}, got {actual}"
            ),
            Self::MacDigestMismatch => write!(f, "reveal MAC digest mismatch"),
        }
    }
}

impl std::error::Error for RevealError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InputOpenError {
    OwnInputLength { expected: usize, actual: usize },
    PeerShareLength { expected: usize, actual: usize },
    PeerInputLength { expected: usize, actual: usize },
    PeerInputIndex { index: usize, len: usize },
    MacDigestMismatch,
}

impl InputOpenError {
    fn from_peer_check(value: PeerMacCheckError) -> Self {
        match value {
            PeerMacCheckError::PeerShareLength { expected, actual } => {
                Self::PeerShareLength { expected, actual }
            }
            PeerMacCheckError::MacDigestMismatch => Self::MacDigestMismatch,
        }
    }
}

impl fmt::Display for InputOpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OwnInputLength { expected, actual } => write!(
                f,
                "bad input-open own input length: expected {expected}, got {actual}"
            ),
            Self::PeerShareLength { expected, actual } => write!(
                f,
                "bad input-open peer share length: expected {expected}, got {actual}"
            ),
            Self::PeerInputLength { expected, actual } => write!(
                f,
                "bad input-open peer input length: expected {expected}, got {actual}"
            ),
            Self::PeerInputIndex { index, len } => write!(
                f,
                "bad input-open peer input index {index} for length {len}"
            ),
            Self::MacDigestMismatch => write!(f, "input-open MAC digest mismatch"),
        }
    }
}

impl std::error::Error for InputOpenError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelFlow {
    job_id: Vec<u8>,
    local_role: Role,
    channel: LogicalChannel,
    next_send: u64,
    next_recv: u64,
    aborted: bool,
}

impl ChannelFlow {
    pub fn new(job_id: Vec<u8>, local_role: Role, channel: LogicalChannel) -> Self {
        Self {
            job_id,
            local_role,
            channel,
            next_send: 0,
            next_recv: 0,
            aborted: false,
        }
    }

    pub fn job_id(&self) -> &[u8] {
        &self.job_id
    }

    pub fn local_role(&self) -> Role {
        self.local_role
    }

    pub fn channel(&self) -> LogicalChannel {
        self.channel
    }

    pub fn next_send(&self) -> u64 {
        self.next_send
    }

    pub fn next_recv(&self) -> u64 {
        self.next_recv
    }

    pub fn is_aborted(&self) -> bool {
        self.aborted
    }

    pub fn abort(mut self) -> Self {
        self.aborted = true;
        self
    }

    pub fn outbound_frame(
        self,
        kind: MessageKind,
        payload: Vec<u8>,
    ) -> StepResult<(Self, MpcFrame)> {
        if self.aborted {
            return Err(StepError::new(self, CoreError::Aborted));
        }
        let sequence = self.next_send;
        let frame = MpcFrame::new(
            self.job_id.clone(),
            self.local_role,
            self.channel,
            sequence,
            kind,
            payload,
        )
        .map_err(|err| StepError::new(self.clone(), CoreError::Frame(err.to_string())))?;
        self.accept_outbound(frame)
    }

    pub fn accept_outbound(mut self, frame: MpcFrame) -> StepResult<(Self, MpcFrame)> {
        if self.aborted {
            return Err(StepError::new(self, CoreError::Aborted));
        }
        if frame.job_id != self.job_id {
            return Err(aborting_error(self, CoreError::JobMismatch));
        }
        if frame.sender_role != self.local_role {
            let expected = self.local_role;
            let got = frame.sender_role;
            return Err(aborting_error(
                self,
                CoreError::RoleMismatch { expected, got },
            ));
        }
        if frame.channel != self.channel {
            let expected = self.channel;
            let got = frame.channel;
            return Err(aborting_error(
                self,
                CoreError::ChannelMismatch { expected, got },
            ));
        }
        if frame.sequence != self.next_send {
            let expected = self.next_send;
            let got = frame.sequence;
            return Err(aborting_error(
                self,
                CoreError::SequenceMismatch { expected, got },
            ));
        }
        self.next_send = self.next_send.saturating_add(1);
        Ok((self, frame))
    }

    pub fn accept_inbound(mut self, frame: MpcFrame) -> StepResult<(Self, MpcFrame)> {
        if self.aborted {
            return Err(StepError::new(self, CoreError::Aborted));
        }
        if frame.job_id != self.job_id {
            return Err(aborting_error(self, CoreError::JobMismatch));
        }
        if frame.sender_role == self.local_role {
            let expected = opposite_role(self.local_role);
            let got = frame.sender_role;
            return Err(aborting_error(
                self,
                CoreError::RoleMismatch { expected, got },
            ));
        }
        if frame.channel != self.channel {
            let expected = self.channel;
            let got = frame.channel;
            return Err(aborting_error(
                self,
                CoreError::ChannelMismatch { expected, got },
            ));
        }
        if frame.sequence != self.next_recv {
            let expected = self.next_recv;
            let got = frame.sequence;
            return Err(aborting_error(
                self,
                CoreError::SequenceMismatch { expected, got },
            ));
        }
        self.next_recv = self.next_recv.saturating_add(1);
        Ok((self, frame))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionParams {
    pub ssp: u32,
    pub circuit_digest: Vec<u8>,
    pub job_binding: Vec<u8>,
}

impl SessionParams {
    pub fn new(ssp: u32, circuit_digest: Vec<u8>, job_binding: Vec<u8>) -> Self {
        Self {
            ssp,
            circuit_digest,
            job_binding,
        }
    }

    pub fn to_start(&self) -> SessionStart {
        SessionStart {
            ssp: self.ssp,
            circuit_digest: self.circuit_digest.clone(),
            job_binding: self.job_binding.clone(),
        }
    }
}

impl From<SessionStart> for SessionParams {
    fn from(value: SessionStart) -> Self {
        Self {
            ssp: value.ssp,
            circuit_digest: value.circuit_digest,
            job_binding: value.job_binding,
        }
    }
}

pub fn send_session_start(
    flow: ChannelFlow,
    params: &SessionParams,
) -> StepResult<(ChannelFlow, MpcFrame)> {
    require_main(flow)?.outbound_frame(MessageKind::SessionStart, params.to_start().encode_to_vec())
}

pub fn receive_session_start_and_ack(
    flow: ChannelFlow,
    expected: &SessionParams,
    frame: MpcFrame,
) -> StepResult<(ChannelFlow, MpcFrame)> {
    let flow = require_main(flow)?;
    let (flow, frame) = flow.accept_inbound(frame)?;
    require_kind(flow, &frame, MessageKind::SessionStart).and_then(|flow| {
        let start = SessionStart::decode(&frame.payload)
            .map_err(|err| aborting_error(flow.clone(), CoreError::Frame(err.to_string())))?;
        compare_session_params(flow, expected, &SessionParams::from(start)).and_then(|flow| {
            let ack = session_start_ack(flow.job_id(), flow.local_role(), expected);
            flow.outbound_frame(MessageKind::SessionStartAck, ack.encode_to_vec())
        })
    })
}

pub fn receive_session_start_ack(
    flow: ChannelFlow,
    expected: &SessionParams,
    frame: MpcFrame,
) -> StepResult<ChannelFlow> {
    let flow = require_main(flow)?;
    let (flow, frame) = flow.accept_inbound(frame)?;
    require_kind(flow, &frame, MessageKind::SessionStartAck).and_then(|flow| {
        let ack = SessionStartAck::decode(&frame.payload)
            .map_err(|err| aborting_error(flow.clone(), CoreError::Frame(err.to_string())))?;
        let expected_ack = session_start_ack(flow.job_id(), frame.sender_role, expected);
        if ack != expected_ack {
            return Err(aborting_error(flow, CoreError::SessionAckMismatch));
        }
        Ok(flow)
    })
}

pub type StepResult<T> = Result<T, StepError>;

#[derive(Debug, Eq, PartialEq)]
pub struct StepError {
    state: ChannelFlow,
    error: CoreError,
}

impl StepError {
    pub fn new(state: ChannelFlow, error: CoreError) -> Self {
        Self { state, error }
    }

    pub fn state(&self) -> &ChannelFlow {
        &self.state
    }

    pub fn error(&self) -> &CoreError {
        &self.error
    }

    pub fn into_parts(self) -> (ChannelFlow, CoreError) {
        (self.state, self.error)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoreError {
    Aborted,
    JobMismatch,
    WrongChannelForPhase {
        expected: LogicalChannel,
        got: LogicalChannel,
    },
    RoleMismatch {
        expected: Role,
        got: Role,
    },
    ChannelMismatch {
        expected: LogicalChannel,
        got: LogicalChannel,
    },
    SequenceMismatch {
        expected: u64,
        got: u64,
    },
    UnexpectedMessageKind {
        expected: MessageKind,
        got: MessageKind,
    },
    SessionParameterMismatch {
        field: &'static str,
    },
    SessionAckMismatch,
    Frame(String),
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aborted => write!(f, "MPC job is aborted"),
            Self::JobMismatch => write!(f, "MPC frame job id does not match this state"),
            Self::WrongChannelForPhase { expected, got } => {
                write!(
                    f,
                    "MPC phase channel mismatch: expected {expected:?}, got {got:?}"
                )
            }
            Self::RoleMismatch { expected, got } => {
                write!(
                    f,
                    "MPC frame role mismatch: expected {expected:?}, got {got:?}"
                )
            }
            Self::ChannelMismatch { expected, got } => {
                write!(
                    f,
                    "MPC frame channel mismatch: expected {expected:?}, got {got:?}"
                )
            }
            Self::SequenceMismatch { expected, got } => {
                write!(
                    f,
                    "MPC frame sequence mismatch: expected {expected}, got {got}"
                )
            }
            Self::UnexpectedMessageKind { expected, got } => {
                write!(
                    f,
                    "MPC frame kind mismatch: expected {expected:?}, got {got:?}"
                )
            }
            Self::SessionParameterMismatch { field } => {
                write!(f, "MPC session parameter mismatch in {field}")
            }
            Self::SessionAckMismatch => write!(f, "MPC session-start ack mismatch"),
            Self::Frame(err) => write!(f, "invalid MPC frame: {err}"),
        }
    }
}

impl std::error::Error for CoreError {}

fn opposite_role(role: Role) -> Role {
    match role {
        Role::Alice => Role::Bob,
        Role::Bob => Role::Alice,
    }
}

fn require_main(flow: ChannelFlow) -> StepResult<ChannelFlow> {
    if flow.channel() != LogicalChannel::Main {
        let got = flow.channel();
        return Err(aborting_error(
            flow,
            CoreError::WrongChannelForPhase {
                expected: LogicalChannel::Main,
                got,
            },
        ));
    }
    Ok(flow)
}

fn require_kind(
    flow: ChannelFlow,
    frame: &MpcFrame,
    expected: MessageKind,
) -> StepResult<ChannelFlow> {
    if frame.kind != expected {
        return Err(aborting_error(
            flow,
            CoreError::UnexpectedMessageKind {
                expected,
                got: frame.kind,
            },
        ));
    }
    Ok(flow)
}

fn compare_session_params(
    flow: ChannelFlow,
    expected: &SessionParams,
    got: &SessionParams,
) -> StepResult<ChannelFlow> {
    if expected.ssp != got.ssp {
        return Err(aborting_error(
            flow,
            CoreError::SessionParameterMismatch { field: "ssp" },
        ));
    }
    if expected.circuit_digest != got.circuit_digest {
        return Err(aborting_error(
            flow,
            CoreError::SessionParameterMismatch {
                field: "circuit_digest",
            },
        ));
    }
    if expected.job_binding != got.job_binding {
        return Err(aborting_error(
            flow,
            CoreError::SessionParameterMismatch {
                field: "job_binding",
            },
        ));
    }
    Ok(flow)
}

fn aborting_error(flow: ChannelFlow, error: CoreError) -> StepError {
    StepError::new(flow.abort(), error)
}

fn session_start_ack(job_id: &[u8], sender_role: Role, params: &SessionParams) -> SessionStartAck {
    let mut hash = Sha256::new();
    hash.update(SESSION_ACK_DOMAIN);
    update_len_prefixed(&mut hash, job_id);
    hash.update([role_code(sender_role)]);
    hash.update(params.ssp.to_le_bytes());
    update_len_prefixed(&mut hash, &params.circuit_digest);
    update_len_prefixed(&mut hash, &params.job_binding);
    SessionStartAck {
        transcript_binding: hash.finalize().to_vec(),
    }
}

fn update_len_prefixed(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
}

fn role_code(role: Role) -> u8 {
    match role {
        Role::Alice => 1,
        Role::Bob => 2,
    }
}

fn verify_peer_mac_digest(
    wire_bundle: &[AShareBundle],
    peer_share: &[u8],
    peer_digest: [u8; REVEAL_DIGEST_BYTES],
    delta: Block,
) -> std::result::Result<(), PeerMacCheckError> {
    if peer_share.len() != wire_bundle.len() {
        return Err(PeerMacCheckError::PeerShareLength {
            expected: wire_bundle.len(),
            actual: peer_share.len(),
        });
    }

    let mut expected_hash = Sha256::new();
    for (wire, share) in wire_bundle.iter().zip(peer_share) {
        let expected_mac = wire.key.xor(select_block(*share).and(delta));
        expected_hash.update(expected_mac.as_bytes());
    }
    let expected_digest: [u8; REVEAL_DIGEST_BYTES] = expected_hash.finalize().into();
    if expected_digest != peer_digest {
        return Err(PeerMacCheckError::MacDigestMismatch);
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn auth_pair(
        local_bit: u8,
        peer_bit: u8,
        local_key_low: u64,
        peer_key_low: u64,
        local_delta: Block,
        peer_delta: Block,
    ) -> (AShareBundle, AShareBundle) {
        let local_key = Block::make(0, local_key_low & !1);
        let peer_key = Block::make(0, peer_key_low & !1);
        let local_mac = peer_key.xor(select_block(local_bit).and(peer_delta));
        let peer_mac = local_key.xor(select_block(peer_bit).and(local_delta));
        (
            AShareBundle {
                mac: local_mac,
                key: local_key,
            },
            AShareBundle {
                mac: peer_mac,
                key: peer_key,
            },
        )
    }

    fn auth_vectors() -> (Block, Block, Vec<AShareBundle>, Vec<AShareBundle>) {
        let local_delta = Block::make(0, 0x101);
        let peer_delta = Block::make(0, 0x201);
        let pairs = [
            auth_pair(1, 0, 0x10, 0x20, local_delta, peer_delta),
            auth_pair(0, 1, 0x30, 0x40, local_delta, peer_delta),
            auth_pair(1, 1, 0x50, 0x60, local_delta, peer_delta),
        ];
        let local = pairs.iter().map(|(local, _peer)| *local).collect();
        let peer = pairs.iter().map(|(_local, peer)| *peer).collect();
        (local_delta, peer_delta, local, peer)
    }

    #[test]
    fn transpose_128_rows_matches_bit_reference() {
        const ROWS: usize = 128;
        for row_bytes in [1usize, 16, 32, 256] {
            let output_len = row_bytes * 8;
            let mut rows = vec![0u8; ROWS * row_bytes];
            for (i, byte) in rows.iter_mut().enumerate() {
                *byte = ((i * 37 + i / 7 + 0x5a) & 0xff) as u8;
            }
            let reference = transpose_128_rows_bit_reference(&rows, row_bytes, output_len);
            assert_eq!(transpose_128_rows(&rows, row_bytes, output_len), reference);
            assert_eq!(
                transpose_128_rows_soft(&rows, row_bytes, output_len),
                reference
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
            for row in 0..128 {
                if (rows[row * row_bytes + source_byte] & source_mask) != 0 {
                    bytes[row / 8] |= 1 << (row % 8);
                }
            }
            *out_block = Block::from_bytes(bytes);
        }
        out
    }

    fn next_u64(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn next_block(state: &mut u64) -> Block {
        Block::make(next_u64(state), next_u64(state))
    }

    fn params() -> SessionParams {
        SessionParams::new(73, vec![0x11; 32], b"job-binding".to_vec())
    }

    fn frame(job_id: &[u8], sender_role: Role, channel: LogicalChannel, sequence: u64) -> MpcFrame {
        MpcFrame::new(
            job_id.to_vec(),
            sender_role,
            channel,
            sequence,
            MessageKind::ProgramRunRequest,
            Vec::new(),
        )
        .unwrap()
    }

    #[test]
    fn outbound_builder_assigns_sequence_and_advances() {
        let state = ChannelFlow::new(b"job".to_vec(), Role::Alice, LogicalChannel::Main);
        let (state, frame) = state
            .outbound_frame(MessageKind::SessionStart, vec![1, 2, 3])
            .unwrap();
        assert_eq!(frame.sequence, 0);
        assert_eq!(frame.sender_role, Role::Alice);
        assert_eq!(frame.channel, LogicalChannel::Main);
        assert_eq!(frame.payload, vec![1, 2, 3]);
        assert_eq!(state.next_send(), 1);
        assert_eq!(state.next_recv(), 0);
    }

    #[test]
    fn inbound_accepts_peer_sequence_and_advances() {
        let state = ChannelFlow::new(b"job".to_vec(), Role::Bob, LogicalChannel::Sibling);
        let (state, frame) = state
            .accept_inbound(frame(b"job", Role::Alice, LogicalChannel::Sibling, 0))
            .unwrap();
        assert_eq!(frame.sender_role, Role::Alice);
        assert_eq!(state.next_recv(), 1);
        assert_eq!(state.next_send(), 0);
    }

    #[test]
    fn sequence_gap_preserves_state_in_error() {
        let state = ChannelFlow::new(b"job".to_vec(), Role::Alice, LogicalChannel::Main);
        let err = state
            .accept_outbound(frame(b"job", Role::Alice, LogicalChannel::Main, 1))
            .unwrap_err();
        assert_eq!(
            err.error(),
            &CoreError::SequenceMismatch {
                expected: 0,
                got: 1,
            }
        );
        assert_eq!(err.state().next_send(), 0);
        assert!(err.state().is_aborted());
    }

    #[test]
    fn abort_poisoning_rejects_future_frames() {
        let state = ChannelFlow::new(b"job".to_vec(), Role::Alice, LogicalChannel::Main).abort();
        let err = state
            .accept_outbound(frame(b"job", Role::Alice, LogicalChannel::Main, 0))
            .unwrap_err();
        assert_eq!(err.error(), &CoreError::Aborted);
        assert!(err.state().is_aborted());
    }

    #[test]
    fn gf_mul_clmul_matches_soft() {
        let mut state = 0x7f4a_7c15_9e37_79b9;
        for _ in 0..5000 {
            let lhs = next_block(&mut state);
            let rhs = next_block(&mut state);
            assert_eq!(gf_mul(lhs, rhs), gf_mul_soft(lhs, rhs));
        }

        let one = Block::make(0, 1);
        let ones = Block::make(u64::MAX, u64::MAX);
        let hi = Block::make(1 << 63, 0);
        for &lhs in &[Block::zero(), one, ones, hi] {
            for &rhs in &[Block::zero(), one, ones, hi] {
                assert_eq!(gf_mul(lhs, rhs), gf_mul_soft(lhs, rhs));
            }
        }
    }

    #[test]
    fn gf_pack_128_clmul_matches_soft() {
        let mut state = 0x1234_5678_9abc_def0;
        for _ in 0..200 {
            let data: Vec<Block> = (0..128).map(|_| next_block(&mut state)).collect();
            assert_eq!(gf_pack_128(&data), gf_pack_128_soft(&data));
        }

        let zero = vec![Block::zero(); 128];
        assert_eq!(gf_pack_128(&zero), gf_pack_128_soft(&zero));
        let ones = vec![Block::make(u64::MAX, u64::MAX); 128];
        assert_eq!(gf_pack_128(&ones), gf_pack_128_soft(&ones));
        for i in 0..128 {
            let mut data = vec![Block::zero(); 128];
            data[i] = Block::make(u64::MAX, u64::MAX);
            assert_eq!(gf_pack_128(&data), gf_pack_128_soft(&data));
        }
    }

    #[test]
    fn reveal_recovers_authenticated_public_bits() {
        let (local_delta, peer_delta, local, peer) = auth_vectors();
        assert!(verify_share_relation(
            &local,
            local_delta,
            &peer,
            peer_delta
        ));
        let peer_open = reveal_local_share(&peer);
        let lambda = vec![1, 0, 1];
        let bits = reveal_recipient_bits(
            &lambda,
            &local,
            &peer_open.share_bits,
            peer_open.mac_digest,
            local_delta,
        )
        .unwrap();
        assert_eq!(bits, vec![0, 1, 1]);
    }

    #[test]
    fn reveal_rejects_digest_tamper_and_bad_shape() {
        let (local_delta, _peer_delta, local, peer) = auth_vectors();
        let mut peer_open = reveal_local_share(&peer);
        peer_open.mac_digest[0] ^= 1;
        let err = reveal_recipient_bits(
            &[1, 0, 1],
            &local,
            &peer_open.share_bits,
            peer_open.mac_digest,
            local_delta,
        )
        .unwrap_err();
        assert_eq!(err, RevealError::MacDigestMismatch);

        let err =
            reveal_recipient_bits(&[1, 0], &local, &[0, 1, 1], [0; 32], local_delta).unwrap_err();
        assert_eq!(
            err,
            RevealError::BadWireShape {
                lambda_len: 2,
                bundle_len: 3,
            }
        );

        let peer_open = reveal_local_share(&peer);
        let err = reveal_recipient_bits(
            &[1, 0, 1],
            &local,
            &[0, 1],
            peer_open.mac_digest,
            local_delta,
        )
        .unwrap_err();
        assert_eq!(
            err,
            RevealError::PeerShareLength {
                expected: 3,
                actual: 2,
            }
        );
    }

    #[test]
    fn input_open_finalizes_authenticated_lambdas() {
        let (local_delta, _peer_delta, local, peer) = auth_vectors();
        let peer_open = reveal_local_share(&peer);
        let lambda = finalize_input_open(
            &local,
            &[1, 0, 0],
            &[1],
            &peer_open.share_bits,
            peer_open.mac_digest,
            &[1],
            local_delta,
        )
        .unwrap();
        assert_eq!(lambda, vec![0, 0, 0]);
    }

    #[test]
    fn input_open_rejects_tamper_and_bad_peer_index() {
        let (local_delta, _peer_delta, local, peer) = auth_vectors();
        let mut peer_open = reveal_local_share(&peer);
        peer_open.mac_digest[0] ^= 1;
        let err = finalize_input_open(
            &local,
            &[1, 0, 0],
            &[1],
            &peer_open.share_bits,
            peer_open.mac_digest,
            &[1],
            local_delta,
        )
        .unwrap_err();
        assert_eq!(err, InputOpenError::MacDigestMismatch);

        let peer_open = reveal_local_share(&peer);
        let err = finalize_input_open(
            &local,
            &[1, 0, 0],
            &[3],
            &peer_open.share_bits,
            peer_open.mac_digest,
            &[1],
            local_delta,
        )
        .unwrap_err();
        assert_eq!(err, InputOpenError::PeerInputIndex { index: 3, len: 3 });
    }

    #[test]
    fn session_start_ack_round_trip_validates_params() {
        let job_id = b"session-job".to_vec();
        let params = params();
        let alice = ChannelFlow::new(job_id.clone(), Role::Alice, LogicalChannel::Main);
        let bob = ChannelFlow::new(job_id, Role::Bob, LogicalChannel::Main);

        let (alice, start) = send_session_start(alice, &params).unwrap();
        assert_eq!(start.kind, MessageKind::SessionStart);
        assert_eq!(alice.next_send(), 1);

        let (bob, ack) = receive_session_start_and_ack(bob, &params, start).unwrap();
        assert_eq!(ack.kind, MessageKind::SessionStartAck);
        assert_eq!(bob.next_recv(), 1);
        assert_eq!(bob.next_send(), 1);

        let alice = receive_session_start_ack(alice, &params, ack).unwrap();
        assert_eq!(alice.next_recv(), 1);
    }

    #[test]
    fn session_start_mismatch_aborts_after_receive() {
        let job_id = b"session-job".to_vec();
        let params = params();
        let mut peer_params = params.clone();
        peer_params.circuit_digest[0] ^= 1;

        let alice = ChannelFlow::new(job_id.clone(), Role::Alice, LogicalChannel::Main);
        let bob = ChannelFlow::new(job_id, Role::Bob, LogicalChannel::Main);
        let (_alice, start) = send_session_start(alice, &params).unwrap();
        let err = receive_session_start_and_ack(bob, &peer_params, start).unwrap_err();

        assert_eq!(
            err.error(),
            &CoreError::SessionParameterMismatch {
                field: "circuit_digest"
            }
        );
        assert!(err.state().is_aborted());
        assert_eq!(err.state().next_recv(), 1);
    }

    #[test]
    fn session_ack_tamper_aborts() {
        let job_id = b"session-job".to_vec();
        let params = params();
        let alice = ChannelFlow::new(job_id.clone(), Role::Alice, LogicalChannel::Main);
        let bob = ChannelFlow::new(job_id, Role::Bob, LogicalChannel::Main);
        let (alice, start) = send_session_start(alice, &params).unwrap();
        let (_bob, mut ack) = receive_session_start_and_ack(bob, &params, start).unwrap();
        let mut decoded = SessionStartAck::decode(&ack.payload).unwrap();
        decoded.transcript_binding[0] ^= 1;
        ack.payload = decoded.encode_to_vec();

        let err = receive_session_start_ack(alice, &params, ack).unwrap_err();
        assert_eq!(err.error(), &CoreError::SessionAckMismatch);
        assert!(err.state().is_aborted());
    }

    #[test]
    fn session_start_rejects_wrong_kind_and_sibling_channel() {
        let job_id = b"session-job".to_vec();
        let params = params();
        let bob = ChannelFlow::new(job_id.clone(), Role::Bob, LogicalChannel::Main);
        let wrong = MpcFrame::new(
            job_id.clone(),
            Role::Alice,
            LogicalChannel::Main,
            0,
            MessageKind::ProgramRunRequest,
            Vec::new(),
        )
        .unwrap();
        let err = receive_session_start_and_ack(bob, &params, wrong).unwrap_err();
        assert_eq!(
            err.error(),
            &CoreError::UnexpectedMessageKind {
                expected: MessageKind::SessionStart,
                got: MessageKind::ProgramRunRequest,
            }
        );
        assert!(err.state().is_aborted());

        let sibling = ChannelFlow::new(job_id, Role::Alice, LogicalChannel::Sibling);
        let err = send_session_start(sibling, &params).unwrap_err();
        assert_eq!(
            err.error(),
            &CoreError::WrongChannelForPhase {
                expected: LogicalChannel::Main,
                got: LogicalChannel::Sibling,
            }
        );
        assert!(err.state().is_aborted());
    }
}
