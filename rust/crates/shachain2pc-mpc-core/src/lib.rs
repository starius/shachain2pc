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
}

impl fmt::Display for SoftSpokenStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadDeltaRole => write!(
                f,
                "SoftSpoken delta can only be set before Alice setup starts"
            ),
            Self::MaliciousCheckMismatch => write!(f, "SoftSpoken malicious check mismatch"),
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

fn block_to_bools(block: Block) -> [bool; 128] {
    let bytes = block.into_bytes();
    let mut out = [false; 128];
    for i in 0..128 {
        out[i] = ((bytes[i / 8] >> (i % 8)) & 1) != 0;
    }
    out
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
