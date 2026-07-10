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
