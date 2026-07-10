impl Ag2pcTriplePool {
    pub async fn setup<S: TranscriptIo>(
        streams: &mut Ag2pcStreams<S>,
        party: Role,
        ssp: usize,
    ) -> Result<Self> {
        let delta = random_ag2pc_delta(party)?;
        Self::setup_with_delta(streams, party, ssp, delta).await
    }

    pub async fn setup_with_delta<S: TranscriptIo>(
        streams: &mut Ag2pcStreams<S>,
        party: Role,
        ssp: usize,
        delta: Block,
    ) -> Result<Self> {
        if !streams.main.fs_enabled() {
            streams.main.enable_fs(party == Role::Alice)?;
        }
        if !streams.sibling.fs_enabled() {
            streams.sibling.enable_fs(party == Role::Alice)?;
        }

        let delta = normalize_ag2pc_delta(party, delta);
        let mut out = Self {
            state: Ag2pcTriplePoolState::new(party, ssp, delta),
            abit1: SoftSpoken4::new_with_delta(Role::Alice, true, delta)?,
            abit2: SoftSpoken4::new(Role::Bob, true)?,
        };
        out.begin_abits(streams).await?;
        Ok(out)
    }

    pub fn trim_idle_allocations(&mut self) {
        self.abit1.trim_idle_allocations();
        self.abit2.trim_idle_allocations();
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

    pub async fn draw<S: TranscriptIo>(
        &mut self,
        streams: &mut Ag2pcStreams<S>,
        count: usize,
    ) -> Result<Vec<AShareBundle>> {
        let (mac, key) = self.gen_cot_shares(streams, count).await?;
        Ok(mac
            .into_iter()
            .zip(key)
            .map(|(mac, key)| AShareBundle { mac, key })
            .collect())
    }

    pub async fn compute_inplace<S: TranscriptIo>(
        &mut self,
        streams: &mut Ag2pcStreams<S>,
        rep_a: &[AShareBundle],
        rep_b: &[AShareBundle],
    ) -> Result<Vec<AShareBundle>> {
        self.compute_inplace_owned(streams, rep_a.to_vec(), rep_b.to_vec())
            .await
    }

    pub async fn compute_inplace_owned<S: TranscriptIo>(
        &mut self,
        streams: &mut Ag2pcStreams<S>,
        rep_a: Vec<AShareBundle>,
        rep_b: Vec<AShareBundle>,
    ) -> Result<Vec<AShareBundle>> {
        let mut compute = Ag2pcComputeBuffer::new(self, rep_a, rep_b)
            .map_err(|_| CompatError::BadAg2pcInputShape)?;
        let l = compute.l();
        if l == 0 {
            return Ok(Vec::new());
        }
        let bucket = compute.bucket();
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

        let (r_mac, r_key) = self.gen_cot_shares(streams, l).await?;
        compute
            .insert_random_cots(r_mac, r_key)
            .map_err(|_| CompatError::BadAg2pcInputShape)?;
        self.leaky_and_halfgate(
            streams,
            &mut compute.acc_mac,
            &mut compute.acc_key,
            l,
            &mut hashes,
        )
        .await?;
        self.layered_bucket_into_acc(
            streams,
            &mut compute.acc_mac,
            &mut compute.acc_key,
            bucket,
            l,
            &mut hashes,
        )
        .await?;

        let dme: [u8; HASH_DIGEST_BYTES] = feq.finalize().into();
        ag2pc_feq_check(&mut streams.main, self.party, &dme).await?;

        let (xb_me, yb_me) = compute.opening_bits();
        let (xb_peer, yb_peer) = self
            .exchange_two_bool_vectors(streams, &xb_me, &yb_me, l)
            .await?;
        compute
            .finish(self, &xb_me, &yb_me, &xb_peer, &yb_peer)
            .map_err(|_| CompatError::BadAg2pcInputShape)
    }

    pub async fn maybe_flush_cot_check<S: TranscriptIo>(
        &mut self,
        streams: &mut Ag2pcStreams<S>,
    ) -> Result<()> {
        if self.should_flush_cot_check() {
            self.flush_cot_check(streams).await?;
        }
        Ok(())
    }

    pub async fn flush_cot_check<S: TranscriptIo>(
        &mut self,
        streams: &mut Ag2pcStreams<S>,
    ) -> Result<()> {
        self.mark_cot_check_flushed();
        self.end_abits(streams).await?;
        self.begin_abits(streams).await
    }

    pub async fn end<S: TranscriptIo>(&mut self, streams: &mut Ag2pcStreams<S>) -> Result<()> {
        self.mark_cot_check_flushed();
        self.end_abits(streams).await
    }

    async fn gen_cot_shares<S: TranscriptIo>(
        &mut self,
        streams: &mut Ag2pcStreams<S>,
        count: usize,
    ) -> Result<(Vec<Block>, Vec<Block>)> {
        self.mark_cots_minted();
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

    async fn leaky_and_halfgate<S: TranscriptIo>(
        &mut self,
        streams: &mut Ag2pcStreams<S>,
        mac: &mut [Block],
        key: &mut [Block],
        l: usize,
        hashes: &mut Ag2pcComputeHashes<'_>,
    ) -> Result<()> {
        let mut g_blocks = self
            .leaky_and_prepare_g(mac, key, l, hashes.gmitc)
            .map_err(|_| CompatError::BadAg2pcInputShape)?;
        let w_blocks = self.exchange_blocks(streams, &g_blocks, l).await?;
        g_blocks.zeroize();
        drop(g_blocks);
        let (s_me, sout) = self
            .leaky_and_prepare_s(mac, key, l, hashes.emitc, w_blocks)
            .map_err(|_| CompatError::BadAg2pcInputShape)?;
        let s_peer = self.exchange_bool_vector(streams, &s_me, l).await?;
        self.leaky_and_finish(
            Ag2pcShareSlicesMut { mac, key },
            l,
            &s_me,
            &s_peer,
            sout,
            hashes.feq,
        )
        .map_err(|_| CompatError::BadAg2pcInputShape)
    }

    async fn layered_bucket_into_acc<S: TranscriptIo>(
        &mut self,
        streams: &mut Ag2pcStreams<S>,
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
            let r = Ag2pcTriplePoolState::bucket_shift(seed, l);
            self.bucket_one_layer(
                streams,
                Ag2pcShareSlicesMut {
                    mac: acc_mac,
                    key: acc_key,
                },
                Ag2pcLayerSlices {
                    mac: &sac_mac,
                    key: &sac_key,
                },
                l,
                r,
            )
            .await?;
        }
        Ok(())
    }

    async fn bucket_one_layer<S: TranscriptIo>(
        &mut self,
        streams: &mut Ag2pcStreams<S>,
        acc: Ag2pcShareSlicesMut<'_>,
        layer: Ag2pcLayerSlices<'_>,
        l: usize,
        r: usize,
    ) -> Result<()> {
        let Ag2pcShareSlicesMut {
            mac: acc_mac,
            key: acc_key,
        } = acc;
        let d_me = self
            .bucket_prepare_layer(
                Ag2pcShareSlicesMut {
                    mac: &mut *acc_mac,
                    key: &mut *acc_key,
                },
                layer,
                l,
                r,
            )
            .map_err(|_| CompatError::BadAg2pcInputShape)?;
        let d_peer = self.exchange_bool_vector(streams, &d_me, l).await?;
        self.bucket_finish_layer(
            Ag2pcShareSlicesMut {
                mac: &mut *acc_mac,
                key: &mut *acc_key,
            },
            layer,
            l,
            r,
            &d_me,
            &d_peer,
        )
        .map_err(|_| CompatError::BadAg2pcInputShape)
    }

    async fn exchange_blocks<S: TranscriptIo>(
        &mut self,
        streams: &mut Ag2pcStreams<S>,
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

    async fn exchange_bool_vector<S: TranscriptIo>(
        &mut self,
        streams: &mut Ag2pcStreams<S>,
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

    async fn exchange_two_bool_vectors<S: TranscriptIo>(
        &mut self,
        streams: &mut Ag2pcStreams<S>,
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

    async fn begin_abits<S: TranscriptIo>(&mut self, streams: &mut Ag2pcStreams<S>) -> Result<()> {
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

    async fn end_abits<S: TranscriptIo>(&mut self, streams: &mut Ag2pcStreams<S>) -> Result<()> {
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

async fn ag2pc_begin_flush<S: TranscriptIo>(soft: &mut SoftSpoken4, stream: &mut S) -> Result<()> {
    soft.begin(stream).await?;
    stream.flush().await?;
    Ok(())
}

async fn ag2pc_next_n_flush<S: TranscriptIo>(
    soft: &mut SoftSpoken4,
    stream: &mut S,
    count: usize,
) -> Result<Vec<Block>> {
    let out = soft.next_n(stream, count).await?;
    stream.flush().await?;
    Ok(out)
}

async fn ag2pc_end_flush<S: TranscriptIo>(soft: &mut SoftSpoken4, stream: &mut S) -> Result<()> {
    soft.end(stream).await?;
    stream.flush().await?;
    Ok(())
}

async fn ag2pc_send_blocks<S: ByteIo>(stream: &mut S, blocks: &[Block]) -> Result<()> {
    stream.send_block(blocks).await?;
    stream.flush().await?;
    Ok(())
}

async fn ag2pc_recv_blocks<S: ByteIo>(stream: &mut S, len: usize) -> Result<Vec<Block>> {
    Ok(stream.recv_block(len).await?)
}

async fn ag2pc_send_bool_vector<S: ByteIo>(stream: &mut S, data: &[u8]) -> Result<()> {
    stream.send_data(&ag2pc_pack_bools(data)).await?;
    stream.flush().await?;
    Ok(())
}

async fn ag2pc_recv_bool_vector<S: ByteIo>(stream: &mut S, len: usize) -> Result<Vec<u8>> {
    let encoded = stream.recv_data(ag2pc_bool_wire_len(len)).await?;
    Ok(ag2pc_unpack_bools(&encoded, len))
}

async fn ag2pc_send_two_bool_vectors<S: ByteIo>(
    stream: &mut S,
    first: &[u8],
    second: &[u8],
) -> Result<()> {
    stream.send_data(&ag2pc_pack_bools(first)).await?;
    stream.send_data(&ag2pc_pack_bools(second)).await?;
    stream.flush().await?;
    Ok(())
}

async fn ag2pc_recv_two_bool_vectors<S: ByteIo>(
    stream: &mut S,
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

async fn ag2pc_feq_check<S: ByteIo>(
    stream: &mut S,
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
    Ok(normalize_ag2pc_delta(party, random_block()?))
}

pub fn normalize_ag2pc_delta(party: Role, delta: Block) -> Block {
    let mut bytes = delta.into_bytes();
    bytes[0] |= 1;
    if party == Role::Alice {
        bytes[0] |= 2;
    } else {
        bytes[0] &= !2;
    }
    Block::from_bytes(bytes)
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

pub fn verify_ag2pc_share_relation(
    local: &[AShareBundle],
    local_delta: Block,
    peer: &[AShareBundle],
    peer_delta: Block,
) -> bool {
    verify_share_relation(local, local_delta, peer, peer_delta)
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

#[cfg(test)]
fn transpose_128_rows(rows: &[u8], row_bytes: usize, output_len: usize) -> Vec<Block> {
    transpose_128_rows_simd(rows, row_bytes, output_len)
}

// Transpose a 16x16 byte tile held as 16 rows of u8x16, via 4 interleave stages
// (epi8/16/32/64). On 128-bit vectors std::simd's interleave is a single-lane
// zip, i.e. exactly _mm_unpacklo/_mm_unpackhi, so this mirrors emp's SSE tile
// transpose; the transmutes are same-size 128-bit reinterprets to change the
// interleave granularity.
#[inline]
#[cfg(test)]
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

// Emit the 8 output rows for one source byte-column of a 16-row group: peel off
// one bit per movemask (simd_ge(0x80).to_bitmask()), MSB-first, advancing with a
// per-byte left shift. `col` holds that column's byte for the 16 rows of the group.
#[inline]
#[cfg(test)]
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
// then peels off the bits with movemask -- avoiding the strided per-byte gather of
// the naive form. Produces the same OUT[col].bit(row) =
// (rows[row*rb + col/8] >> (col%8)) & 1 mapping as the scalar reference
// (tests::transpose_128_rows_matches_bit_reference).
#[cfg(test)]
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
    // is not a multiple of 16, e.g. the row_bytes=1 unit test). Gather per column.
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

fn point_from_bytes(group: &EcGroup, bytes: &[u8], ctx: &mut BigNumContext) -> Result<EcPoint> {
    if bytes.len() != POINT_BYTES {
        return Err(CompatError::BadPointLength(bytes.len()));
    }
    Ok(EcPoint::from_bytes(group, bytes, ctx)?)
}

fn point_bytes(group: &EcGroup, point: &EcPointRef, ctx: &mut BigNumContext) -> Result<Vec<u8>> {
    Ok(point.to_bytes(group, PointConversionForm::UNCOMPRESSED, ctx)?)
}
