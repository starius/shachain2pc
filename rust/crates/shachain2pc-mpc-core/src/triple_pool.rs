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

pub struct Ag2pcShareSlicesMut<'a> {
    pub mac: &'a mut [Block],
    pub key: &'a mut [Block],
}

#[derive(Clone, Copy)]
pub struct Ag2pcLayerSlices<'a> {
    pub mac: &'a [Block],
    pub key: &'a [Block],
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
        shares: Ag2pcShareSlicesMut<'_>,
        l: usize,
        s_me: &[u8],
        s_peer: &[u8],
        mut sout: Vec<Block>,
        feq: &mut Sha256,
    ) -> Result<(), Ag2pcTriplePoolError> {
        require_len("mac", shares.mac.len(), 3 * l)?;
        require_len("key", shares.key.len(), 3 * l)?;
        require_len("s_me", s_me.len(), l)?;
        require_len("s_peer", s_peer.len(), l)?;
        require_len("sout", sout.len(), l)?;
        let dxor = self.delta.xor(bit0_mask());
        for k in 0..l {
            let d = s_me[k] ^ s_peer[k];
            let mask = select_block(d);
            if self.party == Role::Alice {
                shares.mac[2 * l + k] = shares.mac[2 * l + k].xor(bit0_mask().and(mask));
            } else {
                shares.key[2 * l + k] = shares.key[2 * l + k].xor(dxor.and(mask));
            }
            sout[k] = sout[k].xor(self.delta.and(mask));
        }
        feq.update(Block::slice_as_bytes(&sout));
        sout.zeroize();
        Ok(())
    }

    pub fn bucket_shift(seed: Block, l: usize) -> usize {
        let mut prg = Prg::new(seed, 0);
        let raw = u32::from_ne_bytes(
            prg.random_data(4)
                .try_into()
                .expect("four random bytes for bucket shift"),
        );
        (raw as usize) % l
    }

    pub fn bucket_prepare_layer(
        &self,
        acc: Ag2pcShareSlicesMut<'_>,
        layer: Ag2pcLayerSlices<'_>,
        l: usize,
        r: usize,
    ) -> Result<Vec<u8>, Ag2pcTriplePoolError> {
        require_len("acc_mac", acc.mac.len(), 3 * l)?;
        require_len("acc_key", acc.key.len(), 3 * l)?;
        require_len("layer_mac", layer.mac.len(), 3 * l)?;
        require_len("layer_key", layer.key.len(), 3 * l)?;
        let mut d_me = vec![0u8; l];
        let cut = l - r;
        for (i, d) in d_me.iter_mut().enumerate() {
            let src = if i < cut { i + r } else { i + r - l };
            acc.mac[i] = acc.mac[i].xor(layer.mac[src]);
            acc.mac[2 * l + i] = acc.mac[2 * l + i].xor(layer.mac[2 * l + src]);
            acc.key[i] = acc.key[i].xor(layer.key[src]);
            acc.key[2 * l + i] = acc.key[2 * l + i].xor(layer.key[2 * l + src]);
            *d = block_lsb(acc.mac[l + i]) ^ block_lsb(layer.mac[l + src]);
        }
        Ok(d_me)
    }

    pub fn bucket_finish_layer(
        &self,
        acc: Ag2pcShareSlicesMut<'_>,
        layer: Ag2pcLayerSlices<'_>,
        l: usize,
        r: usize,
        d_me: &[u8],
        d_peer: &[u8],
    ) -> Result<(), Ag2pcTriplePoolError> {
        require_len("acc_mac", acc.mac.len(), 3 * l)?;
        require_len("acc_key", acc.key.len(), 3 * l)?;
        require_len("layer_mac", layer.mac.len(), 3 * l)?;
        require_len("layer_key", layer.key.len(), 3 * l)?;
        require_len("d_me", d_me.len(), l)?;
        require_len("d_peer", d_peer.len(), l)?;
        let cut = l - r;
        for i in 0..l {
            let src = if i < cut { i + r } else { i + r - l };
            let mask = select_block(d_me[i] ^ d_peer[i]);
            acc.mac[2 * l + i] = acc.mac[2 * l + i].xor(layer.mac[src].and(mask));
            acc.key[2 * l + i] = acc.key[2 * l + i].xor(layer.key[src].and(mask));
        }
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
