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
