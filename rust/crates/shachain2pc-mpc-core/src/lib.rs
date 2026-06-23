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
