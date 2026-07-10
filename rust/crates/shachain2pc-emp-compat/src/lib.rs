// std::simd (portable SIMD) powers the bit-matrix transpose; it is unstable, so
// the crate enables it via the portable_simd feature gate. RUSTC_BOOTSTRAP=1 (set
// in rust/.cargo/config.toml) unlocks it on the pinned stable toolchain.
#![feature(portable_simd)]

use openssl::bn::{BigNum, BigNumContext, BigNumRef};
use openssl::ec::{EcGroup, EcPoint, EcPointRef, PointConversionForm};
use openssl::error::ErrorStack;
use openssl::nid::Nid;
use openssl::rand::rand_bytes;
use p256::elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::{Digest, Sha256};
use shachain2pc_circuit::{Circuit, GateType};
use shachain2pc_emp_wire::{Ag2pcStreams, Block, ByteIo, TranscriptIo, WireError, BLOCK_BYTES};
pub use shachain2pc_mpc_core::{
    cggm_bit_reverse, cggm_build_sender, cggm_eval_receiver, sfvole_receiver_butterfly,
    sfvole_sender_butterfly, AShareBundle, Ag2pcComputeBuffer, Ag2pcLayerSlices,
    Ag2pcShareSlicesMut, Ag2pcTriplePoolState, Prg, Prp, SoftSpoken4State, SOFTSPOKEN_CHUNK_BLOCKS,
    SOFTSPOKEN_CHUNK_OTS, SOFTSPOKEN_K, SOFTSPOKEN_N, SOFTSPOKEN_Q,
};
use shachain2pc_mpc_core::{
    finalize_input_open, reveal_local_share, reveal_recipient_bits, verify_share_relation,
    InputOpenError, Mitccrh8, RevealError,
};
use shachain2pc_types::{Role, INDEX_BITS, VALUE_BITS};
use std::sync::OnceLock;
use std::{fmt, ops};
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

// EMP random oracle, P-256, and base-OT compatibility helpers.
include!("base_ot.rs");

// SoftSpoken OT-extension wrapper over the pure state machine.
include!("softspoken.rs");

// Authenticated wire containers and AG2PC protocol shell types.
include!("wires.rs");

// AG2PC direct-program representation and builders.
include!("program.rs");

// AG2PC session execution, input opening, and garbling paths.
include!("session.rs");

// Triple-pool I/O, equality checks, delta helpers, and compatibility utilities.
include!("triple_pool.rs");

#[cfg(test)]
mod tests;
