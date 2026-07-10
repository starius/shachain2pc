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

// Pure AG2PC triple-pool state and compute buffers.
include!("triple_pool.rs");

// Pure PRP/PRG, SoftSpoken, CGGM/SFVOLE, MITCCRH, and transpose kernels.
include!("softspoken.rs");

// Pure authenticated reveal and input-open checks.
include!("reveal.rs");

// Pure typed session handshake and frame sequencing state machine.
include!("channel_flow.rs");

#[cfg(test)]
mod tests;
