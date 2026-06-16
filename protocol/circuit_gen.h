// The "pure protocol" of shachain2pc: deterministically build the one fixed
// boolean circuit that derives shachain element H(I) from two seed shares.
//
// The circuit both parties agree on for index I computes, with I's bit-flips
// baked in as PUBLIC constants:
//
//     seed = aliceShare XOR bobShare          (256-bit XOR of the two inputs)
//     value = generate_from_seed(seed, I)     (popcount(I) SHA-256 blocks)
//
// Inputs: 256 ALICE bits then 256 BOB bits (n1 = n2 = 256). Output: 256 bits.
// All bit layouts are MSB-first big-endian (see wire_layout.h). Because the
// flips are constants of the agreed circuit rather than a controllable input,
// and the circuit is evaluated under malicious-secure authenticated garbling,
// the only reachable output is H(I) for the agreed I -- this is the property
// a semi-honest garbled-circuit design lacks.
#ifndef SHACHAIN2PC_PROTOCOL_CIRCUIT_GEN_H
#define SHACHAIN2PC_PROTOCOL_CIRCUIT_GEN_H

#include <cstdint>

#include "bristol.h"

namespace shachain2pc::protocol {

// BuildDerivationCircuit composes the chain for index I from a SHA-256
// compression gadget (emp's bristol_format/sha-256.txt: 512-bit message in,
// 256-bit digest out, IV internal, no padding). It is a pure function of the
// gadget and I. popcount(I) ranges 0..48; I uses only its low 48 bits.
Circuit BuildDerivationCircuit(const Circuit& sha256_compress, uint64_t I);

}  // namespace shachain2pc::protocol

#endif  // SHACHAIN2PC_PROTOCOL_CIRCUIT_GEN_H
