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
#include <vector>

#include "bristol.h"

namespace shachain2pc::protocol {

// BuildDerivationCircuit composes the chain for index I from a SHA-256
// compression gadget (emp's bristol_format/sha-256.txt: 512-bit message in,
// 256-bit digest out, IV internal, no padding). It is a pure function of the
// gadget and I. popcount(I) ranges 0..48; I uses only its low 48 bits.
Circuit BuildDerivationCircuit(const Circuit& sha256_compress, uint64_t I);

// --- Block-chunking: split the one chain into a sequence of smaller circuits so
// the per-circuit preprocessing peak is bounded by chunk size instead of the
// whole chain. The intermediate value is carried between chunks as an
// *authenticated* wire (never re-input), and the per-link flips stay in-circuit
// public constants -- so this is the malicious-secure equivalent of the single
// circuit (see README / the semi-honest steering caveat it avoids).

// SplitChainBits returns the set chain-bit positions of I (high to low, the BOLT
// processing order) grouped into chunks of `blocks_per_chunk`. The first group is
// chunk 0 (which additionally does the seed XOR). Always returns >= 1 group: an
// empty first group means popcount(I) == 0 (chunk 0 is seed-only). Throws on
// blocks_per_chunk < 1 or I out of range.
std::vector<std::vector<int>> SplitChainBits(uint64_t I, int blocks_per_chunk);

// BuildChunkCircuit builds one chunk. If `first`, inputs are 256 ALICE + 256 BOB
// share bits and the circuit computes seed = ALICE XOR BOB; otherwise the single
// 256-bit input IS the carried value (chained directly, not re-input). It then
// applies each bit in `chain_bits` (already high-to-low) as a public-constant flip
// followed by one SHA-256 compression. Output: 256 bits.
//   first == true  -> n1 = n2 = 256 (num_inputs 512)
//   first == false -> n1 = 256, n2 = 0 (num_inputs 256, the carried value)
Circuit BuildChunkCircuit(const Circuit& sha256_compress,
                          const std::vector<int>& chain_bits, bool first);

// BuildTileCircuit builds one subtree tile over the bit window
// [bit_offset, bit_offset + tile_height - 1]. Input is one carried 256-bit root;
// output is every arm in ascending suffix order, where arm `suffix` applies the
// set bits of `suffix` at positions `bit_offset + j` (high to low). For
// bit_offset == 0 the outputs are final leaves; for bit_offset > 0 they are
// intermediate roots that feed the next lower tile level. A height-h tile outputs
// 2^h * 256 bits and uses 2^h - 1 SHA-256 blocks internally.
Circuit BuildTileCircuit(const Circuit& sha256_compress, int bit_offset,
                         int tile_height);

// One level of a recursive tile cover: a tile over [bit_offset, bit_offset+height).
struct TileLevel {
  int bit_offset;
  int height;
};

// PlanTileLevels decomposes an aligned subtree of `depth` bits into tile levels,
// top (most significant bits) to bottom (bits [0, height)). The bottom level
// always sits at bit_offset 0 and has height `tile_height`; if `depth` is not a
// multiple of `tile_height`, the top level is a smaller partial of height
// `depth % tile_height`. Requires depth >= tile_height >= 1.
std::vector<TileLevel> PlanTileLevels(int depth, int tile_height);

}  // namespace shachain2pc::protocol

#endif  // SHACHAIN2PC_PROTOCOL_CIRCUIT_GEN_H
