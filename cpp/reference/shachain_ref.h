// Single-party BOLT-03 shachain reference (no MPC), the ground-truth oracle the
// two-party protocol is validated against.
#ifndef SHACHAIN2PC_REFERENCE_SHACHAIN_REF_H
#define SHACHAIN2PC_REFERENCE_SHACHAIN_REF_H

#include <array>
#include <cstdint>

namespace shachain2pc::reference {

using Hash = std::array<uint8_t, 32>;

// MaxHeight is the number of index bits and the maximum chain length.
constexpr int kMaxHeight = 48;

// StartIndex is the first per-commitment index, 2^48 - 1.
constexpr uint64_t kStartIndex = (uint64_t(1) << kMaxHeight) - 1;

// GenerateFromSeed computes the shachain element for index I: starting from the
// seed, for each bit B from 47 down to 0 set in I, flip bit B (bit B%8 of byte
// B/8) of the running value and replace it with its SHA-256 hash.
Hash GenerateFromSeed(const Hash& seed, uint64_t I);

// AtIndex maps an external per-commitment number v to the internal index.
inline uint64_t AtIndex(uint64_t v) { return kStartIndex - v; }

// Combine reconstructs a value from its two XOR shares.
Hash Combine(const Hash& a, const Hash& b);

// FillSeed returns a 32-byte seed with every byte set to b.
Hash FillSeed(uint8_t b);

}  // namespace shachain2pc::reference

#endif  // SHACHAIN2PC_REFERENCE_SHACHAIN_REF_H
