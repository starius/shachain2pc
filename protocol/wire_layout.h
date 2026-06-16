// Wire bit-layout for shachain2pc circuits. The emp sha-256.txt gadget consumes
// and produces bits MSB-first big-endian (byte j, bit k counted from the MSB ->
// bit index 8*j + k); the probe in tools/ pins this. Seed shares and outputs use
// the same layout so that XOR of share bits equals XOR of share bytes.
#ifndef SHACHAIN2PC_PROTOCOL_WIRE_LAYOUT_H
#define SHACHAIN2PC_PROTOCOL_WIRE_LAYOUT_H

#include <array>
#include <cstdint>
#include <vector>

namespace shachain2pc::protocol {

using Value = std::array<uint8_t, 32>;

// kValueBits is the bit width of a shachain value / seed share.
constexpr int kValueBits = 256;

// MsbBitIndex maps byte j and LSB-position l (0 = least significant) to the
// MSB-first bit index used on the wires.
inline int MsbBitIndex(int byte, int lsb) { return 8 * byte + (7 - lsb); }

// FlipBitIndex returns the wire bit index of shachain chain-bit B, which the
// reference flips as bit (B%8) of byte (B/8).
inline int FlipBitIndex(int b) { return MsbBitIndex(b / 8, b % 8); }

// ValueToBits / BitsToValue convert a 32-byte value to/from 256 MSB-first bits.
inline std::vector<uint8_t> ValueToBits(const Value& v) {
  std::vector<uint8_t> bits(kValueBits);
  for (int j = 0; j < 32; ++j)
    for (int k = 0; k < 8; ++k) bits[8 * j + k] = (v[j] >> (7 - k)) & 1;
  return bits;
}

inline Value BitsToValue(const std::vector<uint8_t>& bits) {
  Value v{};
  for (int j = 0; j < 32; ++j)
    for (int k = 0; k < 8; ++k) v[j] |= (bits[8 * j + k] & 1) << (7 - k);
  return v;
}

}  // namespace shachain2pc::protocol

#endif  // SHACHAIN2PC_PROTOCOL_WIRE_LAYOUT_H
