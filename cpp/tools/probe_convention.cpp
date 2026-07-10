// Probe: determine the byte<->bit convention of emp's bristol_format/sha-256.txt
// compression circuit, so the generator lays seed/flip/output bits correctly.
//
//   - emp KAT: compression(IV, 0^512) == da5698be...   (anchors the parser)
//   - full SHA256(X) for a 32-byte X equals compression(IV, pad(X)) on one block.
//     We build pad(X) under MSB-first and LSB-first input conventions and check
//     which reproduces OpenSSL's SHA256(X). Output is read MSB-first big-endian
//     (the convention emp's own test fixes).
#include <openssl/sha.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "../protocol/bristol.h"

using shachain2pc::protocol::Circuit;
using shachain2pc::protocol::DefaultSha256CompressPath;
using shachain2pc::protocol::EvalBristol;
using shachain2pc::protocol::LoadBristol;

static std::string Hex(const std::vector<uint8_t>& b) {
  static const char* d = "0123456789abcdef";
  std::string s;
  for (uint8_t x : b) {
    s.push_back(d[x >> 4]);
    s.push_back(d[x & 0xf]);
  }
  return s;
}

// 64-byte message block -> 512 bits.
static std::vector<uint8_t> BytesToBitsMsb(const std::vector<uint8_t>& bytes) {
  std::vector<uint8_t> bits(bytes.size() * 8);
  for (size_t j = 0; j < bytes.size(); ++j)
    for (int k = 0; k < 8; ++k) bits[8 * j + k] = (bytes[j] >> (7 - k)) & 1;
  return bits;
}
static std::vector<uint8_t> BytesToBitsLsb(const std::vector<uint8_t>& bytes) {
  std::vector<uint8_t> bits(bytes.size() * 8);
  for (size_t j = 0; j < bytes.size(); ++j)
    for (int k = 0; k < 8; ++k) bits[8 * j + k] = (bytes[j] >> k) & 1;
  return bits;
}
static std::vector<uint8_t> BitsToBytesMsb(const std::vector<uint8_t>& bits) {
  std::vector<uint8_t> bytes(bits.size() / 8, 0);
  for (size_t j = 0; j < bytes.size(); ++j)
    for (int k = 0; k < 8; ++k) bytes[j] |= bits[8 * j + k] << (7 - k);
  return bytes;
}

// One-block SHA256 padding of a 32-byte value.
static std::vector<uint8_t> Pad32(const std::vector<uint8_t>& x) {
  std::vector<uint8_t> m(64, 0);
  for (int i = 0; i < 32; ++i) m[i] = x[i];
  m[32] = 0x80;
  m[62] = 0x01;  // bit length 256 = 0x0100, big-endian in bytes 56..63
  return m;
}

int main() {
  Circuit c = LoadBristol(DefaultSha256CompressPath());
  std::printf("circuit: n1=%d n2=%d n3=%d wires=%d gates=%d\n", c.n1, c.n2,
              c.n3, c.num_wire, c.num_gate());

  // 1) emp KAT: all-zero block.
  {
    std::vector<uint8_t> in(512, 0);
    auto out = EvalBristol(c, in);
    std::string got = Hex(BitsToBytesMsb(out));
    std::printf("emp KAT zero-block: %s  %s\n", got.c_str(),
                got == "da5698be17b9b46962335799779fbeca8ce5d491c0d26243bafef"
                       "9ea1837a9d8"
                    ? "OK"
                    : "MISMATCH");
  }

  // 2) full-hash probe for two 32-byte inputs, both input conventions.
  std::vector<std::vector<uint8_t>> xs = {std::vector<uint8_t>(32, 0), {}};
  for (int i = 0; i < 32; ++i) xs[1].push_back(static_cast<uint8_t>(i));

  for (const auto& x : xs) {
    uint8_t ref[32];
    SHA256(x.data(), x.size(), ref);
    std::string want = Hex(std::vector<uint8_t>(ref, ref + 32));
    auto block = Pad32(x);
    auto msb = Hex(BitsToBytesMsb(EvalBristol(c, BytesToBitsMsb(block))));
    auto lsb = Hex(BitsToBytesMsb(EvalBristol(c, BytesToBitsLsb(block))));
    std::printf("x[0]=%02x: want=%s\n  in=MSB -> %s  %s\n  in=LSB -> %s  %s\n",
                x[0], want.c_str(), msb.c_str(), msb == want ? "OK" : "no",
                lsb.c_str(), lsb == want ? "OK" : "no");
  }
  return 0;
}
