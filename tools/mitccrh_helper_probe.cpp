// Deterministic helper probe for emp::MITCCRH<8>.
//
// AG2PC's leaky half-gate uses MITCCRH<8>::hash<8,2> for the garbler/evaluator
// hash streams. This freezes the default ReuseShift=3 key scheduling, the
// key-major block layout, and the sigma variant used by hash_cir.
#include <emp-tool/emp-tool.h>
#include <emp-tool/runtime/crypto/mitccrh.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <string>

namespace {

std::string HexBytes(const uint8_t* data, size_t len) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.resize(len * 2);
  for (size_t i = 0; i < len; ++i) {
    out[2 * i] = kHex[data[i] >> 4];
    out[2 * i + 1] = kHex[data[i] & 0x0f];
  }
  return out;
}

std::string HexBlock(emp::block b) {
  alignas(16) std::array<uint8_t, 16> bytes{};
  _mm_storeu_si128(reinterpret_cast<__m128i*>(bytes.data()), b);
  return HexBytes(bytes.data(), bytes.size());
}

std::string DigestBlocks(const emp::block* blocks, size_t count) {
  emp::Hash hash;
  hash.put(blocks, count * sizeof(emp::block));
  std::array<uint8_t, emp::Hash::DIGEST_SIZE> digest{};
  hash.digest(digest.data());
  return HexBytes(digest.data(), digest.size());
}

void PrintBlockArray(const char* name, const emp::block* blocks, size_t count,
                     bool trailing_comma) {
  std::printf("\"%s\":[", name);
  for (size_t i = 0; i < count; ++i) {
    if (i != 0) std::printf(",");
    std::printf("\"%s\"", HexBlock(blocks[i]).c_str());
  }
  std::printf("]%s\n", trailing_comma ? "," : "");
}

emp::block InputBlock(uint64_t lane_hi, uint64_t lane_lo, uint64_t i) {
  return emp::makeBlock(lane_hi | i, lane_lo | i);
}

}  // namespace

int main() {
  const emp::block seed =
      emp::makeBlock(0x0102030405060708ULL, 0x1112131415161718ULL);

  emp::block hash_8x2[16];
  emp::block hash_8x2_second[16];
  emp::block hash_4x2_first[8];
  emp::block hash_4x2_second[8];
  emp::block hash_cir_8x2[16];

  for (uint64_t i = 0; i < 16; ++i) {
    hash_8x2[i] = InputBlock(0x1000000000000000ULL,
                             0x2000000000000000ULL, i);
    hash_8x2_second[i] = InputBlock(0x3000000000000000ULL,
                                    0x4000000000000000ULL, i);
    hash_cir_8x2[i] = InputBlock(0x9000000000000000ULL,
                                 0xa000000000000000ULL, i);
  }
  for (uint64_t i = 0; i < 8; ++i) {
    hash_4x2_first[i] = InputBlock(0x5000000000000000ULL,
                                   0x6000000000000000ULL, i);
    hash_4x2_second[i] = InputBlock(0x7000000000000000ULL,
                                    0x8000000000000000ULL, i);
  }

  emp::MITCCRH<8> h8;
  h8.setS(seed);
  h8.hash<8, 2>(hash_8x2);
  h8.hash<8, 2>(hash_8x2_second);

  emp::MITCCRH<8> h4;
  h4.setS(seed);
  h4.hash<4, 2>(hash_4x2_first);
  h4.hash<4, 2>(hash_4x2_second);

  emp::MITCCRH<8> hc;
  hc.setS(seed);
  hc.hash_cir<8, 2>(hash_cir_8x2);

  std::printf("{\n");
  std::printf("\"schema\":\"shachain2pc.mitccrh_helper.v1\",\n");
  std::printf("\"batch_size\":8,\n");
  std::printf("\"reuse_shift\":3,\n");
  std::printf("\"seed\":\"%s\",\n", HexBlock(seed).c_str());
  std::printf("\"hash_8x2_digest\":\"%s\",\n",
              DigestBlocks(hash_8x2, 16).c_str());
  std::printf("\"hash_8x2_second_digest\":\"%s\",\n",
              DigestBlocks(hash_8x2_second, 16).c_str());
  std::printf("\"hash_4x2_first_digest\":\"%s\",\n",
              DigestBlocks(hash_4x2_first, 8).c_str());
  std::printf("\"hash_4x2_second_digest\":\"%s\",\n",
              DigestBlocks(hash_4x2_second, 8).c_str());
  std::printf("\"hash_cir_8x2_digest\":\"%s\",\n",
              DigestBlocks(hash_cir_8x2, 16).c_str());
  PrintBlockArray("hash_8x2", hash_8x2, 16, true);
  PrintBlockArray("hash_8x2_second", hash_8x2_second, 16, true);
  PrintBlockArray("hash_4x2_first", hash_4x2_first, 8, true);
  PrintBlockArray("hash_4x2_second", hash_4x2_second, 8, true);
  PrintBlockArray("hash_cir_8x2", hash_cir_8x2, 16, false);
  std::printf("}\n");
  return 0;
}
