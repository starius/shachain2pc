// Deterministic helper probe for the current emp::SoftSpoken<4> backend.
//
// This freezes cGGM split-layout bytes and the SFVOLE butterfly relation used
// underneath AG2PCSession's COT backend. It is not a protocol run.
#include <emp-ot/common/cggm.h>
#include <emp-ot/ot_extension/softspoken/sfvole_butterfly.h>
#include <emp-tool/emp-tool.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <string>

namespace {

constexpr int k = 4;
constexpr int Q = 1 << k;
constexpr int Bs = 9;
constexpr int AlphaField = 0x0b;
constexpr int64_t SessionId = 7;
constexpr int64_t CounterBase = 5;

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

bool BlocksEqual(emp::block a, emp::block b) {
  return emp::cmpBlock(&a, &b, 1);
}

}  // namespace

int main() {
  emp::block delta = emp::makeBlock(0x0112233445566778LL,
                                    0x899aabbccddeeff1LL);
  emp::block root = emp::makeBlock(0x01030507090b0d0fLL,
                                   0x11131517191b1d1fLL);

  emp::block leaves[Q];
  emp::block k0[k];
  emp::cggm::build_sender<emp::cggm::kTile, false>(k, delta, root, leaves, k0);

  const int alpha_path =
      static_cast<int>(emp::cggm::bit_reverse(AlphaField, k));
  emp::block recv_keys[k];
  for (int level = 1; level <= k; ++level) {
    const int alpha_i = (alpha_path >> (k - level)) & 1;
    const int alpha_bar_i = 1 - alpha_i;
    recv_keys[level - 1] =
        k0[level - 1] ^ (emp::select_mask[alpha_bar_i] & delta);
  }

  emp::block recv_leaves[Q];
  emp::cggm::eval_receiver<emp::cggm::kTile, false>(k, alpha_path, recv_keys,
                                                    recv_leaves);

  bool cggm_relation = true;
  for (int i = 0; i < Q; ++i) {
    const bool punctured = i == AlphaField;
    if (punctured) {
      cggm_relation = cggm_relation &&
                      BlocksEqual(recv_leaves[i], emp::zero_block);
    } else {
      cggm_relation = cggm_relation && BlocksEqual(recv_leaves[i], leaves[i]);
    }
  }

  emp::AES_KEY session_key;
  emp::AES_set_encrypt_key(emp::makeBlock(0LL, SessionId), &session_key);

  emp::block u[Bs];
  emp::block v[k * Bs];
  emp::block w[k * Bs];
  emp::softspoken::sfvole_sender_butterfly<k>(
      leaves, &session_key, CounterBase, Bs, u, v);
  emp::softspoken::sfvole_receiver_butterfly<k>(
      AlphaField, recv_leaves, &session_key, CounterBase, Bs, w);

  bool sfvole_relation = true;
  for (int plane = 0; plane < k; ++plane) {
    const bool alpha_bit = ((AlphaField >> plane) & 1) != 0;
    for (int j = 0; j < Bs; ++j) {
      emp::block expected =
          v[plane * Bs + j] ^ (emp::select_mask[alpha_bit] & u[j]);
      sfvole_relation =
          sfvole_relation && BlocksEqual(expected, w[plane * Bs + j]);
    }
  }

  std::printf("{\n");
  std::printf("\"schema\":\"shachain2pc.softspoken_helper.v1\",\n");
  std::printf("\"k\":%d,\n", k);
  std::printf("\"q\":%d,\n", Q);
  std::printf("\"bs\":%d,\n", Bs);
  std::printf("\"alpha_field\":%d,\n", AlphaField);
  std::printf("\"alpha_path\":%d,\n", alpha_path);
  std::printf("\"session_id\":%lld,\n",
              static_cast<long long>(SessionId));
  std::printf("\"counter_base\":%lld,\n",
              static_cast<long long>(CounterBase));
  std::printf("\"delta\":\"%s\",\n", HexBlock(delta).c_str());
  std::printf("\"root\":\"%s\",\n", HexBlock(root).c_str());
  std::printf("\"cggm_relation\":%s,\n",
              cggm_relation ? "true" : "false");
  std::printf("\"sfvole_relation\":%s,\n",
              sfvole_relation ? "true" : "false");
  std::printf("\"sender_leaves_digest\":\"%s\",\n",
              DigestBlocks(leaves, Q).c_str());
  std::printf("\"receiver_leaves_digest\":\"%s\",\n",
              DigestBlocks(recv_leaves, Q).c_str());
  std::printf("\"sfvole_u_digest\":\"%s\",\n",
              DigestBlocks(u, Bs).c_str());
  std::printf("\"sfvole_v_digest\":\"%s\",\n",
              DigestBlocks(v, k * Bs).c_str());
  std::printf("\"sfvole_w_digest\":\"%s\",\n",
              DigestBlocks(w, k * Bs).c_str());
  PrintBlockArray("k0", k0, k, true);
  PrintBlockArray("recv_keys", recv_keys, k, true);
  PrintBlockArray("sender_leaves", leaves, Q, true);
  PrintBlockArray("receiver_leaves", recv_leaves, Q, true);
  PrintBlockArray("sfvole_u", u, Bs, true);
  PrintBlockArray("sfvole_v", v, k * Bs, true);
  PrintBlockArray("sfvole_w", w, k * Bs, false);
  std::printf("}\n");
  return (cggm_relation && sfvole_relation) ? 0 : 1;
}
