// Deterministic helper probe for emp::CSW base OT internals.
//
// The real CSW protocol is randomized. This probe fixes the receiver seed,
// sender scalar, receiver scalars, choices, and payloads to freeze the current
// EMP random-oracle framing, P-256 point encodings, aggregate proof, and
// chosen-input ciphertext relation.
#include <emp-ot/base_ot/csw.h>
#include <emp-tool/emp-tool.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace {

constexpr int64_t kLength = 80;
constexpr char kDomToCurve[] = "emp-ot:csw-base-ot:to-curve";
constexpr char kDomAgg[] = "emp-ot:csw-base-ot:agg";

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

std::string HexPoint(emp::Point& p) {
  std::vector<unsigned char> bytes(p.size());
  p.to_bin(bytes.data(), bytes.size());
  return HexBytes(bytes.data(), bytes.size());
}

std::string DigestBlocks(const emp::block* blocks, size_t count) {
  emp::Hash hash;
  hash.put(blocks, count * sizeof(emp::block));
  std::array<uint8_t, emp::Hash::DIGEST_SIZE> digest{};
  hash.digest(digest.data());
  return HexBytes(digest.data(), digest.size());
}

emp::Scalar ScalarFromU64(uint64_t value) {
  std::array<unsigned char, 8> bytes{};
  for (int i = 0; i < 8; ++i) {
    bytes[7 - i] = static_cast<unsigned char>((value >> (8 * i)) & 0xff);
  }
  emp::Scalar out;
  out.from_bin(bytes.data(), bytes.size());
  return out;
}

emp::block Pad(emp::block sid, int64_t i, emp::Point& p) {
  return emp::RO("emp-ot:csw-base-ot:pad", sid)
      .absorb(static_cast<uint64_t>(i))
      .absorb(p)
      .squeeze_block();
}

emp::block Short(emp::block sid, emp::block x) {
  return emp::RO("emp-ot:csw-base-ot:short", sid)
      .absorb(x)
      .squeeze_block();
}

emp::block Data0(int64_t i) {
  return emp::makeBlock(0x1000000000000000ULL | static_cast<uint64_t>(i),
                        0x0000000000000100ULL | static_cast<uint64_t>(i));
}

emp::block Data1(int64_t i) {
  return emp::makeBlock(0x2000000000000000ULL | static_cast<uint64_t>(i),
                        0x0000000000000200ULL | static_cast<uint64_t>(i));
}

bool Choice(int64_t i) {
  return ((i * 7 + 3) % 11) < 5;
}

}  // namespace

int main() {
  emp::ECGroup group;
  const emp::block sid = emp::zero_block;
  const emp::block seed =
      emp::makeBlock(0x0102030405060708ULL, 0x1112131415161718ULL);
  emp::Point T = emp::RO(kDomToCurve, sid).absorb(seed).squeeze_point(group);
  emp::Scalar r = ScalarFromU64(0x12345);
  emp::Point z = group.mul_gen(r);
  emp::Point T_r_neg = T.mul(r).inv();

  std::vector<emp::Point> b_points;
  std::vector<emp::block> p0(kLength);
  std::vector<emp::block> p1(kLength);
  std::vector<emp::block> h0(kLength);
  std::vector<emp::block> chi(kLength);
  std::vector<emp::block> c0(kLength);
  std::vector<emp::block> c1(kLength);
  std::vector<emp::block> recovered(kLength);
  b_points.reserve(kLength);

  for (int64_t i = 0; i < kLength; ++i) {
    emp::Scalar alpha = ScalarFromU64(0x2000 + static_cast<uint64_t>(i) * 17);
    emp::Point b = group.mul_gen(alpha);
    if (Choice(i)) b = b.add(T);
    b_points.push_back(b);

    emp::Point rho0 = b_points.back().mul(r);
    emp::Point rho1 = rho0.add(T_r_neg);
    p0[i] = Pad(sid, i, rho0);
    p1[i] = Pad(sid, i, rho1);
    h0[i] = Short(sid, p0[i]);
  }

  emp::block otans = emp::RO(kDomAgg, sid)
      .absorb(h0.data(), static_cast<size_t>(kLength) * sizeof(emp::block))
      .squeeze_block();
  emp::block proof = Short(sid, otans);

  for (int64_t i = 0; i < kLength; ++i) {
    emp::block h1 = Short(sid, p1[i]);
    chi[i] = h0[i] ^ h1;
    c0[i] = p0[i] ^ Data0(i);
    c1[i] = p1[i] ^ Data1(i);

    emp::Scalar alpha = ScalarFromU64(0x2000 + static_cast<uint64_t>(i) * 17);
    emp::Point z_alpha = z.mul(alpha);
    emp::block p_bi = Pad(sid, i, z_alpha);
    recovered[i] = p_bi ^ (Choice(i) ? c1[i] : c0[i]);
  }

  bool verified = true;
  for (int64_t i = 0; i < kLength; ++i) {
    emp::block expected = Choice(i) ? Data1(i) : Data0(i);
    if (!emp::cmpBlock(&expected, &recovered[i], 1)) {
      verified = false;
      break;
    }
  }

  std::printf("{\n");
  std::printf("\"schema\":\"shachain2pc.csw_helper.v1\",\n");
  std::printf("\"length\":%lld,\n", static_cast<long long>(kLength));
  std::printf("\"verified\":%s,\n", verified ? "true" : "false");
  std::printf("\"sid\":\"%s\",\n", HexBlock(sid).c_str());
  std::printf("\"seed\":\"%s\",\n", HexBlock(seed).c_str());
  std::printf("\"T\":\"%s\",\n", HexPoint(T).c_str());
  std::printf("\"z\":\"%s\",\n", HexPoint(z).c_str());
  std::printf("\"B_first\":\"%s\",\n", HexPoint(b_points.front()).c_str());
  std::printf("\"B_last\":\"%s\",\n", HexPoint(b_points.back()).c_str());
  std::printf("\"otans\":\"%s\",\n", HexBlock(otans).c_str());
  std::printf("\"proof\":\"%s\",\n", HexBlock(proof).c_str());
  std::printf("\"p0_digest\":\"%s\",\n", DigestBlocks(p0.data(), p0.size()).c_str());
  std::printf("\"p1_digest\":\"%s\",\n", DigestBlocks(p1.data(), p1.size()).c_str());
  std::printf("\"h0_digest\":\"%s\",\n", DigestBlocks(h0.data(), h0.size()).c_str());
  std::printf("\"chi_digest\":\"%s\",\n", DigestBlocks(chi.data(), chi.size()).c_str());
  std::printf("\"c0_digest\":\"%s\",\n", DigestBlocks(c0.data(), c0.size()).c_str());
  std::printf("\"c1_digest\":\"%s\",\n", DigestBlocks(c1.data(), c1.size()).c_str());
  std::printf("\"recovered_digest\":\"%s\",\n",
              DigestBlocks(recovered.data(), recovered.size()).c_str());
  std::printf("\"p0_first\":\"%s\",\n", HexBlock(p0.front()).c_str());
  std::printf("\"p1_first\":\"%s\",\n", HexBlock(p1.front()).c_str());
  std::printf("\"chi_first\":\"%s\",\n", HexBlock(chi.front()).c_str());
  std::printf("\"c0_first\":\"%s\",\n", HexBlock(c0.front()).c_str());
  std::printf("\"c1_first\":\"%s\",\n", HexBlock(c1.front()).c_str());
  std::printf("\"recovered_first\":\"%s\",\n", HexBlock(recovered.front()).c_str());
  std::printf("\"recovered_last\":\"%s\"\n", HexBlock(recovered.back()).c_str());
  std::printf("}\n");
  return verified ? 0 : 1;
}
