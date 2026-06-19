// Plaintext verification of the generated derivation circuit against the
// single-party reference, over several indices and share splits. No MPC: this
// isolates circuit-correctness risk before wiring to emp-ag2pc.
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "../protocol/bristol.h"
#include "../protocol/circuit_gen.h"
#include "../protocol/wire_layout.h"
#include "../reference/shachain_ref.h"

namespace ref = shachain2pc::reference;
namespace proto = shachain2pc::protocol;

static std::string Hex(const proto::Value& v) {
  static const char* d = "0123456789abcdef";
  std::string s;
  for (uint8_t b : v) {
    s.push_back(d[b >> 4]);
    s.push_back(d[b & 0xf]);
  }
  return s;
}

static int PopCount(uint64_t x) {
  int n = 0;
  while (x) {
    n += x & 1;
    x >>= 1;
  }
  return n;
}

// Run the circuit for index I with seed split into (share, seed^share).
static proto::Value RunCircuit(const proto::Circuit& c, const proto::Value& seed,
                               const proto::Value& share) {
  proto::Value a = share;
  proto::Value b{};
  for (int i = 0; i < 32; ++i) b[i] = seed[i] ^ a[i];
  std::vector<uint8_t> in = proto::ValueToBits(a);
  std::vector<uint8_t> bb = proto::ValueToBits(b);
  in.insert(in.end(), bb.begin(), bb.end());
  return proto::BitsToValue(proto::EvalBristol(c, in));
}

int main() {
  proto::Circuit sha = proto::LoadBristol(
      ".deps/emp/include/emp-tool/circuits/files/bristol_format/sha-256.txt");

  struct Case {
    uint8_t seed_fill;
    uint64_t index;
  };
  const Case cases[] = {
      {0x00, 0xffffffffffffULL}, {0xff, 0xffffffffffffULL},
      {0xff, 0xaaaaaaaaaaaULL},  {0xff, 0x555555555555ULL},
      {0x01, 1ULL},             {0x00, 0ULL},
      {0xab, 0x123456789abcULL},
  };

  // Three share splits per case: all-zero (share == seed on B), a fixed
  // pattern, and a different pattern. The circuit XORs them back, so all must
  // agree with the reference.
  proto::Value split0{};
  proto::Value split1{};
  proto::Value split2{};
  for (int j = 0; j < 32; ++j) {
    split1[j] = static_cast<uint8_t>(j * 7 + 13);
    split2[j] = static_cast<uint8_t>(0xa5 ^ (j * 31));
  }

  int failures = 0;
  for (const Case& tc : cases) {
    proto::Value seed = ref::FillSeed(tc.seed_fill);
    proto::Value want = ref::GenerateFromSeed(seed, tc.index);
    proto::Circuit c = proto::BuildDerivationCircuit(sha, tc.index);

    bool ok = true;
    for (const proto::Value* sh : {&split0, &split1, &split2}) {
      proto::Value got = RunCircuit(c, seed, *sh);
      if (got != want) {
        ok = false;
        std::printf("  split mismatch: got %s\n", Hex(got).c_str());
      }
    }
    std::printf("seed=%02x I=%012llx pop=%2d gates=%8d  %s\n", tc.seed_fill,
                static_cast<unsigned long long>(tc.index), PopCount(tc.index),
                c.num_gate(), ok ? "PASS" : "FAIL");
    if (!ok) {
      std::printf("   want %s\n", Hex(want).c_str());
      ++failures;
    }
  }

  // Round-trip through the serializer (what emp will read).
  {
    proto::Circuit c = proto::BuildDerivationCircuit(sha, 1ULL);
    proto::SaveBristol(c, ".build/derive_I1.txt");
    proto::Circuit r = proto::LoadBristol(".build/derive_I1.txt");
    proto::Value seed = ref::FillSeed(0x01);
    bool ok = RunCircuit(r, seed, split1) == ref::GenerateFromSeed(seed, 1ULL);
    std::printf("serializer round-trip (I=1): %s\n", ok ? "PASS" : "FAIL");
    if (!ok) ++failures;
  }

  std::printf("%s\n",
              failures == 0 ? "circuit verify: OK" : "circuit verify: FAILED");
  return failures == 0 ? 0 : 1;
}
