// Reference oracle CLI: print generate_from_seed(gShare XOR eShare, I). Used by
// the demo to cross-check the two-party result against the single-party truth.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>

#include "../util/hex.h"
#include "shachain_ref.h"

int main(int argc, char** argv) {
  if (argc < 4) {
    std::fprintf(stderr, "usage: %s <gShare_hex> <eShare_hex> <I_hex>\n", argv[0]);
    return 2;
  }
  using namespace shachain2pc;
  try {
    auto g = util::FromHex32(argv[1]);
    auto e = util::FromHex32(argv[2]);
    uint64_t I = std::strtoull(argv[3], nullptr, 16);
    reference::Hash seed = reference::Combine(g, e);
    reference::Hash out = reference::GenerateFromSeed(seed, I);
    std::printf("%s\n", util::ToHex(out).c_str());
    return 0;
  } catch (const std::exception& e) {
    std::fprintf(stderr, "ref_cli error: %s\n", e.what());
    return 1;
  }
}
