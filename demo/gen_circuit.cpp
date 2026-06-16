// Generate the agreed derivation circuit for an index I and write it in Bristol
// format. Both parties run this (or share its output) so they evaluate exactly
// the same circuit -- the index, and its bit-flips, are fixed and public.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <string>

#include "../protocol/bristol.h"
#include "../protocol/circuit_gen.h"

static const char* kDefaultSha =
    ".sources/emp-tool/emp-tool/circuits/files/bristol_format/sha-256.txt";

int main(int argc, char** argv) {
  if (argc < 3) {
    std::fprintf(stderr,
                 "usage: %s <I_hex> <out_path> [sha256_compress_bristol]\n",
                 argv[0]);
    return 2;
  }
  using namespace shachain2pc::protocol;
  try {
    uint64_t I = std::strtoull(argv[1], nullptr, 16);
    std::string out = argv[2];
    std::string sha = argc > 3 ? argv[3] : kDefaultSha;

    Circuit gadget = LoadBristol(sha);
    Circuit c = BuildDerivationCircuit(gadget, I);
    SaveBristol(c, out);
    std::fprintf(stderr,
                 "wrote %s for I=%llx: n1=%d n2=%d n3=%d wires=%d gates=%d\n",
                 out.c_str(), static_cast<unsigned long long>(I), c.n1, c.n2,
                 c.n3, c.num_wire, c.num_gate());
    return 0;
  } catch (const std::exception& e) {
    std::fprintf(stderr, "gen_circuit error: %s\n", e.what());
    return 1;
  }
}
