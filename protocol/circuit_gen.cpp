#include "circuit_gen.h"

#include <stdexcept>
#include <vector>

#include "wire_layout.h"

namespace shachain2pc::protocol {
namespace {

// Incremental Bristol circuit builder. Input wires are reserved first, so they
// occupy [0, n1+n2); every other wire is allocated on demand with a strictly
// increasing id, keeping the gate list in topological order.
class Builder {
 public:
  explicit Builder(int num_inputs) : next_(num_inputs) {}

  int Alloc() { return next_++; }

  void And(int a, int b, int o) { gates_.push_back({Gate::kAnd, a, b, o}); }
  void Xor(int a, int b, int o) { gates_.push_back({Gate::kXor, a, b, o}); }
  void Inv(int a, int o) { gates_.push_back({Gate::kInv, a, -1, o}); }

  int XorW(int a, int b) {
    int o = Alloc();
    Xor(a, b, o);
    return o;
  }
  int InvW(int a) {
    int o = Alloc();
    Inv(a, o);
    return o;
  }

  // Instantiate a sub-circuit gadget: its input wires (gadget ids [0, gn1+gn2))
  // are bound to the supplied wire ids; all other gadget wires get fresh ids.
  // Returns the gadget's n3 output wires (its highest gadget ids), in order.
  std::vector<int> ApplyGadget(const Circuit& g, const std::vector<int>& in) {
    const int gin = g.n1 + g.n2;
    if (static_cast<int>(in.size()) != gin) {
      throw std::runtime_error("ApplyGadget: wrong gadget input width");
    }
    std::vector<int> map(g.num_wire);
    for (int w = 0; w < gin; ++w) map[w] = in[w];
    for (int w = gin; w < g.num_wire; ++w) map[w] = Alloc();
    for (const Gate& ge : g.gates) {
      switch (ge.type) {
        case Gate::kAnd:
          And(map[ge.in0], map[ge.in1], map[ge.out]);
          break;
        case Gate::kXor:
          Xor(map[ge.in0], map[ge.in1], map[ge.out]);
          break;
        case Gate::kInv:
          Inv(map[ge.in0], map[ge.out]);
          break;
      }
    }
    std::vector<int> out(g.n3);
    for (int i = 0; i < g.n3; ++i) out[i] = map[g.num_wire - g.n3 + i];
    return out;
  }

  Circuit Finish(int n1, int n2, int n3) {
    Circuit c;
    c.n1 = n1;
    c.n2 = n2;
    c.n3 = n3;
    c.num_wire = next_;
    c.gates = std::move(gates_);
    return c;
  }

 private:
  int next_;
  std::vector<Gate> gates_;
};

// PaddingBits returns the 256 constant bits that pad a 32-byte value into one
// SHA-256 block (bits 256..511 of the message), MSB-first big-endian.
std::vector<uint8_t> PaddingBits() {
  std::array<uint8_t, 32> pad{};
  pad[0] = 0x80;   // byte 32 of the block
  pad[30] = 0x01;  // byte 62: bit length 256 = 0x0100, big-endian
  std::vector<uint8_t> bits(256);
  for (int j = 0; j < 32; ++j)
    for (int k = 0; k < 8; ++k) bits[8 * j + k] = (pad[j] >> (7 - k)) & 1;
  return bits;
}

}  // namespace

Circuit BuildDerivationCircuit(const Circuit& sha, uint64_t I) {
  if (I > kMaxIndex) {
    throw std::runtime_error("BuildDerivationCircuit: index exceeds 48 bits");
  }
  if (sha.n1 + sha.n2 != 512 || sha.n3 != kValueBits) {
    throw std::runtime_error("BuildDerivationCircuit: gadget is not 512->256");
  }

  Builder b(2 * kValueBits);  // 256 ALICE input wires, then 256 BOB input wires

  // Constant wires: c0 = w0 XOR w0 = 0; c1 = NOT c0 = 1.
  const int c0 = b.XorW(0, 0);
  const int c1 = b.InvW(c0);
  const std::vector<uint8_t> pad = PaddingBits();

  // seed = aliceShare XOR bobShare, bit by bit (MSB-first layout).
  std::vector<int> p(kValueBits);
  for (int i = 0; i < kValueBits; ++i) {
    p[i] = b.XorW(i, kValueBits + i);
  }

  // For each set chain-bit B from 47 down to 0: flip then hash.
  for (int bit = kIndexBits - 1; bit >= 0; --bit) {
    if (((I >> bit) & 1) == 0) continue;
    const int idx = FlipBitIndex(bit);
    p[idx] = b.InvW(p[idx]);  // public constant flip

    std::vector<int> block(512);
    for (int i = 0; i < kValueBits; ++i) block[i] = p[i];
    for (int i = 0; i < kValueBits; ++i) block[kValueBits + i] = pad[i] ? c1 : c0;
    p = b.ApplyGadget(sha, block);
  }

  // Copy the final value into fresh wires so the output occupies the top n3
  // wires regardless of how many hashes ran (handles popcount(I) == 0 too).
  std::vector<int> out(kValueBits);
  for (int i = 0; i < kValueBits; ++i) out[i] = b.XorW(p[i], c0);

  return b.Finish(kValueBits, kValueBits, kValueBits);
}

}  // namespace shachain2pc::protocol
