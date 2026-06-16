// Bristol-format boolean circuits (the "old" Bristol format emp-ag2pc reads via
// emp::BristolFormat), plus a pure plaintext evaluator used to verify generated
// circuits against the single-party reference before any MPC is involved.
//
// Layout convention (matches emp::BristolFormat):
//   - header line 1: "<num_gate> <num_wire>"
//   - header line 2: "<n1> <n2> <n3>"  (ALICE input bits, BOB input bits, outputs)
//   - input wires  : [0, n1) belong to ALICE, [n1, n1+n2) to BOB
//   - output wires : the last n3 wires, [num_wire - n3, num_wire)
//   - gate lines   : "2 1 <in0> <in1> <out> AND|XOR" or "1 1 <in> <out> INV"
//   - gates are listed in topological order and evaluated in file order.
#ifndef SHACHAIN2PC_PROTOCOL_BRISTOL_H
#define SHACHAIN2PC_PROTOCOL_BRISTOL_H

#include <cstdint>
#include <string>
#include <vector>

namespace shachain2pc::protocol {

struct Gate {
  enum Type { kAnd, kXor, kInv };
  Type type;
  int in0;
  int in1;  // ignored for kInv
  int out;
};

struct Circuit {
  int num_wire = 0;
  int n1 = 0;
  int n2 = 0;
  int n3 = 0;
  std::vector<Gate> gates;

  int num_gate() const { return static_cast<int>(gates.size()); }
};

// Parse a Bristol-format file. Throws std::runtime_error on malformed input.
Circuit LoadBristol(const std::string& path);

// Serialize to Bristol format readable by emp::BristolFormat.
void SaveBristol(const Circuit& c, const std::string& path);

// Evaluate the circuit in plaintext. in_bits must have size n1 + n2 (ALICE bits
// first, then BOB bits); returns n3 output bits. Each element is 0 or 1.
std::vector<uint8_t> EvalBristol(const Circuit& c,
                                 const std::vector<uint8_t>& in_bits);

}  // namespace shachain2pc::protocol

#endif  // SHACHAIN2PC_PROTOCOL_BRISTOL_H
