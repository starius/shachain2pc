#include "bristol.h"

#include <cstdio>
#include <stdexcept>

namespace shachain2pc::protocol {

Circuit LoadBristol(const std::string& path) {
  FILE* f = std::fopen(path.c_str(), "r");
  if (f == nullptr) {
    throw std::runtime_error("LoadBristol: cannot open " + path);
  }
  Circuit c;
  int num_gate = 0;
  if (std::fscanf(f, "%d %d", &num_gate, &c.num_wire) != 2) {
    std::fclose(f);
    throw std::runtime_error("LoadBristol: bad header line 1 in " + path);
  }
  if (std::fscanf(f, "%d %d %d", &c.n1, &c.n2, &c.n3) != 3) {
    std::fclose(f);
    throw std::runtime_error("LoadBristol: bad header line 2 in " + path);
  }
  // Header sanity: counts must be consistent so wire indices can be bounds
  // checked below. Inputs occupy the first n1+n2 wires; outputs the last n3.
  if (num_gate < 0 || c.num_wire <= 0 || c.n1 < 0 || c.n2 < 0 || c.n3 < 0 ||
      c.n1 + c.n2 > c.num_wire || c.n3 > c.num_wire) {
    std::fclose(f);
    throw std::runtime_error("LoadBristol: inconsistent header in " + path);
  }
  c.gates.reserve(num_gate);
  for (int i = 0; i < num_gate; ++i) {
    int n_in = 0;
    int n_out = 0;
    if (std::fscanf(f, "%d %d", &n_in, &n_out) != 2 || n_out != 1) {
      std::fclose(f);
      throw std::runtime_error("LoadBristol: bad gate arity in " + path);
    }
    char op[16];
    Gate g;
    if (n_in == 2) {
      if (std::fscanf(f, "%d %d %d %15s", &g.in0, &g.in1, &g.out, op) != 4) {
        std::fclose(f);
        throw std::runtime_error("LoadBristol: bad 2-input gate in " + path);
      }
      if (op[0] == 'A') {
        g.type = Gate::kAnd;
      } else if (op[0] == 'X') {
        g.type = Gate::kXor;
      } else {
        std::fclose(f);
        throw std::runtime_error("LoadBristol: unknown 2-input op in " + path);
      }
    } else if (n_in == 1) {
      if (std::fscanf(f, "%d %d %15s", &g.in0, &g.out, op) != 3) {
        std::fclose(f);
        throw std::runtime_error("LoadBristol: bad 1-input gate in " + path);
      }
      g.in1 = -1;
      g.type = Gate::kInv;  // emp only emits INV as a unary gate
    } else {
      std::fclose(f);
      throw std::runtime_error("LoadBristol: unexpected gate fan-in in " + path);
    }
    // Bounds-check every wire index so a malformed circuit fails here rather
    // than indexing emp's wire/label arrays out of bounds (a segfault).
    auto in_range = [&](int w) { return w >= 0 && w < c.num_wire; };
    if (!in_range(g.in0) || !in_range(g.out) ||
        (g.type != Gate::kInv && !in_range(g.in1))) {
      std::fclose(f);
      throw std::runtime_error("LoadBristol: gate wire index out of range in " + path);
    }
    c.gates.push_back(g);
  }
  std::fclose(f);
  return c;
}

void SaveBristol(const Circuit& c, const std::string& path) {
  FILE* f = std::fopen(path.c_str(), "w");
  if (f == nullptr) {
    throw std::runtime_error("SaveBristol: cannot open " + path);
  }
  std::fprintf(f, "%d %d\n", c.num_gate(), c.num_wire);
  std::fprintf(f, "%d %d %d\n", c.n1, c.n2, c.n3);
  std::fprintf(f, "\n");
  for (const Gate& g : c.gates) {
    switch (g.type) {
      case Gate::kAnd:
        std::fprintf(f, "2 1 %d %d %d AND\n", g.in0, g.in1, g.out);
        break;
      case Gate::kXor:
        std::fprintf(f, "2 1 %d %d %d XOR\n", g.in0, g.in1, g.out);
        break;
      case Gate::kInv:
        std::fprintf(f, "1 1 %d %d INV\n", g.in0, g.out);
        break;
    }
  }
  std::fclose(f);
}

std::vector<uint8_t> EvalBristol(const Circuit& c,
                                 const std::vector<uint8_t>& in_bits) {
  if (static_cast<int>(in_bits.size()) != c.n1 + c.n2) {
    throw std::runtime_error("EvalBristol: wrong input width");
  }
  std::vector<uint8_t> w(c.num_wire, 0);
  for (int i = 0; i < c.n1 + c.n2; ++i) {
    w[i] = in_bits[i] & 1;
  }
  for (const Gate& g : c.gates) {
    switch (g.type) {
      case Gate::kAnd:
        w[g.out] = w[g.in0] & w[g.in1];
        break;
      case Gate::kXor:
        w[g.out] = w[g.in0] ^ w[g.in1];
        break;
      case Gate::kInv:
        w[g.out] = w[g.in0] ^ 1;
        break;
    }
  }
  std::vector<uint8_t> out(c.n3, 0);
  for (int i = 0; i < c.n3; ++i) {
    out[i] = w[c.num_wire - c.n3 + i];
  }
  return out;
}

}  // namespace shachain2pc::protocol
