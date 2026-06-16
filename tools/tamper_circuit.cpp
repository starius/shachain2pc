// Adversary helper for low-level experiments: produce a tampered copy of an
// agreed circuit that computes a DIFFERENT function while preserving the
// gate/wire/AND counts, so the malicious-2PC protocol structure still matches.
#include <cstdio>
#include <string>

#include "../protocol/bristol.h"

int main(int argc, char** argv) {
  if (argc < 3) {
    std::fprintf(stderr, "usage: %s <in_bristol> <out_bristol>\n", argv[0]);
    return 2;
  }
  using namespace shachain2pc::protocol;
  Circuit c = LoadBristol(argv[1]);

  // Rewire the last AND gate's first input to a different existing wire. This
  // changes the computed function but keeps num_gate/num_wire and the AND count
  // identical, so both parties' C2PC preprocessing stays in lockstep.
  int idx = -1;
  for (int i = c.num_gate() - 1; i >= 0; --i) {
    if (c.gates[i].type == Gate::kAnd) {
      idx = i;
      break;
    }
  }
  if (idx < 0) {
    std::fprintf(stderr, "tamper: no AND gate found\n");
    return 1;
  }
  int old_in0 = c.gates[idx].in0;
  c.gates[idx].in0 = (old_in0 == 0) ? 1 : 0;  // wires 0/1 are always defined
  std::fprintf(stderr, "tampered AND gate #%d: in0 %d -> %d (out wire %d)\n", idx,
               old_in0, c.gates[idx].in0, c.gates[idx].out);

  SaveBristol(c, argv[2]);
  return 0;
}
