// Measure per-phase bytes sent by one party for a given circuit, summed across
// the main connection and all of Fpre's preprocessing sockets (it spawns its
// own connections per thread). Round structure is constant; this shows how
// bandwidth scales with the AND-gate count. Run like demo/party (two processes).
#include <emp-tool/emp-tool.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "emp-ag2pc/emp-ag2pc.h"

using namespace emp;

static uint64_t TotalSent(C2PC<NetIO>& t) {
  uint64_t s = t.io->counter;
  for (int i = 0; i < Fpre<NetIO>::THDS; ++i) {
    s += t.fpre->io[i]->counter;
    s += t.fpre->io2[i]->counter;
  }
  return s;
}

int main(int argc, char** argv) {
  if (argc < 4) {
    std::fprintf(stderr, "usage: %s <1|2> <port> <circuit> [peer_ip]\n", argv[0]);
    return 2;
  }
  int party = std::atoi(argv[1]);
  int port = std::atoi(argv[2]);
  const char* circ = argv[3];
  const char* peer = argc > 4 ? argv[4] : "127.0.0.1";

  // emp's BristolFormat loader fscanf()s a NULL FILE* (segfault) on a missing
  // circuit; guard against that before constructing it.
  if (FILE* f = std::fopen(circ, "r")) {
    std::fclose(f);
  } else {
    std::fprintf(stderr, "measure_io: cannot open circuit '%s'\n", circ);
    return 1;
  }

  NetIO* io = new NetIO(party == ALICE ? nullptr : peer, port);
  BristolFormat cf(circ);
  int ands = 0;
  for (int i = 0; i < cf.num_gate; ++i)
    if (cf.gates[4 * i + 3] == AND_GATE) ++ands;

  C2PC<NetIO> twopc(io, party, &cf);
  io->flush();
  uint64_t c_setup = TotalSent(twopc);
  twopc.function_independent();
  io->flush();
  uint64_t c_indep = TotalSent(twopc);
  twopc.function_dependent();
  io->flush();
  uint64_t c_dep = TotalSent(twopc);

  bool* in = new bool[cf.n1 + cf.n2];
  bool* out = new bool[cf.n3];
  std::memset(in, 0, cf.n1 + cf.n2);
  twopc.online(in, out, true);
  io->flush();
  uint64_t c_online = TotalSent(twopc);

  std::fprintf(stderr,
               "party %d  ANDs=%d\n"
               "  setup (base OT) : %10lu bytes\n"
               "  func-independent: %10lu bytes  (auth. AND triples)\n"
               "  func-dependent  : %10lu bytes  (garbled tables)\n"
               "  online          : %10lu bytes  (input/output)\n"
               "  TOTAL SENT      : %10lu bytes  (%.2f MB)\n",
               party, ands, (unsigned long)c_setup,
               (unsigned long)(c_indep - c_setup), (unsigned long)(c_dep - c_indep),
               (unsigned long)(c_online - c_dep), (unsigned long)c_online,
               c_online / 1048576.0);
  delete[] in;
  delete[] out;
  delete io;
  return 0;
}
