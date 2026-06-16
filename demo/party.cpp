// One party of the maliciously-secure two-party derivation. Party 1 is the emp
// garbler (ALICE) and listens; party 2 is the evaluator (BOB) and connects to
// the peer. Each supplies only its own seed share. On success both print the
// derived value H(I) as "RESULT <hex>".
#include <emp-tool/emp-tool.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <cstdio>
#include <cstdlib>
#include <string>

#include "../run/derive.h"
#include "../util/hex.h"

// SetTransportTimeout bounds how long any blocking recv/send on the connected
// socket waits, so a stalled or dead-but-open peer aborts the run (emp surfaces
// the timed-out recv as a clean error/exit) instead of hanging forever. It is a
// per-call inactivity timeout, generous by default so it never trips on a
// legitimate slow phase; override the seconds via SHACHAIN2PC_TIMEOUT_SECS
// (0 disables it).
static void SetTransportTimeout(emp::NetIO* io) {
  long secs = 300;
  if (const char* e = std::getenv("SHACHAIN2PC_TIMEOUT_SECS")) {
    char* end = nullptr;
    long v = std::strtol(e, &end, 10);
    if (end != e && v >= 0) secs = v;
  }
  if (secs == 0 || io->consocket < 0) return;
  struct timeval tv;
  tv.tv_sec = secs;
  tv.tv_usec = 0;
  setsockopt(io->consocket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(io->consocket, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

int main(int argc, char** argv) {
  if (argc < 5) {
    std::fprintf(stderr,
                 "usage: %s <1|2> <port> <circuit_path> <share_hex> [peer_ip]\n"
                 "  1 = ALICE (garbler, listens), 2 = BOB (evaluator, connects)\n",
                 argv[0]);
    return 2;
  }
  using namespace shachain2pc;
  int party = std::atoi(argv[1]);
  int port = std::atoi(argv[2]);
  std::string circuit = argv[3];
  auto share = util::FromHex32(argv[4]);
  const char* peer = argc > 5 ? argv[5] : "127.0.0.1";

  // Validate the circuit before opening the socket, so a missing/wrong file
  // fails fast with a clear message instead of blocking on the peer (or letting
  // emp's loader segfault on a NULL FILE*).
  try {
    run::ValidateCircuitFile(circuit);
  } catch (const std::exception& e) {
    std::fprintf(stderr, "ABORT %s\n", e.what());
    return 1;
  }

  const char* addr = (party == run::kAlice) ? nullptr : peer;
  emp::NetIO* io = new emp::NetIO(addr, port);
  SetTransportTimeout(io);  // bound blocking recv/send so a stalled peer aborts
  try {
    protocol::Value out = run::RunDerivation(io, party, circuit, share);
    delete io;
    std::printf("RESULT %s\n", util::ToHex(out).c_str());
    return 0;
  } catch (const std::exception& e) {
    delete io;
    std::fprintf(stderr, "ABORT %s\n", e.what());
    return 1;
  }
}
