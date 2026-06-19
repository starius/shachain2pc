// One party of the maliciously-secure two-party derivation. Party 1 is the emp
// garbler (ALICE) and listens; party 2 is the evaluator (BOB) and connects to
// the peer. Each supplies only its own seed share. On success both print the
// derived value H(I) as "RESULT <hex>".
#include <emp-tool/emp-tool.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <cstdio>
#include <cstdlib>
#include <stdexcept>
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
  if (secs == 0 || io->sock < 0) return;
  struct timeval tv;
  tv.tv_sec = secs;
  tv.tv_usec = 0;
  setsockopt(io->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(io->sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

int main(int argc, char** argv) {
  if (argc < 5) {
    std::fprintf(stderr,
                 "usage: %s <1|2> <port> <I_hex> <share_hex> [peer_ip]\n"
                 "  1 = ALICE (garbler, listens), 2 = BOB (evaluator, connects)\n",
                 argv[0]);
    return 2;
  }
  using namespace shachain2pc;
  int party = std::atoi(argv[1]);
  int port = std::atoi(argv[2]);
  uint64_t index = 0;
  protocol::Value share{};
  try {
    if (party != run::kAlice && party != run::kBob) {
      throw std::runtime_error("party must be 1 or 2");
    }
    if (port <= 0 || port > 65535) {
      throw std::runtime_error("port must be in 1..65535");
    }
    index = util::FromHexU48(argv[3]);
    share = util::FromHex32(argv[4]);
  } catch (const std::exception& e) {
    std::fprintf(stderr, "ABORT %s\n", e.what());
    return 1;
  }
  const char* peer = argc > 5 ? argv[5] : "127.0.0.1";

  const char* addr = (party == run::kAlice) ? nullptr : peer;
  emp::NetIO* io = new emp::NetIO(addr, port);
  SetTransportTimeout(io);  // bound blocking recv/send so a stalled peer aborts
  ThreadPool pool(run::kThreads);  // session-local compute parallelism (global type)
  try {
    protocol::Value out = run::RunDerivation(io, &pool, party, index, share);
    delete io;
    std::printf("RESULT %s\n", util::ToHex(out).c_str());
    return 0;
  } catch (const std::exception& e) {
    delete io;
    std::fprintf(stderr, "ABORT %s\n", e.what());
    return 1;
  }
}
