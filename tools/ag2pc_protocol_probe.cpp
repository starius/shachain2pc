// Live C++ probe for AG2PCProtocol input authentication and decode.
#include <emp-tool/emp-tool.h>
#include <emp-tool/runtime/runtime.h>
#include <emp-ag2pc/backend/protocol.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <cstdio>
#include <cstdlib>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

constexpr int kSsp = 40;

int ParseParty(const char* arg) {
  int party = std::atoi(arg);
  if (party != emp::ALICE && party != emp::BOB) {
    throw std::runtime_error("party must be 1 or 2");
  }
  return party;
}

void SetTransportTimeout(emp::NetIO* io) {
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

bool Eq(const std::vector<uint8_t>& got, const std::vector<uint8_t>& want) {
  return got == want;
}

}  // namespace

int main(int argc, char** argv) {
  try {
    if (argc < 3 || argc > 4) {
      std::fprintf(stderr, "usage: %s <1|2> <port> [peer_ip]\n", argv[0]);
      return 2;
    }
    int party = ParseParty(argv[1]);
    int port = std::atoi(argv[2]);
    if (port <= 0 || port > 65535) {
      throw std::runtime_error("port must be in 1..65535");
    }
    const char* peer = (argc == 4) ? argv[3] : "127.0.0.1";
    const char* addr = (party == emp::ALICE) ? nullptr : peer;

    emp::NetIO main(addr, port, /*quiet=*/true);
    SetTransportTimeout(&main);
    ThreadPool thread_pool(4);
    AG2PCProtocol proto(&main, &thread_pool, party, kSsp);
    SetTransportTimeout(proto.sib);

    std::vector<uint8_t> alice_bits =
        (party == emp::ALICE) ? std::vector<uint8_t>{1, 0}
                              : std::vector<uint8_t>{0, 0};
    std::vector<uint8_t> bob_bits =
        (party == emp::BOB) ? std::vector<uint8_t>{1}
                            : std::vector<uint8_t>{0};
    std::vector<emp::SecureWires> inputs = proto.process_inputs(
        std::vector<int>{emp::ALICE, emp::BOB},
        std::vector<std::vector<uint8_t>>{alice_bits, bob_bits});
    proto.flush_cot_check();

    std::vector<uint8_t> alice_open = proto.decode(inputs[0], emp::PUBLIC);
    std::vector<uint8_t> bob_open = proto.decode(inputs[1], emp::PUBLIC);
    emp::SecureWires pub = proto.public_wires(std::vector<uint8_t>{1, 0, 1});
    std::vector<uint8_t> public_open = proto.decode(pub, emp::PUBLIC);

    bool ok = Eq(alice_open, std::vector<uint8_t>{1, 0}) &&
              Eq(bob_open, std::vector<uint8_t>{1}) &&
              Eq(public_open, std::vector<uint8_t>{1, 0, 1}) &&
              proto.process_input_calls == 1;
    std::printf(
        "{\"schema\":\"shachain2pc.ag2pc_protocol_probe.v1\","
        "\"party\":%d,\"verified\":%s,"
        "\"process_input_calls\":%d,"
        "\"alice_len\":%zu,\"bob_len\":%zu,\"public_len\":%zu}\n",
        party, ok ? "true" : "false", proto.process_input_calls,
        alice_open.size(), bob_open.size(), public_open.size());
    return ok ? 0 : 1;
  } catch (const std::exception& e) {
    std::fprintf(stderr, "ABORT %s\n", e.what());
    return 1;
  }
}
