#include <emp-tool/emp-tool.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <string>
#include <vector>

#include "emp-ag2pc/2pc.h"

namespace {

constexpr int kNumGate = 3;
constexpr int kNumWire = 8;
constexpr int kN1 = 3;
constexpr int kN2 = 2;
constexpr int kN3 = 1;
constexpr int kInputLen = kN1 + kN2;

int kGateArr[kNumGate * 4] = {
    0, 3, 5, 0,
    1, 4, 6, 1,
    5, 6, 7, 0,
};

bool kInput[kInputLen] = {true, false, true, true, true};
uint8_t kExpectedOutput[kN3] = {1};

enum class Transport { kListen, kConnect };

struct Options {
  const char* peer = "127.0.0.1";
  bool sync_before_dependent = false;
  bool sync_before_online = false;
};

Transport ParseTransport(const char* s) {
  std::string v(s);
  if (v == "listen") return Transport::kListen;
  if (v == "connect") return Transport::kConnect;
  throw std::runtime_error("transport must be listen or connect");
}

int ParseParty(const char* s) {
  std::string v(s);
  if (v == "1" || v == "alice") return emp::ALICE;
  if (v == "2" || v == "bob") return emp::BOB;
  throw std::runtime_error("party must be 1/alice or 2/bob");
}

Options ParseOptions(int argc, char** argv) {
  Options out;
  for (int i = 4; i < argc; ++i) {
    std::string v(argv[i]);
    if (v == "sync-before-dependent") {
      out.sync_before_dependent = true;
    } else if (v == "sync-before-online") {
      out.sync_before_online = true;
    } else {
      out.peer = argv[i];
    }
  }
  return out;
}

void WaitSync(emp::NetIO& io, const char* phase) {
  uint8_t marker = 0;
  io.recv_data(&marker, 1);
  if (marker != 0xA5) {
    throw std::runtime_error(std::string("bad sync marker before ") + phase);
  }
}

std::vector<uint8_t> OutputBytes(const bool* output) {
  std::vector<uint8_t> out(kN3);
  for (int i = 0; i < kN3; ++i) out[i] = output[i] ? 1 : 0;
  return out;
}

void VerifyOutput(const std::vector<uint8_t>& output,
                  const char* description) {
  for (int i = 0; i < kN3; ++i) {
    if (output[i] != kExpectedOutput[i]) {
      throw std::runtime_error(std::string(description) +
                               " C2PC online output mismatch");
    }
  }
}

void ExchangeAndVerify(emp::NetIO& io, int party,
                       const std::vector<uint8_t>& local) {
  std::vector<uint8_t> remote(kN3);
  if (party == emp::ALICE) {
    io.send_data(local.data(), kN3);
    io.recv_data(remote.data(), kN3);
  } else {
    io.recv_data(remote.data(), kN3);
    io.send_data(local.data(), kN3);
  }
  io.flush();
  VerifyOutput(local, "local");
  VerifyOutput(remote, "remote");
  if (local != remote) {
    throw std::runtime_error("C2PC online cross-mode output mismatch");
  }
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 4 || argc > 7) {
    std::fprintf(stderr,
                 "usage: %s <listen|connect> <port> <1|2> [peer_ip] "
                 "[sync-before-dependent] [sync-before-online]\n",
                 argv[0]);
    return 2;
  }

  try {
    Transport transport = ParseTransport(argv[1]);
    int port = std::atoi(argv[2]);
    int party = ParseParty(argv[3]);
    Options options = ParseOptions(argc, argv);
    if (port <= 0 || port > 65535) {
      throw std::runtime_error("port must be in 1..65535");
    }

    emp::NetIO io(transport == Transport::kListen ? nullptr : options.peer, port,
                  true);
    emp::BristolFormat cf(kNumGate, kNumWire, kN1, kN2, kN3, kGateArr);
    emp::C2PC<emp::NetIO> twopc(&io, party, &cf);
    twopc.function_independent();
    if (options.sync_before_dependent) WaitSync(io, "function_dependent");
    twopc.function_dependent();
    if (options.sync_before_online) WaitSync(io, "online");

    bool output[kN3] = {};
    twopc.online(kInput, output, true);
    ExchangeAndVerify(io, party, OutputBytes(output));
  } catch (const std::exception& e) {
    std::fprintf(stderr, "c2pc_online_probe: %s\n", e.what());
    return 1;
  }
  return 0;
}
