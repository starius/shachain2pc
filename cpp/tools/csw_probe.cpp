#include <emp-ot/base_ot/csw.h>
#include <emp-tool/emp-tool.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>

namespace {

constexpr int kLength = 80;

enum class Transport { kListen, kConnect };
enum class OtRole { kSend, kRecv };

Transport ParseTransport(const char* s) {
  std::string v(s);
  if (v == "listen") return Transport::kListen;
  if (v == "connect") return Transport::kConnect;
  throw std::runtime_error("transport must be listen or connect");
}

OtRole ParseOtRole(const char* s) {
  std::string v(s);
  if (v == "send") return OtRole::kSend;
  if (v == "recv") return OtRole::kRecv;
  throw std::runtime_error("ot_role must be send or recv");
}

emp::block Data0(uint64_t i) {
  return emp::makeBlock(0x1000000000000000ULL | i,
                        0x0000000000000100ULL | i);
}

emp::block Data1(uint64_t i) {
  return emp::makeBlock(0x2000000000000000ULL | i,
                        0x0000000000000200ULL | i);
}

bool Choice(uint64_t i) {
  return ((i * 7 + 3) % 11) < 5;
}

void FillData(emp::block data0[kLength], emp::block data1[kLength]) {
  for (uint64_t i = 0; i < kLength; ++i) {
    data0[i] = Data0(i);
    data1[i] = Data1(i);
  }
}

void FillChoices(bool choices[kLength]) {
  for (uint64_t i = 0; i < kLength; ++i) choices[i] = Choice(i);
}

void VerifyRecv(const emp::block out[kLength],
                const emp::block data0[kLength],
                const emp::block data1[kLength],
                const bool choices[kLength]) {
  for (int i = 0; i < kLength; ++i) {
    const emp::block& expected = choices[i] ? data1[i] : data0[i];
    if (std::memcmp(&out[i], &expected, sizeof(emp::block)) != 0) {
      throw std::runtime_error("CSW recv output mismatch");
    }
  }
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 4 || argc > 5) {
    std::fprintf(stderr,
                 "usage: %s <listen|connect> <port> <send|recv> [peer_ip]\n",
                 argv[0]);
    return 2;
  }

  try {
    Transport transport = ParseTransport(argv[1]);
    int port = std::atoi(argv[2]);
    OtRole role = ParseOtRole(argv[3]);
    const char* peer = argc > 4 ? argv[4] : "127.0.0.1";
    if (port <= 0 || port > 65535) {
      throw std::runtime_error("port must be in 1..65535");
    }

    emp::NetIO io(transport == Transport::kListen ? nullptr : peer, port,
                  true);
    emp::CSW ot(&io);

    emp::block data0[kLength];
    emp::block data1[kLength];
    FillData(data0, data1);

    if (role == OtRole::kSend) {
      ot.send(data0, data1, kLength);
      io.flush();
    } else {
      bool choices[kLength];
      FillChoices(choices);
      emp::block out[kLength];
      ot.recv(out, choices, kLength);
      VerifyRecv(out, data0, data1, choices);
    }
  } catch (const std::exception& e) {
    std::fprintf(stderr, "csw_probe: %s\n", e.what());
    return 1;
  }
  return 0;
}
