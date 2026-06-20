// Transport probe for the current AG2PC primary+sibling NetIO shape.
#include <emp-tool/emp-tool.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>

namespace {

constexpr int kAlice = 1;
constexpr int kBob = 2;

int ParseParty(const char* arg) {
  int party = std::atoi(arg);
  if (party != kAlice && party != kBob) {
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

std::array<uint8_t, 8> Payload(int party, int stream_id) {
  uint8_t tag = party == kAlice ? 0xa7 : 0xb8;
  return {tag,
          static_cast<uint8_t>(stream_id),
          static_cast<uint8_t>(0x11 + stream_id),
          static_cast<uint8_t>(0x22 + stream_id),
          static_cast<uint8_t>(0x33 + stream_id),
          static_cast<uint8_t>(0x44 + stream_id),
          static_cast<uint8_t>(0x55 + stream_id),
          static_cast<uint8_t>(0x66 + stream_id)};
}

void Expect(const std::array<uint8_t, 8>& got,
            const std::array<uint8_t, 8>& want,
            const char* label) {
  if (std::memcmp(got.data(), want.data(), got.size()) != 0) {
    throw std::runtime_error(std::string("payload mismatch: ") + label);
  }
}

void Exercise(emp::NetIO* io, int party, int stream_id) {
  std::array<uint8_t, 8> mine = Payload(party, stream_id);
  std::array<uint8_t, 8> peer =
      Payload(party == kAlice ? kBob : kAlice, stream_id);
  std::array<uint8_t, 8> got{};
  if (party == kAlice) {
    io->send_data(mine.data(), mine.size());
    io->flush();
    io->recv_data(got.data(), got.size());
    Expect(got, peer, "alice recv");
  } else {
    io->recv_data(got.data(), got.size());
    Expect(got, peer, "bob recv");
    io->send_data(mine.data(), mine.size());
    io->flush();
  }
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
    const char* addr = (party == kAlice) ? nullptr : peer;
    emp::NetIO main(addr, port, /*quiet=*/true);
    SetTransportTimeout(&main);
    std::unique_ptr<emp::NetIO> sibling(main.make_sibling());
    SetTransportTimeout(sibling.get());

    Exercise(&main, party, 0);
    Exercise(sibling.get(), party, 1);
    std::printf("OK party=%d main_sent=%llu main_recv=%llu "
                "sibling_sent=%llu sibling_recv=%llu\n",
                party,
                static_cast<unsigned long long>(main.send_counter),
                static_cast<unsigned long long>(main.recv_counter),
                static_cast<unsigned long long>(sibling->send_counter),
                static_cast<unsigned long long>(sibling->recv_counter));
    return 0;
  } catch (const std::exception& e) {
    std::fprintf(stderr, "ABORT %s\n", e.what());
    return 1;
  }
}
