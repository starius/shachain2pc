// Live C++ probe for the current emp::SoftSpoken<4> COT backend.
#include <emp-ot/ot_extension/softspoken/softspoken.h>
#include <emp-tool/emp-tool.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

constexpr int kLength = 2051;

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

bool Lsb(emp::block b) {
  alignas(16) std::array<uint8_t, 16> bytes{};
  _mm_storeu_si128(reinterpret_cast<__m128i*>(bytes.data()), b);
  return (bytes[0] & 1) != 0;
}

std::string HexBytes(const uint8_t* data, size_t len) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.resize(len * 2);
  for (size_t i = 0; i < len; ++i) {
    out[2 * i] = kHex[data[i] >> 4];
    out[2 * i + 1] = kHex[data[i] & 0x0f];
  }
  return out;
}

std::string HexBlock(emp::block b) {
  alignas(16) std::array<uint8_t, 16> bytes{};
  _mm_storeu_si128(reinterpret_cast<__m128i*>(bytes.data()), b);
  return HexBytes(bytes.data(), bytes.size());
}

std::array<bool, 128> FixedDeltaBits() {
  std::array<bool, 128> bits{};
  for (int i = 0; i < 128; ++i) {
    bits[i] = ((i * 17 + 9) % 23) < 11;
  }
  bits[0] = true;
  return bits;
}

void PrintJson(int party, bool verified, emp::NetIO& io, emp::block delta) {
  std::printf(
      "{\"schema\":\"shachain2pc.softspoken_probe.v1\","
      "\"probe\":\"softspoken4\","
      "\"party\":%d,"
      "\"length\":%d,"
      "\"chunk_size\":%lld,"
      "\"verified\":%s,"
      "\"sent\":%llu,"
      "\"recv\":%llu,"
      "\"rounds\":%llu,"
      "\"flushes\":%llu,"
      "\"delta\":\"%s\","
      "\"digest\":\"%s\"}\n",
      party, kLength,
      static_cast<long long>(emp::SoftSpoken<4>::kChunkOTs),
      verified ? "true" : "false",
      static_cast<unsigned long long>(io.send_counter),
      static_cast<unsigned long long>(io.recv_counter),
      static_cast<unsigned long long>(io.rounds),
      static_cast<unsigned long long>(io.flushes_count),
      HexBlock(delta).c_str(), HexBlock(io.get_digest()).c_str());
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
    emp::NetIO io(addr, port, /*quiet=*/true);
    SetTransportTimeout(&io);

    emp::SoftSpoken<4> cot(party, &io, /*malicious=*/true);
    if (party == emp::ALICE) {
      std::array<bool, 128> bits = FixedDeltaBits();
      cot.set_delta(bits.data());
    }

    std::vector<emp::block> out(kLength);
    cot.begin();
    cot.next_n(out.data(), out.size());
    cot.end();

    bool verified = true;
    emp::block delta = cot.Delta;
    if (party == emp::ALICE) {
      io.send_block(&delta, 1);
      io.send_block(out.data(), out.size());
      io.flush();
      uint8_t ok = 0;
      io.recv_data(&ok, 1);
      verified = ok == 1;
    } else {
      io.recv_block(&delta, 1);
      std::vector<emp::block> sender(kLength);
      io.recv_block(sender.data(), sender.size());
      for (int i = 0; i < kLength; ++i) {
        bool choice = Lsb(out[i]);
        emp::block expected = sender[i] ^ (emp::select_mask[choice] & delta);
        if (!emp::cmpBlock(&expected, &out[i], 1)) {
          verified = false;
          break;
        }
      }
      uint8_t ok = verified ? 1 : 0;
      io.send_data(&ok, 1);
      io.flush();
    }
    PrintJson(party, verified, io, delta);
    return verified ? 0 : 1;
  } catch (const std::exception& e) {
    std::fprintf(stderr, "ABORT %s\n", e.what());
    return 1;
  }
}
