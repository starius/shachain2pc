#include <emp-tool/emp-tool.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

#include "emp-ag2pc/leaky_deltaot.h"
#include "emp-ot/iknp.h"

namespace {

constexpr int kIknpLength = 2051;
constexpr int kLeakyLength = 257;
constexpr int kSecurityBits = 128;

enum class Transport { kListen, kConnect };
enum class ProbeRole { kIknpSend, kIknpRecv, kLeakySend, kLeakyRecv };

class BlockBuffer {
 public:
  explicit BlockBuffer(int length) : length_(length), data_(new emp::block[length]) {}
  ~BlockBuffer() { delete[] data_; }

  BlockBuffer(const BlockBuffer&) = delete;
  BlockBuffer& operator=(const BlockBuffer&) = delete;

  emp::block* data() { return data_; }
  const emp::block* data() const { return data_; }
  int size() const { return length_; }
  emp::block& operator[](int i) { return data_[i]; }
  const emp::block& operator[](int i) const { return data_[i]; }

 private:
  int length_;
  emp::block* data_;
};

Transport ParseTransport(const char* s) {
  std::string v(s);
  if (v == "listen") return Transport::kListen;
  if (v == "connect") return Transport::kConnect;
  throw std::runtime_error("transport must be listen or connect");
}

ProbeRole ParseRole(const char* s) {
  std::string v(s);
  if (v == "iknp-send") return ProbeRole::kIknpSend;
  if (v == "iknp-recv") return ProbeRole::kIknpRecv;
  if (v == "leaky-send") return ProbeRole::kLeakySend;
  if (v == "leaky-recv") return ProbeRole::kLeakyRecv;
  throw std::runtime_error(
      "role must be iknp-send, iknp-recv, leaky-send, or leaky-recv");
}

std::vector<bool> Choices(int length) {
  std::vector<bool> choices(length);
  for (int i = 0; i < length; ++i) choices[i] = ((i * 7 + 3) % 11) < 5;
  return choices;
}

void ChoicesArray(bool* out, int length) {
  for (int i = 0; i < length; ++i) out[i] = ((i * 7 + 3) % 11) < 5;
}

void LeakySendChoices(bool out[kSecurityBits]) {
  for (int i = 0; i < kSecurityBits; ++i) out[i] = ((i * 5 + 1) % 9) < 4;
  out[0] = true;
}

bool SameBlock(emp::block lhs, emp::block rhs) {
  return std::memcmp(&lhs, &rhs, sizeof(emp::block)) == 0;
}

void SendVerification(emp::NetIO& io, emp::block delta,
                      const BlockBuffer& sender_data) {
  io.send_block(&delta, 1);
  io.send_block(sender_data.data(), sender_data.size());
  io.flush();
}

void VerifyIknp(const BlockBuffer& receiver_data,
                const std::vector<bool>& choices, emp::block delta,
                const BlockBuffer& sender_data) {
  for (int i = 0; i < receiver_data.size(); ++i) {
    emp::block expected = choices[i] ? (sender_data[i] ^ delta) : sender_data[i];
    if (!SameBlock(receiver_data[i], expected)) {
      throw std::runtime_error("IKNP COT relation mismatch");
    }
  }
}

void VerifyLeaky(const BlockBuffer& receiver_data, emp::block delta,
                 const BlockBuffer& sender_data) {
  for (int i = 0; i < receiver_data.size(); ++i) {
    emp::block expected =
        emp::getLSB(receiver_data[i]) ? (sender_data[i] ^ delta) : sender_data[i];
    if (!SameBlock(receiver_data[i], expected)) {
      throw std::runtime_error("LeakyDeltaOT relation mismatch");
    }
  }
}

void RecvAndVerifyIknp(emp::NetIO& io,
                       const BlockBuffer& receiver_data,
                       const std::vector<bool>& choices) {
  emp::block delta;
  BlockBuffer sender_data(receiver_data.size());
  io.recv_block(&delta, 1);
  io.recv_block(sender_data.data(), sender_data.size());
  VerifyIknp(receiver_data, choices, delta, sender_data);
}

void RecvAndVerifyLeaky(emp::NetIO& io,
                        const BlockBuffer& receiver_data) {
  emp::block delta;
  BlockBuffer sender_data(receiver_data.size());
  io.recv_block(&delta, 1);
  io.recv_block(sender_data.data(), sender_data.size());
  VerifyLeaky(receiver_data, delta, sender_data);
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 4 || argc > 5) {
    std::fprintf(
        stderr,
        "usage: %s <listen|connect> <port> <role> [peer_ip]\n",
        argv[0]);
    return 2;
  }

  try {
    Transport transport = ParseTransport(argv[1]);
    int port = std::atoi(argv[2]);
    ProbeRole role = ParseRole(argv[3]);
    const char* peer = argc > 4 ? argv[4] : "127.0.0.1";
    if (port <= 0 || port > 65535) {
      throw std::runtime_error("port must be in 1..65535");
    }

    emp::NetIO io(transport == Transport::kListen ? nullptr : peer, port,
                  true);

    if (role == ProbeRole::kIknpSend) {
      emp::IKNP<emp::NetIO> iknp(&io, false);
      BlockBuffer data(kIknpLength);
      iknp.send_cot(data.data(), data.size());
      SendVerification(io, iknp.Delta, data);
    } else if (role == ProbeRole::kIknpRecv) {
      emp::IKNP<emp::NetIO> iknp(&io, false);
      bool choices[kIknpLength];
      ChoicesArray(choices, kIknpLength);
      BlockBuffer data(kIknpLength);
      iknp.recv_cot(data.data(), choices, data.size());
      RecvAndVerifyIknp(io, data, Choices(kIknpLength));
    } else if (role == ProbeRole::kLeakySend) {
      emp::LeakyDeltaOT<emp::NetIO> dot(&io);
      bool s[kSecurityBits];
      LeakySendChoices(s);
      dot.setup_send(s);
      io.flush();
      BlockBuffer data(kLeakyLength);
      dot.send_dot(data.data(), data.size());
      SendVerification(io, dot.Delta, data);
    } else {
      emp::LeakyDeltaOT<emp::NetIO> dot(&io);
      dot.setup_recv();
      io.flush();
      BlockBuffer data(kLeakyLength);
      dot.recv_dot(data.data(), data.size());
      RecvAndVerifyLeaky(io, data);
    }
  } catch (const std::exception& e) {
    std::fprintf(stderr, "iknp_probe: %s\n", e.what());
    return 1;
  }
  return 0;
}
