#include <emp-tool/emp-tool.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

#include "emp-ag2pc/fpre.h"

namespace {

constexpr int kRequestedSize = 321;

enum class Transport { kListen, kConnect };

class BlockBuffer {
 public:
  explicit BlockBuffer(int length)
      : length_(length), data_(new emp::block[length]) {}
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

struct Verification {
  emp::block delta;
  const BlockBuffer* key;
  const std::vector<uint8_t>* mac_bits;
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

bool SameBlock(emp::block lhs, emp::block rhs) {
  return std::memcmp(&lhs, &rhs, sizeof(emp::block)) == 0;
}

std::vector<uint8_t> MacBits(const BlockBuffer& mac) {
  std::vector<uint8_t> out(mac.size());
  for (int i = 0; i < mac.size(); ++i) {
    out[i] = emp::getLSB(mac[i]) ? 1 : 0;
  }
  return out;
}

void SendVerification(emp::NetIO& io, const Verification& verification) {
  io.send_block(&verification.delta, 1);
  io.send_block(verification.key->data(), verification.key->size());
  io.send_data(verification.mac_bits->data(),
               static_cast<int>(verification.mac_bits->size()));
  io.flush();
}

void RecvVerification(emp::NetIO& io, emp::block* delta, BlockBuffer* key,
                      std::vector<uint8_t>* mac_bits) {
  io.recv_block(delta, 1);
  io.recv_block(key->data(), key->size());
  mac_bits->resize(key->size());
  io.recv_data(mac_bits->data(), static_cast<int>(mac_bits->size()));
}

void VerifyRelation(const BlockBuffer& mac, emp::block remote_delta,
                    const BlockBuffer& remote_key) {
  for (int i = 0; i < mac.size(); ++i) {
    emp::block expected = emp::getLSB(mac[i]) ? (remote_key[i] ^ remote_delta)
                                              : remote_key[i];
    if (!SameBlock(mac[i], expected)) {
      throw std::runtime_error("Fpre refill MAC/KEY relation mismatch");
    }
  }
}

void VerifyTriples(const std::vector<uint8_t>& local_bits,
                   const std::vector<uint8_t>& remote_bits) {
  if (local_bits.size() != remote_bits.size() ||
      local_bits.size() % 3 != 0) {
    throw std::runtime_error("Fpre refill MAC-bit length mismatch");
  }
  for (size_t i = 0; i < local_bits.size() / 3; ++i) {
    bool a = (local_bits[3 * i] != 0) != (remote_bits[3 * i] != 0);
    bool b = (local_bits[3 * i + 1] != 0) != (remote_bits[3 * i + 1] != 0);
    bool c = (local_bits[3 * i + 2] != 0) != (remote_bits[3 * i + 2] != 0);
    if ((a && b) != c) {
      throw std::runtime_error("Fpre refill triple relation mismatch");
    }
  }
}

void ExchangeAndVerify(emp::NetIO& io, int party, const Verification& local,
                       const BlockBuffer& local_mac) {
  emp::block remote_delta;
  BlockBuffer remote_key(local.key->size());
  std::vector<uint8_t> remote_bits;
  if (party == emp::ALICE) {
    SendVerification(io, local);
    RecvVerification(io, &remote_delta, &remote_key, &remote_bits);
  } else {
    RecvVerification(io, &remote_delta, &remote_key, &remote_bits);
    SendVerification(io, local);
  }
  VerifyRelation(local_mac, remote_delta, remote_key);
  VerifyTriples(*local.mac_bits, remote_bits);
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 4 || argc > 5) {
    std::fprintf(stderr,
                 "usage: %s <listen|connect> <port> <1|2> [peer_ip]\n",
                 argv[0]);
    return 2;
  }

  try {
    Transport transport = ParseTransport(argv[1]);
    int port = std::atoi(argv[2]);
    int party = ParseParty(argv[3]);
    const char* peer = argc > 4 ? argv[4] : "127.0.0.1";
    if (port <= 0 || port > 65535) {
      throw std::runtime_error("port must be in 1..65535");
    }

    emp::NetIO io(transport == Transport::kListen ? nullptr : peer, port,
                  true);
    emp::Fpre<emp::NetIO> fpre(&io, party, kRequestedSize);
    fpre.refill();

    const int result_len = fpre.batch_size * 3;
    BlockBuffer mac(result_len);
    BlockBuffer key(result_len);
    std::memcpy(mac.data(), fpre.MAC_res, result_len * sizeof(emp::block));
    std::memcpy(key.data(), fpre.KEY_res, result_len * sizeof(emp::block));
    std::vector<uint8_t> mac_bits = MacBits(mac);

    Verification local{fpre.Delta, &key, &mac_bits};
    ExchangeAndVerify(io, party, local, mac);
  } catch (const std::exception& e) {
    std::fprintf(stderr, "fpre_refill_probe: %s\n", e.what());
    return 1;
  }
  return 0;
}
