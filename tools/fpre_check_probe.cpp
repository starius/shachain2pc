#include <emp-tool/emp-tool.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>

#include "emp-ag2pc/fpre.h"

namespace {

constexpr int kRequestedSize = 321;
constexpr int kCheckLength = 683;
constexpr int kDotLength = kCheckLength * 3;

enum class Transport { kListen, kConnect };

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

struct Verification {
  emp::block delta;
  const BlockBuffer* key;
  std::array<uint8_t, emp::Hash::DIGEST_SIZE> digest;
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

int ParseCheckIndex(const char* s) {
  int index = std::atoi(s);
  if (index == 0 || index == 1) return index;
  throw std::runtime_error("check_index must be 0 or 1");
}

bool SameBlock(emp::block lhs, emp::block rhs) {
  return std::memcmp(&lhs, &rhs, sizeof(emp::block)) == 0;
}

void SendVerification(emp::NetIO& io, const Verification& verification) {
  io.send_block(&verification.delta, 1);
  io.send_block(verification.key->data(), verification.key->size());
  io.send_data(verification.digest.data(), verification.digest.size());
  io.flush();
}

void RecvVerification(emp::NetIO& io, emp::block* delta, BlockBuffer* key,
                      std::array<uint8_t, emp::Hash::DIGEST_SIZE>* digest) {
  io.recv_block(delta, 1);
  io.recv_block(key->data(), key->size());
  io.recv_data(digest->data(), digest->size());
}

void VerifyRelation(const BlockBuffer& mac, emp::block remote_delta,
                    const BlockBuffer& remote_key) {
  for (int i = 0; i < mac.size(); ++i) {
    emp::block expected = emp::getLSB(mac[i]) ? (remote_key[i] ^ remote_delta)
                                              : remote_key[i];
    if (!SameBlock(mac[i], expected)) {
      throw std::runtime_error("Fpre check MAC/KEY relation mismatch");
    }
  }
}

void VerifyDigest(
    const std::array<uint8_t, emp::Hash::DIGEST_SIZE>& local,
    const std::array<uint8_t, emp::Hash::DIGEST_SIZE>& remote) {
  if (std::memcmp(local.data(), remote.data(), local.size()) != 0) {
    throw std::runtime_error("Fpre check Feq digest mismatch");
  }
}

void ExchangeAndVerify(emp::NetIO& io, int party, const Verification& local,
                       const BlockBuffer& local_mac) {
  emp::block remote_delta;
  BlockBuffer remote_key(local.key->size());
  std::array<uint8_t, emp::Hash::DIGEST_SIZE> remote_digest;
  if (party == emp::ALICE) {
    SendVerification(io, local);
    RecvVerification(io, &remote_delta, &remote_key, &remote_digest);
  } else {
    RecvVerification(io, &remote_delta, &remote_key, &remote_digest);
    SendVerification(io, local);
  }
  VerifyRelation(local_mac, remote_delta, remote_key);
  VerifyDigest(local.digest, remote_digest);
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 5 || argc > 6) {
    std::fprintf(
        stderr,
        "usage: %s <listen|connect> <port> <1|2> <check_index> [peer_ip]\n",
        argv[0]);
    return 2;
  }

  try {
    Transport transport = ParseTransport(argv[1]);
    int port = std::atoi(argv[2]);
    int party = ParseParty(argv[3]);
    int check_index = ParseCheckIndex(argv[4]);
    const char* peer = argc > 5 ? argv[5] : "127.0.0.1";
    if (port <= 0 || port > 65535) {
      throw std::runtime_error("port must be in 1..65535");
    }

    emp::NetIO io(transport == Transport::kListen ? nullptr : peer, port,
                  true);
    emp::Fpre<emp::NetIO> fpre(&io, party, kRequestedSize);
    BlockBuffer mac(kDotLength);
    BlockBuffer key(kDotLength);
    fpre.generate(mac.data(), key.data(), kCheckLength, 0);
    fpre.check(mac.data(), key.data(), kCheckLength, check_index);

    Verification local{fpre.Delta, &key, {}};
    fpre.eq[check_index]->dgst(reinterpret_cast<char*>(local.digest.data()));
    ExchangeAndVerify(io, party, local, mac);
  } catch (const std::exception& e) {
    std::fprintf(stderr, "fpre_check_probe: %s\n", e.what());
    return 1;
  }
  return 0;
}
