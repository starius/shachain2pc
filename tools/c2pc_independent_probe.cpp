#include <emp-tool/emp-tool.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
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
constexpr int kNumAnds = 2;
constexpr int kTotalPre = kInputLen + kNumAnds;

int kGateArr[kNumGate * 4] = {
    0, 3, 5, 0,
    1, 4, 6, 1,
    5, 6, 7, 0,
};

enum class Transport { kListen, kConnect };

struct BlockSpan {
  const emp::block* data;
  int length;
};

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
  BlockSpan input_key;
  BlockSpan preprocess_key;
  BlockSpan ands_key;
  const std::vector<uint8_t>* ands_bits;
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

std::vector<uint8_t> MacBits(const emp::block* mac, int length) {
  std::vector<uint8_t> out(length);
  for (int i = 0; i < length; ++i) {
    out[i] = emp::getLSB(mac[i]) ? 1 : 0;
  }
  return out;
}

void SendSpan(emp::NetIO& io, BlockSpan span) {
  io.send_block(span.data, span.length);
}

void RecvSpan(emp::NetIO& io, BlockBuffer* out) {
  io.recv_block(out->data(), out->size());
}

void SendVerification(emp::NetIO& io, const Verification& verification) {
  io.send_block(&verification.delta, 1);
  SendSpan(io, verification.input_key);
  SendSpan(io, verification.preprocess_key);
  SendSpan(io, verification.ands_key);
  io.send_data(verification.ands_bits->data(),
               static_cast<int>(verification.ands_bits->size()));
  io.flush();
}

void RecvVerification(emp::NetIO& io, emp::block* delta,
                      BlockBuffer* input_key, BlockBuffer* preprocess_key,
                      BlockBuffer* ands_key,
                      std::vector<uint8_t>* ands_bits) {
  io.recv_block(delta, 1);
  RecvSpan(io, input_key);
  RecvSpan(io, preprocess_key);
  RecvSpan(io, ands_key);
  ands_bits->resize(ands_key->size());
  io.recv_data(ands_bits->data(), static_cast<int>(ands_bits->size()));
}

void VerifyRelation(const emp::block* mac, int length, emp::block remote_delta,
                    const BlockBuffer& remote_key,
                    const char* description) {
  for (int i = 0; i < length; ++i) {
    emp::block expected = emp::getLSB(mac[i]) ? (remote_key[i] ^ remote_delta)
                                              : remote_key[i];
    if (!SameBlock(mac[i], expected)) {
      throw std::runtime_error(std::string(description) +
                               " MAC/KEY relation mismatch");
    }
  }
}

void VerifyTriples(const std::vector<uint8_t>& local_bits,
                   const std::vector<uint8_t>& remote_bits) {
  if (local_bits.size() != remote_bits.size() ||
      local_bits.size() % 3 != 0) {
    throw std::runtime_error("C2PC independent AND-bit length mismatch");
  }
  for (size_t i = 0; i < local_bits.size() / 3; ++i) {
    bool a = (local_bits[3 * i] != 0) != (remote_bits[3 * i] != 0);
    bool b = (local_bits[3 * i + 1] != 0) != (remote_bits[3 * i + 1] != 0);
    bool c = (local_bits[3 * i + 2] != 0) != (remote_bits[3 * i + 2] != 0);
    if ((a && b) != c) {
      throw std::runtime_error("C2PC independent AND triple mismatch");
    }
  }
}

void ExchangeAndVerify(emp::NetIO& io, int party,
                       const Verification& local,
                       const emp::C2PC<emp::NetIO>& twopc) {
  emp::block remote_delta;
  BlockBuffer remote_input_key(kInputLen);
  BlockBuffer remote_preprocess_key(kTotalPre);
  BlockBuffer remote_ands_key(kNumAnds * 3);
  std::vector<uint8_t> remote_ands_bits;
  if (party == emp::ALICE) {
    SendVerification(io, local);
    RecvVerification(io, &remote_delta, &remote_input_key,
                     &remote_preprocess_key, &remote_ands_key,
                     &remote_ands_bits);
  } else {
    RecvVerification(io, &remote_delta, &remote_input_key,
                     &remote_preprocess_key, &remote_ands_key,
                     &remote_ands_bits);
    SendVerification(io, local);
  }

  VerifyRelation(twopc.mac, kInputLen, remote_delta, remote_input_key,
                 "C2PC input");
  VerifyRelation(twopc.preprocess_mac, kTotalPre, remote_delta,
                 remote_preprocess_key, "C2PC preprocess");
  VerifyRelation(twopc.ANDS_mac, kNumAnds * 3, remote_delta, remote_ands_key,
                 "C2PC ANDS");
  VerifyTriples(*local.ands_bits, remote_ands_bits);
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
    emp::BristolFormat cf(kNumGate, kNumWire, kN1, kN2, kN3, kGateArr);
    emp::C2PC<emp::NetIO> twopc(&io, party, &cf);
    twopc.function_independent();

    std::vector<uint8_t> ands_bits = MacBits(twopc.ANDS_mac, kNumAnds * 3);
    Verification local{
        twopc.fpre->Delta,
        {twopc.key, kInputLen},
        {twopc.preprocess_key, kTotalPre},
        {twopc.ANDS_key, kNumAnds * 3},
        &ands_bits,
    };
    ExchangeAndVerify(io, party, local, twopc);
  } catch (const std::exception& e) {
    std::fprintf(stderr, "c2pc_independent_probe: %s\n", e.what());
    return 1;
  }
  return 0;
}
