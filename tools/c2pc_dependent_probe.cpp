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
constexpr int kNumAnds = 2;
constexpr int kSspBytes = 5;
constexpr int kGarbledTableBytes = kNumAnds * 4 * (kSspBytes + 16);

int kGateArr[kNumGate * 4] = {
    0, 3, 5, 0,
    1, 4, 6, 1,
    5, 6, 7, 0,
};

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
  const emp::block* key;
  const emp::block* sigma_key;
  const std::vector<uint8_t>* garbled_table;
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

void AppendBlock(std::vector<uint8_t>* out, emp::block block) {
  const auto* bytes = reinterpret_cast<const uint8_t*>(&block);
  out->insert(out->end(), bytes, bytes + sizeof(emp::block));
}

void AppendPartialBlock(std::vector<uint8_t>* out, emp::block block) {
  const auto* bytes = reinterpret_cast<const uint8_t*>(&block);
  out->insert(out->end(), bytes, bytes + kSspBytes);
}

void AndRowMasks(const emp::C2PC<emp::NetIO>& twopc, int gate_index,
                 int and_index, emp::block M[4], emp::block K[4]) {
  const int* gates = twopc.cf->gates.data();
  const int in0 = gates[4 * gate_index];
  const int in1 = gates[4 * gate_index + 1];
  const int out = gates[4 * gate_index + 2];

  M[0] = twopc.sigma_mac[and_index] ^ twopc.mac[out];
  M[1] = M[0] ^ twopc.mac[in0];
  M[2] = M[0] ^ twopc.mac[in1];
  M[3] = M[1] ^ twopc.mac[in1];
  if (twopc.party == emp::BOB) M[3] = M[3] ^ twopc.fpre->one;

  K[0] = twopc.sigma_key[and_index] ^ twopc.key[out];
  K[1] = K[0] ^ twopc.key[in0];
  K[2] = K[0] ^ twopc.key[in1];
  K[3] = K[1] ^ twopc.key[in1];
  if (twopc.party == emp::ALICE) K[3] = K[3] ^ twopc.fpre->ZDelta;
}

std::vector<uint8_t> GarbledTableWire(emp::C2PC<emp::NetIO>& twopc) {
  std::vector<uint8_t> out;
  out.reserve(kGarbledTableBytes);
  int and_index = 0;
  for (int gate_index = 0; gate_index < twopc.cf->num_gate; ++gate_index) {
    if (twopc.cf->gates[4 * gate_index + 3] != 0) continue;
    if (twopc.party == emp::ALICE) {
      emp::block M[4];
      emp::block K[4];
      AndRowMasks(twopc, gate_index, and_index, M, K);
      emp::block H[4][2];
      twopc.Hash(H, twopc.labels[twopc.cf->gates[4 * gate_index]],
                 twopc.labels[twopc.cf->gates[4 * gate_index + 1]],
                 gate_index);
      for (int row = 0; row < 4; ++row) {
        H[row][0] = H[row][0] ^ M[row];
        H[row][1] = H[row][1] ^ K[row] ^
                    twopc.labels[twopc.cf->gates[4 * gate_index + 2]];
        if (emp::getLSB(M[row])) H[row][1] = H[row][1] ^ twopc.fpre->Delta;
        AppendPartialBlock(&out, H[row][0]);
        AppendBlock(&out, H[row][1]);
      }
    } else {
      for (int row = 0; row < 4; ++row) {
        AppendPartialBlock(&out, twopc.GT[and_index][row][0]);
        AppendBlock(&out, twopc.GT[and_index][row][1]);
      }
    }
    ++and_index;
  }
  return out;
}

void SendVerification(emp::NetIO& io, const Verification& verification) {
  io.send_block(&verification.delta, 1);
  io.send_block(verification.key, kNumWire);
  io.send_block(verification.sigma_key, kNumAnds);
  io.send_data(verification.garbled_table->data(),
               static_cast<int>(verification.garbled_table->size()));
  io.flush();
}

void RecvVerification(emp::NetIO& io, emp::block* delta, BlockBuffer* key,
                      BlockBuffer* sigma_key,
                      std::vector<uint8_t>* garbled_table) {
  io.recv_block(delta, 1);
  io.recv_block(key->data(), key->size());
  io.recv_block(sigma_key->data(), sigma_key->size());
  garbled_table->resize(kGarbledTableBytes);
  io.recv_data(garbled_table->data(), static_cast<int>(garbled_table->size()));
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

void VerifyTable(const std::vector<uint8_t>& local,
                 const std::vector<uint8_t>& remote) {
  if (local != remote) {
    throw std::runtime_error("C2PC garbled-table wire mismatch");
  }
}

void ExchangeAndVerify(emp::NetIO& io, int party,
                       const Verification& local,
                       const emp::C2PC<emp::NetIO>& twopc) {
  emp::block remote_delta;
  BlockBuffer remote_key(kNumWire);
  BlockBuffer remote_sigma_key(kNumAnds);
  std::vector<uint8_t> remote_table;
  if (party == emp::ALICE) {
    SendVerification(io, local);
    RecvVerification(io, &remote_delta, &remote_key, &remote_sigma_key,
                     &remote_table);
  } else {
    RecvVerification(io, &remote_delta, &remote_key, &remote_sigma_key,
                     &remote_table);
    SendVerification(io, local);
  }

  VerifyRelation(twopc.mac, kNumWire, remote_delta, remote_key,
                 "C2PC wire");
  VerifyRelation(twopc.sigma_mac, kNumAnds, remote_delta, remote_sigma_key,
                 "C2PC sigma");
  VerifyTable(*local.garbled_table, remote_table);
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
    twopc.function_dependent();

    std::vector<uint8_t> garbled_table = GarbledTableWire(twopc);
    Verification local{
        twopc.fpre->Delta,
        twopc.key,
        twopc.sigma_key,
        &garbled_table,
    };
    ExchangeAndVerify(io, party, local, twopc);
  } catch (const std::exception& e) {
    std::fprintf(stderr, "c2pc_dependent_probe: %s\n", e.what());
    return 1;
  }
  return 0;
}
