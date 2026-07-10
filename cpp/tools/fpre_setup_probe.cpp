#include <emp-tool/emp-tool.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>

#include "emp-ag2pc/fpre.h"

namespace {

constexpr int kRequestedSize = 321;
constexpr uint32_t kExpectedBatchSize = 322;
constexpr uint32_t kExpectedBucketSize = 5;
constexpr uint32_t kExpectedPermuteBatchSize = 0;

enum class Transport { kListen, kConnect };

struct Verification {
  emp::block delta;
  uint32_t batch_size;
  uint32_t bucket_size;
  uint32_t permute_batch_size;
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

bool SecondLsb(emp::block block) {
  const auto* bytes = reinterpret_cast<const uint8_t*>(&block);
  return ((bytes[0] >> 1) & 1) == 1;
}

void CheckDeltaBits(emp::block delta, int party) {
  if (!emp::getLSB(delta)) {
    throw std::runtime_error("Fpre Delta LSB is not set");
  }
  const bool expected_second_lsb = party == emp::ALICE;
  if (SecondLsb(delta) != expected_second_lsb) {
    throw std::runtime_error("Fpre Delta second LSB does not match party");
  }
}

void CheckParams(uint32_t batch_size, uint32_t bucket_size,
                 uint32_t permute_batch_size) {
  if (batch_size != kExpectedBatchSize ||
      bucket_size != kExpectedBucketSize ||
      permute_batch_size != kExpectedPermuteBatchSize) {
    throw std::runtime_error("Fpre parameter mismatch");
  }
}

Verification LocalVerification(const emp::Fpre<emp::NetIO>& fpre) {
  return Verification{
      fpre.Delta,
      static_cast<uint32_t>(fpre.batch_size),
      static_cast<uint32_t>(fpre.bucket_size),
      fpre.bucket_size > 4 ? 0U : static_cast<uint32_t>(fpre.permute_batch_size),
  };
}

void SendVerification(emp::NetIO& io, const Verification& verification) {
  io.send_block(&verification.delta, 1);
  io.send_data(&verification.batch_size, sizeof(verification.batch_size));
  io.send_data(&verification.bucket_size, sizeof(verification.bucket_size));
  io.send_data(&verification.permute_batch_size,
               sizeof(verification.permute_batch_size));
  io.flush();
}

Verification RecvVerification(emp::NetIO& io) {
  Verification verification;
  io.recv_block(&verification.delta, 1);
  io.recv_data(&verification.batch_size, sizeof(verification.batch_size));
  io.recv_data(&verification.bucket_size, sizeof(verification.bucket_size));
  io.recv_data(&verification.permute_batch_size,
               sizeof(verification.permute_batch_size));
  return verification;
}

void ExchangeAndVerify(emp::NetIO& io, int party, const Verification& local) {
  Verification remote;
  if (party == emp::ALICE) {
    SendVerification(io, local);
    remote = RecvVerification(io);
  } else {
    remote = RecvVerification(io);
    SendVerification(io, local);
  }
  CheckDeltaBits(remote.delta, party == emp::ALICE ? emp::BOB : emp::ALICE);
  CheckParams(remote.batch_size, remote.bucket_size, remote.permute_batch_size);
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
    Verification local = LocalVerification(fpre);
    CheckDeltaBits(local.delta, party);
    CheckParams(local.batch_size, local.bucket_size,
                local.permute_batch_size);
    ExchangeAndVerify(io, party, local);
  } catch (const std::exception& e) {
    std::fprintf(stderr, "fpre_setup_probe: %s\n", e.what());
    return 1;
  }
  return 0;
}
