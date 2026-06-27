// Live C++ probe for AG2PC TriplePool::compute_inplace.
#include <emp-tool/emp-tool.h>
#include <emp-tool/runtime/runtime.h>
#include <emp-ag2pc/backend/triple_pool.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

constexpr int kLength = 35;
constexpr int kSsp = 40;

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

uint8_t Lsb(emp::block b) {
  alignas(16) std::array<uint8_t, 16> bytes{};
  _mm_storeu_si128(reinterpret_cast<__m128i*>(bytes.data()), b);
  return bytes[0] & 1;
}

bool EqBlock(emp::block a, emp::block b) {
  return emp::cmpBlock(&a, &b, 1);
}

bool VerifyShareRelation(const emp::AShareBundleVec& mine,
                         emp::block my_delta,
                         const emp::AShareBundleVec& peer,
                         emp::block peer_delta) {
  if (mine.size() != peer.size()) return false;
  for (size_t i = 0; i < mine.size(); ++i) {
    emp::block mine_expected =
        peer[i].key ^ (emp::select_mask[Lsb(mine[i].mac)] & peer_delta);
    emp::block peer_expected =
        mine[i].key ^ (emp::select_mask[Lsb(peer[i].mac)] & my_delta);
    if (!EqBlock(mine[i].mac, mine_expected)) return false;
    if (!EqBlock(peer[i].mac, peer_expected)) return false;
  }
  return true;
}

bool VerifyAndRelation(const emp::AShareBundleVec& mine_a,
                       const emp::AShareBundleVec& mine_b,
                       const emp::AShareBundleVec& mine_sigma,
                       const emp::AShareBundleVec& peer_a,
                       const emp::AShareBundleVec& peer_b,
                       const emp::AShareBundleVec& peer_sigma) {
  for (int i = 0; i < kLength; ++i) {
    uint8_t a = Lsb(mine_a[i].mac) ^ Lsb(peer_a[i].mac);
    uint8_t b = Lsb(mine_b[i].mac) ^ Lsb(peer_b[i].mac);
    uint8_t sigma = Lsb(mine_sigma[i].mac) ^ Lsb(peer_sigma[i].mac);
    if (sigma != (a & b)) return false;
  }
  return true;
}

void SendBundle(emp::NetIO& io, const emp::AShareBundleVec& bundle) {
  emp::BlockVec mac(bundle.size()), key(bundle.size());
  for (size_t i = 0; i < bundle.size(); ++i) {
    mac[i] = bundle[i].mac;
    key[i] = bundle[i].key;
  }
  io.send_block(mac.data(), mac.size());
  io.send_block(key.data(), key.size());
}

emp::AShareBundleVec RecvBundle(emp::NetIO& io) {
  emp::BlockVec mac(kLength), key(kLength);
  io.recv_block(mac.data(), mac.size());
  io.recv_block(key.data(), key.size());
  emp::AShareBundleVec out(kLength);
  for (int i = 0; i < kLength; ++i) {
    out[i].mac = mac[i];
    out[i].key = key[i];
  }
  return out;
}

void SendAll(emp::NetIO& io, emp::block delta,
             const emp::AShareBundleVec& a,
             const emp::AShareBundleVec& b,
             const emp::AShareBundleVec& sigma) {
  io.send_block(&delta, 1);
  SendBundle(io, a);
  SendBundle(io, b);
  SendBundle(io, sigma);
  io.flush();
}

void RecvAll(emp::NetIO& io, emp::block& delta,
             emp::AShareBundleVec& a,
             emp::AShareBundleVec& b,
             emp::AShareBundleVec& sigma) {
  io.recv_block(&delta, 1);
  a = RecvBundle(io);
  b = RecvBundle(io);
  sigma = RecvBundle(io);
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

    emp::NetIO main(addr, port, /*quiet=*/true);
    SetTransportTimeout(&main);
    std::unique_ptr<emp::NetIO> sibling(main.make_sibling());
    SetTransportTimeout(sibling.get());
    ThreadPool thread_pool(4);
    TriplePool triples(&main, sibling.get(), &thread_pool, party, kSsp);

    emp::AShareBundleVec rep_a, rep_b, sigma;
    triples.draw(kLength, rep_a);
    triples.draw(kLength, rep_b);
    triples.compute_inplace(rep_a, rep_b, kLength, sigma);
    triples.flush_cot_check();

    emp::block peer_delta;
    emp::AShareBundleVec peer_a, peer_b, peer_sigma;
    if (party == emp::ALICE) {
      SendAll(main, triples.Delta, rep_a, rep_b, sigma);
      RecvAll(main, peer_delta, peer_a, peer_b, peer_sigma);
    } else {
      RecvAll(main, peer_delta, peer_a, peer_b, peer_sigma);
      SendAll(main, triples.Delta, rep_a, rep_b, sigma);
    }
    bool ok = VerifyShareRelation(sigma, triples.Delta, peer_sigma, peer_delta) &&
              VerifyAndRelation(rep_a, rep_b, sigma, peer_a, peer_b, peer_sigma);
    std::printf(
        "{\"schema\":\"shachain2pc.ag2pc_compute_probe.v1\","
        "\"party\":%d,\"length\":%d,\"verified\":%s}\n",
        party, kLength, ok ? "true" : "false");
    return ok ? 0 : 1;
  } catch (const std::exception& e) {
    std::fprintf(stderr, "ABORT %s\n", e.what());
    return 1;
  }
}
