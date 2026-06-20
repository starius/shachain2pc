// Live C++ probe for the current emp::TriplePool authenticated-share draw.
#include <emp-tool/emp-tool.h>
#include <emp-tool/runtime/runtime.h>
#include <emp-ag2pc/backend/triple_pool.h>
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
#include <vector>

namespace {

constexpr int kLength = 257;
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

bool EqBlock(emp::block a, emp::block b) {
  return emp::cmpBlock(&a, &b, 1);
}

bool VerifyRelation(const emp::AShareBundleVec& mine,
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

void SendBlocks(emp::NetIO& io, const emp::BlockVec& blocks) {
  if (!blocks.empty()) io.send_block(blocks.data(), blocks.size());
}

void RecvBlocks(emp::NetIO& io, emp::BlockVec& blocks) {
  if (!blocks.empty()) io.recv_block(blocks.data(), blocks.size());
}

void SendBundle(emp::NetIO& io, emp::block delta,
                const emp::AShareBundleVec& bundle) {
  emp::BlockVec mac(bundle.size()), key(bundle.size());
  for (size_t i = 0; i < bundle.size(); ++i) {
    mac[i] = bundle[i].mac;
    key[i] = bundle[i].key;
  }
  io.send_block(&delta, 1);
  SendBlocks(io, mac);
  SendBlocks(io, key);
  io.flush();
}

emp::AShareBundleVec RecvBundle(emp::NetIO& io, emp::block& delta) {
  io.recv_block(&delta, 1);
  emp::BlockVec mac(kLength), key(kLength);
  RecvBlocks(io, mac);
  RecvBlocks(io, key);
  emp::AShareBundleVec out(kLength);
  for (int i = 0; i < kLength; ++i) {
    out[i].mac = mac[i];
    out[i].key = key[i];
  }
  return out;
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

    emp::AShareBundleVec local;
    triples.draw(kLength, local);
    triples.flush_cot_check();

    emp::block peer_delta;
    emp::AShareBundleVec peer_bundle;
    if (party == emp::ALICE) {
      SendBundle(main, triples.Delta, local);
      peer_bundle = RecvBundle(main, peer_delta);
    } else {
      peer_bundle = RecvBundle(main, peer_delta);
      SendBundle(main, triples.Delta, local);
    }
    bool ok = VerifyRelation(local, triples.Delta, peer_bundle, peer_delta);
    std::printf(
        "{\"schema\":\"shachain2pc.ag2pc_triple_pool_probe.v1\","
        "\"party\":%d,\"length\":%d,\"verified\":%s,"
        "\"delta\":\"%s\",\"main_digest\":\"%s\","
        "\"sibling_digest\":\"%s\"}\n",
        party, kLength, ok ? "true" : "false",
        HexBlock(triples.Delta).c_str(), HexBlock(main.get_digest()).c_str(),
        HexBlock(sibling->get_digest()).c_str());
    return ok ? 0 : 1;
  } catch (const std::exception& e) {
    std::fprintf(stderr, "ABORT %s\n", e.what());
    return 1;
  }
}
