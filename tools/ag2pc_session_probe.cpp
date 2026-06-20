// Compatibility probe for the current emp::AG2PCSession backend.
//
// This probes the rewritten C++ backend used by demo/party.cpp, not the old
// emp::C2PC/Fpre stack. It is intentionally live and randomized: the target is
// wire-compatible interop and semantic invariants, not byte-identical production
// transcripts under real randomness.
#include <emp-ag2pc/emp-ag2pc.h>
#include <emp-tool/emp-tool.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

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

uint64_t SumSent(emp::NetIO* a, emp::NetIO* b) {
  return a->send_counter + b->send_counter;
}

uint64_t SumRecv(emp::NetIO* a, emp::NetIO* b) {
  return a->recv_counter + b->recv_counter;
}

uint64_t SumRounds(emp::NetIO* a, emp::NetIO* b) {
  return a->rounds + b->rounds;
}

uint64_t SumFlushes(emp::NetIO* a, emp::NetIO* b) {
  return a->flushes_count + b->flushes_count;
}

struct Snapshot {
  uint64_t sent = 0;
  uint64_t recv = 0;
  uint64_t rounds = 0;
  uint64_t flushes = 0;
};

struct Probe {
  int party;
  emp::AG2PCSession& sess;
  emp::NetIO* main;
  emp::NetIO* sib;
  Snapshot prev;
  int seq = 0;

  Probe(int party_, emp::AG2PCSession& sess_, emp::NetIO* main_)
      : party(party_), sess(sess_), main(main_), sib(sess.protocol().sib) {
    prev = Current();
  }

  Snapshot Current() const {
    return Snapshot{
        SumSent(main, sib),
        SumRecv(main, sib),
        SumRounds(main, sib),
        SumFlushes(main, sib),
    };
  }

  void Emit(const std::string& name, const std::string& fields) {
    Snapshot now = Current();
    std::printf(
        "{\"schema\":\"shachain2pc.ag2pc_probe.v1\","
        "\"probe\":\"ag2pc_session\","
        "\"seq\":%d,"
        "\"case\":\"%s\","
        "\"party\":%d,"
        "\"process_input_calls\":%d,"
        "\"num_and\":%llu,"
        "\"delta_sent\":%llu,"
        "\"delta_recv\":%llu,"
        "\"delta_rounds\":%llu,"
        "\"delta_flushes\":%llu,"
        "\"total_sent\":%llu,"
        "\"total_recv\":%llu,"
        "\"total_rounds\":%llu,"
        "\"total_flushes\":%llu,"
        "\"main_digest\":\"%s\","
        "\"sibling_digest\":\"%s\"%s}\n",
        seq++, name.c_str(), party, sess.process_input_calls(),
        static_cast<unsigned long long>(sess.num_and()),
        static_cast<unsigned long long>(now.sent - prev.sent),
        static_cast<unsigned long long>(now.recv - prev.recv),
        static_cast<unsigned long long>(now.rounds - prev.rounds),
        static_cast<unsigned long long>(now.flushes - prev.flushes),
        static_cast<unsigned long long>(now.sent),
        static_cast<unsigned long long>(now.recv),
        static_cast<unsigned long long>(now.rounds),
        static_cast<unsigned long long>(now.flushes),
        HexBlock(main->get_digest()).c_str(),
        HexBlock(sib->get_digest()).c_str(), fields.c_str());
    std::fflush(stdout);
    prev = now;
  }
};

std::string BoolField(const char* name, bool value) {
  return std::string(",\"") + name + "\":" + (value ? "true" : "false");
}

std::string OptionalBoolField(const char* name,
                              const std::optional<bool>& value) {
  if (!value.has_value()) return std::string(",\"") + name + "\":null";
  return BoolField(name, *value);
}

template <class V>
std::optional<bool> RevealBit(emp::AG2PCSession& sess, const V& bit,
                              int recipient) {
  std::optional<bool> out = sess.reveal(bit, recipient);
  return out;
}

}  // namespace

int main(int argc, char** argv) {
  try {
    if (argc < 3 || argc > 4) {
      std::fprintf(stderr,
                   "usage: %s <1|2> <port> [peer_ip]\n"
                   "  1 = ALICE/listener, 2 = BOB/connector\n",
                   argv[0]);
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
    ThreadPool pool(4);
    emp::AG2PCSession sess(&io, &pool, party, kSsp);
    SetTransportTimeout(sess.protocol().sib);
    io.flush();

    using Ctx = emp::AG2PCSession::DirectCtx;
    using Bit = emp::Bit_T<Ctx>;
    Probe probe(party, sess, &io);
    probe.Emit("session_setup", "");

    auto batch = sess.input_batch();
    Bit alice = batch.add<Bit>(emp::ALICE, party == emp::ALICE);
    Bit bob = batch.add<Bit>(emp::BOB, party == emp::BOB);
    batch.finish();
    probe.Emit("input_batch_two_bits", "");

    Bit public_true = Bit::constant(sess.direct_ctx(), true);
    std::optional<bool> public_reveal =
        RevealBit(sess, public_true, emp::PUBLIC);
    probe.Emit("public_true_reveal",
               OptionalBoolField("result", public_reveal));

    Bit xr = alice ^ bob;
    std::optional<bool> xor_reveal = RevealBit(sess, xr, emp::PUBLIC);
    probe.Emit("xor_reveal", OptionalBoolField("result", xor_reveal));

    Bit ar = alice & bob;
    std::optional<bool> and_reveal = RevealBit(sess, ar, emp::PUBLIC);
    probe.Emit("and_reveal", OptionalBoolField("result", and_reveal));

    Bit carry = alice ^ bob;
    sess.checkpoint(carry, alice, bob);
    probe.Emit("checkpoint_keep_carry_inputs", "");

    Bit carried_and = carry & bob;
    std::optional<bool> carried_reveal =
        RevealBit(sess, carried_and, emp::PUBLIC);
    probe.Emit("carried_and_reveal",
               OptionalBoolField("result", carried_reveal));

    Bit alice_true = Bit::constant(sess.direct_ctx(), true);
    Bit to_alice = alice ^ alice_true;
    std::optional<bool> alice_only = RevealBit(sess, to_alice, emp::ALICE);
    probe.Emit("reveal_to_alice", OptionalBoolField("result", alice_only));

    Bit bob_true = Bit::constant(sess.direct_ctx(), true);
    Bit to_bob = bob ^ bob_true;
    std::optional<bool> bob_only = RevealBit(sess, to_bob, emp::BOB);
    probe.Emit("reveal_to_bob", OptionalBoolField("result", bob_only));

    io.flush();
    return 0;
  } catch (const std::exception& e) {
    std::fprintf(stderr, "ABORT %s\n", e.what());
    return 1;
  }
}
