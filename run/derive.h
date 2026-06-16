// run/: drive the two emp-ag2pc parties to evaluate one agreed derivation
// circuit under malicious-secure authenticated garbling. This is the only place
// that touches the network and the MPC engine; the relation it evaluates is the
// pure circuit built in protocol/.
//
// Roles are asymmetric: party kAlice (1) is the emp garbler and listens; party
// kBob (2) is the evaluator and connects. Each party supplies only its own
// 256-bit seed share, on the input slice its own online() loop reads:
//   - ALICE writes its share into wires [n1, n1+n2)
//   - BOB   writes its share into wires [0, n1)
// The circuit recombines them as seed = (wires [0,n1)) XOR (wires [n1,n1+n2)),
// so it does not matter which party's share is which; neither party needs the
// other's share. Both parties learn the output H(I) (alice_output = true).
#ifndef SHACHAIN2PC_RUN_DERIVE_H
#define SHACHAIN2PC_RUN_DERIVE_H

#include <emp-tool/emp-tool.h>
#include <openssl/sha.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "emp-ag2pc/emp-ag2pc.h"

#include "../protocol/bristol.h"
#include "../protocol/circuit_gen.h"
#include "../protocol/wire_layout.h"

namespace shachain2pc::run {

constexpr int kAlice = emp::ALICE;  // 1, garbler, listens
constexpr int kBob = emp::BOB;      // 2, evaluator, connects
constexpr const char* kDefaultSha256CompressPath =
    ".deps/emp/include/emp-tool/circuits/files/bristol_format/sha-256.txt";

// CheatGuard enforces the abort half of the malicious-security guarantee. emp's
// authenticated-garbling consistency checks (the per-AND-gate "no match GT!" and
// the output-label MAC checks "no match output label!") are emitted on std::cout
// and the engine then *continues* with a corrupted value. We must instead treat
// any such detection as a hard abort and discard the (untrusted) output. This
// guard redirects std::cout for the duration of the MPC and, if any failure
// marker appears, throws -- so a deviating party can never make us return a
// value it steered. The "no match GT!" check is precisely WRK17 soundness: the
// garbler is information-theoretically MAC-committed to each AND gate, so it
// cannot garble a different function (hence a different index) undetected.
class CheatGuard {
 public:
  CheatGuard() : old_(std::cout.rdbuf(cap_.rdbuf())) {}
  ~CheatGuard() {
    if (!restored_) std::cout.rdbuf(old_);
  }

  // Restore std::cout and abort if emp signalled a consistency failure.
  void Verify() {
    const std::string log = cap_.str();
    std::cout.rdbuf(old_);
    restored_ = true;
    static const char* kMarkers[] = {"no match", "cheat", "CHEAT", "abort"};
    for (const char* m : kMarkers) {
      auto pos = log.find(m);
      if (pos != std::string::npos) {
        // Surface the offending line.
        auto start = log.rfind('\n', pos);
        auto end = log.find('\n', pos);
        std::string line = log.substr(
            start == std::string::npos ? 0 : start + 1,
            (end == std::string::npos ? log.size() : end) -
                (start == std::string::npos ? 0 : start + 1));
        throw std::runtime_error(
            "shachain2pc: MPC aborted, cheating detected (\"" + line + "\")");
      }
    }
  }

 private:
  std::ostringstream cap_;
  std::streambuf* old_;
  bool restored_ = false;
};

// CheckDerivationCircuit validates the expected 256+256 -> 256 shape. Gate
// wire bounds are checked by protocol::LoadBristol for loaded gadgets and by
// the deterministic builder for generated derivation circuits.
inline void CheckDerivationCircuit(const protocol::Circuit& c,
                                   const std::string& description) {
  if (c.n1 != protocol::kValueBits || c.n2 != protocol::kValueBits ||
      c.n3 != protocol::kValueBits) {
    throw std::runtime_error(
        "shachain2pc: " + description +
        " has wrong shape: expected 256 256 "
        "256, got " + std::to_string(c.n1) + " " + std::to_string(c.n2) + " " +
        std::to_string(c.n3));
  }
}

// BuildCircuitForIndex locally constructs the canonical derivation circuit for
// the authorized index. No per-index circuit file is read or shared between the
// parties; the digest exchange below only confirms both sides generated the
// same artifact from their local index and SHA-256 gadget.
inline protocol::Circuit BuildCircuitForIndex(
    uint64_t index,
    const std::string& sha_path = kDefaultSha256CompressPath) {
  if (index > protocol::kMaxIndex) {
    throw std::runtime_error("shachain2pc: index exceeds 48 bits");
  }
  protocol::Circuit sha = protocol::LoadBristol(sha_path);
  protocol::Circuit c = protocol::BuildDerivationCircuit(sha, index);
  CheckDerivationCircuit(c, "generated circuit");
  return c;
}

// ToEmpGateArray flattens a validated circuit into emp's gate array layout
// (in0, in1, out, type) so we can hand emp the in-memory circuit instead of
// re-parsing the file. emp gate types: AND=0, XOR=1, NOT=2.
inline std::vector<int> ToEmpGateArray(const protocol::Circuit& c) {
  std::vector<int> arr(static_cast<size_t>(c.num_gate()) * 4);
  for (int i = 0; i < c.num_gate(); ++i) {
    const protocol::Gate& g = c.gates[i];
    arr[4 * i + 0] = g.in0;
    arr[4 * i + 1] = (g.type == protocol::Gate::kInv) ? 0 : g.in1;
    arr[4 * i + 2] = g.out;
    arr[4 * i + 3] = (g.type == protocol::Gate::kAnd)   ? 0
                     : (g.type == protocol::Gate::kXor) ? 1
                                                        : 2;
  }
  return arr;
}

template <typename T>
inline void ReleaseVector(std::vector<T>& v) {
  std::vector<T>().swap(v);
}

// CircuitDigest is a SHA-256 over the circuit structure (header + gate array).
inline std::array<uint8_t, 32> CircuitDigest(const protocol::Circuit& c,
                                             const std::vector<int>& gate_arr) {
  int header[5] = {c.num_gate(), c.num_wire, c.n1, c.n2, c.n3};
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, header, sizeof(header));
  if (!gate_arr.empty()) {
    SHA256_Update(&ctx, gate_arr.data(), gate_arr.size() * sizeof(int));
  }
  std::array<uint8_t, 32> dg{};
  SHA256_Final(dg.data(), &ctx);
  return dg;
}

// ExchangeCircuitDigest makes both parties commit to the SAME agreed circuit
// before any (expensive) preprocessing: each sends its circuit digest and aborts
// immediately with a clear error on mismatch -- instead of running full
// preprocessing on mismatched circuits and then dying deep inside emp with a
// cryptic network error. The order (garbler sends first) is deadlock-free. This
// is a fast, clear first-line check for misconfiguration; it is NOT the security
// boundary -- authenticated garbling still aborts a party that later garbles a
// different circuit than it committed to.
template <typename IO>
void ExchangeCircuitDigest(IO* io, int party,
                           const std::array<uint8_t, 32>& dg) {
  std::array<uint8_t, 32> peer{};
  if (party == kAlice) {
    io->send_data(dg.data(), dg.size());
    io->flush();
    io->recv_data(peer.data(), peer.size());
  } else {
    io->recv_data(peer.data(), peer.size());
    io->send_data(dg.data(), dg.size());
    io->flush();
  }
  if (std::memcmp(dg.data(), peer.data(), dg.size()) != 0) {
    throw std::runtime_error(
        "shachain2pc: circuit mismatch -- the two parties are not running the "
        "same agreed circuit (same index?)");
  }
}

// RunDerivation builds and evaluates the agreed circuit for index with this
// party's seed share, returning the 256-bit derived value both parties obtain.
// Throws (a clean abort) if the local circuit cannot be generated, if the two
// parties disagree on the generated circuit, or if cheating is detected.
template <typename IO>
protocol::Value RunDerivation(IO* io, int party, uint64_t index,
                              const protocol::Value& my_share) {
  protocol::Circuit c = BuildCircuitForIndex(index);
  std::vector<int> gate_arr = ToEmpGateArray(c);

  // Agree on the locally generated circuit before preprocessing; abort fast and
  // clearly on a mismatch rather than desyncing deep inside the MPC.
  ExchangeCircuitDigest(io, party, CircuitDigest(c, gate_arr));

  // Hand emp the validated in-memory circuit (no unchecked file re-parse).
  emp::BristolFormat cf(c.num_gate(), c.num_wire, c.n1, c.n2, c.n3,
                        gate_arr.data());
  ReleaseVector(c.gates);
  ReleaseVector(gate_arr);
  ReleaseVector(cf.wires);  // emp-ag2pc uses cf.gates, not BristolFormat::wires.

  const int nin = cf.n1 + cf.n2;
  const std::vector<uint8_t> share_bits = protocol::ValueToBits(my_share);
  // emp reads a plain bool buffer; place this party's share on its own slice.
  std::vector<char> in_buf(nin, 0);
  std::vector<char> out_buf(cf.n3, 0);
  if (party == kAlice) {
    for (int i = 0; i < protocol::kValueBits; ++i) in_buf[cf.n1 + i] = share_bits[i];
  } else {
    for (int i = 0; i < protocol::kValueBits; ++i) in_buf[i] = share_bits[i];
  }

  CheatGuard guard;  // capture emp's consistency-check output; abort on cheat
  emp::C2PC<IO> twopc(io, party, &cf);
  io->flush();
  twopc.function_independent();
  io->flush();
  twopc.function_dependent();
  io->flush();
  twopc.online(reinterpret_cast<bool*>(in_buf.data()),
               reinterpret_cast<bool*>(out_buf.data()), /*alice_output=*/true);
  io->flush();
  guard.Verify();  // throws std::runtime_error if cheating was detected

  std::vector<uint8_t> out_bits(cf.n3);
  for (int i = 0; i < cf.n3; ++i) out_bits[i] = out_buf[i] ? 1 : 0;
  return protocol::BitsToValue(out_bits);
}

}  // namespace shachain2pc::run

#endif  // SHACHAIN2PC_RUN_DERIVE_H
