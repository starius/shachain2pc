// run/: drive the two emp-ag2pc parties to evaluate one agreed derivation
// circuit under malicious-secure authenticated garbling. This is the only place
// that touches the network and the MPC engine; the relation it evaluates is the
// pure circuit built in protocol/.
//
// PORTED to the rewritten emp-ag2pc (session/backend API). The whole 2PC is one
// `emp::AG2PCSession`: authenticate each party's input, run the circuit, reveal.
// Differences from the previous single-shot `emp::C2PC` driver:
//   * No CheatGuard / std::cout scraping. The new engine's SoftSpoken-COT
//     consistency check runs *before* every reveal and gates output -- a deviating
//     party makes `reveal` abort (emp::error) rather than return a steered value.
//   * The circuit is handed over as a `circuit::BooleanProgram` (the new untyped
//     IR) and run via `sess.run_artifact<RetV>(prog, args...)`.
//   * Preprocessing sizes to num_ands with zero-init storage, so this works
//     correctly for real (bucket-3/4) circuits -- unlike the old single-shot
//     C2PC, which read uninitialized triples for num_ands > permute_batch_size.
//
// Roles are asymmetric: party kAlice (1) is the garbler and listens; party
// kBob (2) is the evaluator and connects. Each party supplies only its own
// 256-bit seed share, on its own input wires:
//   - BOB   owns input wires [0, n1)        (the program's first 256 inputs)
//   - ALICE owns input wires [n1, n1+n2)    (the next 256)
// The circuit recombines them as seed = (wires [0,n1)) XOR (wires [n1,n1+n2)),
// so it does not matter which party's share is which. Both parties learn H(I).
#ifndef SHACHAIN2PC_RUN_DERIVE_H
#define SHACHAIN2PC_RUN_DERIVE_H

#include <openssl/evp.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "emp-ag2pc/emp-ag2pc.h"
#include "emp-tool/ir/program.h"

#include "../protocol/bristol.h"
#include "../protocol/circuit_gen.h"
#include "../protocol/wire_layout.h"

namespace shachain2pc::run {

constexpr int kAlice = emp::ALICE;  // 1, garbler, listens
constexpr int kBob = emp::BOB;      // 2, evaluator, connects
constexpr int kThreads = 4;         // session ThreadPool size (local compute only)
constexpr const char* kDefaultSha256CompressPath =
    ".deps/emp/include/emp-tool/circuits/files/bristol_format/sha-256.txt";

// CheckDerivationCircuit validates the expected 256+256 -> 256 shape.
inline void CheckDerivationCircuit(const protocol::Circuit& c,
                                   const std::string& description) {
  if (c.n1 != protocol::kValueBits || c.n2 != protocol::kValueBits ||
      c.n3 != protocol::kValueBits) {
    throw std::runtime_error(
        "shachain2pc: " + description +
        " has wrong shape: expected 256 256 256, got " + std::to_string(c.n1) +
        " " + std::to_string(c.n2) + " " + std::to_string(c.n3));
  }
}

// BuildCircuitForIndex locally constructs the canonical derivation circuit for
// the authorized index. No per-index circuit file is read or shared between the
// parties; the digest exchange below confirms both sides generated the same
// artifact from their local index and SHA-256 gadget.
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

// ToEmpGateArray flattens a validated circuit into the (in0, in1, out, type)
// layout used by CircuitDigest. emp gate types here: AND=0, XOR=1, NOT=2.
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

// ToBooleanProgram converts the validated derivation circuit into the new emp
// untyped IR, renumbered into RecordContext-canonical (SSA) form: input wires are
// [0, num_inputs), and gate i's output is exactly wire num_inputs + i. The engine
// requires this (backend/canonical.h: dense, single-def, gate.out==num_inputs+i)
// because the slot layout follows record order. Our Bristol circuit is
// topologically ordered and write-once but uses arbitrary wire ids, so we remap.
// (We emit only And/Xor/Not -- constants are built as xor(w,w)/not(...) gates --
// so the "at most one Const0/Const1" rule is trivially met.)
inline emp::circuit::BooleanProgram ToBooleanProgram(const protocol::Circuit& c) {
  const uint32_t num_inputs = static_cast<uint32_t>(c.n1 + c.n2);
  const size_t ng = c.gates.size();

  // old wire id -> canonical wire id. Inputs map to themselves; each gate's
  // output takes its record-order slot. Built fully first so the rewrite below
  // can resolve every (topologically earlier) operand.
  std::vector<uint32_t> remap(static_cast<size_t>(c.num_wire), 0);
  for (uint32_t w = 0; w < num_inputs; ++w) remap[w] = w;
  for (size_t i = 0; i < ng; ++i) {
    remap[static_cast<uint32_t>(c.gates[i].out)] = num_inputs + static_cast<uint32_t>(i);
  }

  emp::circuit::BooleanProgram p;
  p.num_inputs = num_inputs;
  p.num_wires = num_inputs + static_cast<uint32_t>(ng);
  p.gates.reserve(ng);
  for (size_t i = 0; i < ng; ++i) {
    const protocol::Gate& g = c.gates[i];
    emp::circuit::Gate ng2;
    ng2.in0 = remap[static_cast<uint32_t>(g.in0)];
    ng2.in1 = (g.type == protocol::Gate::kInv)
                  ? 0u
                  : remap[static_cast<uint32_t>(g.in1)];
    ng2.out = num_inputs + static_cast<uint32_t>(i);
    ng2.op = (g.type == protocol::Gate::kAnd)   ? emp::circuit::Op::And
             : (g.type == protocol::Gate::kXor) ? emp::circuit::Op::Xor
                                                : emp::circuit::Op::Not;
    p.gates.push_back(ng2);
  }
  p.outputs.reserve(static_cast<size_t>(c.n3));
  for (int i = 0; i < c.n3; ++i) {
    p.outputs.push_back(remap[static_cast<uint32_t>(c.num_wire - c.n3 + i)]);
  }
  return p;
}

template <typename T>
inline void ReleaseVector(std::vector<T>& v) {
  std::vector<T>().swap(v);
}

// CircuitDigest is a SHA-256 over the circuit structure (header + gate array).
inline std::array<uint8_t, 32> CircuitDigest(const protocol::Circuit& c,
                                             const std::vector<int>& gate_arr) {
  int header[5] = {c.num_gate(), c.num_wire, c.n1, c.n2, c.n3};
  std::array<uint8_t, 32> dg{};
  unsigned int len = 0;
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (ctx == nullptr) {
    throw std::runtime_error("CircuitDigest: EVP_MD_CTX_new failed");
  }
  auto cleanup = [&]() { EVP_MD_CTX_free(ctx); };
  if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
      EVP_DigestUpdate(ctx, header, sizeof(header)) != 1) {
    cleanup();
    throw std::runtime_error("CircuitDigest: EVP digest init/update failed");
  }
  if (!gate_arr.empty()) {
    if (EVP_DigestUpdate(ctx, gate_arr.data(),
                         gate_arr.size() * sizeof(int)) != 1) {
      cleanup();
      throw std::runtime_error("CircuitDigest: EVP digest update failed");
    }
  }
  if (EVP_DigestFinal_ex(ctx, dg.data(), &len) != 1 || len != dg.size()) {
    cleanup();
    throw std::runtime_error("CircuitDigest: EVP digest final failed");
  }
  cleanup();
  return dg;
}

// ExchangeCircuitDigest makes both parties commit to the SAME agreed circuit
// before any (expensive) preprocessing: each sends its circuit digest and aborts
// immediately with a clear error on mismatch. The order (garbler sends first) is
// deadlock-free. This is a fast first-line misconfiguration check, NOT the
// security boundary -- authenticated garbling still aborts a party that later
// garbles a different circuit than it committed to.
inline void ExchangeCircuitDigest(emp::NetIO* io, int party,
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

// BatchDigest commits both parties to the SAME index set over the SAME SHA gadget
// before any work. Per-gate circuit integrity is enforced by authenticated
// garbling itself (a party garbling a different circuit desyncs/aborts), so the
// pre-agreement only needs to pin the index set + gadget.
inline std::array<uint8_t, 32> BatchDigest(const std::vector<uint64_t>& indices,
                                           const protocol::Circuit& sha) {
  std::array<uint8_t, 32> sha_dg = CircuitDigest(sha, ToEmpGateArray(sha));
  std::array<uint8_t, 32> dg{};
  unsigned int len = 0;
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (ctx == nullptr) throw std::runtime_error("BatchDigest: EVP_MD_CTX_new failed");
  auto cleanup = [&]() { EVP_MD_CTX_free(ctx); };
  if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
      EVP_DigestUpdate(ctx, indices.data(),
                       indices.size() * sizeof(uint64_t)) != 1 ||
      EVP_DigestUpdate(ctx, sha_dg.data(), sha_dg.size()) != 1 ||
      EVP_DigestFinal_ex(ctx, dg.data(), &len) != 1 || len != dg.size()) {
    cleanup();
    throw std::runtime_error("BatchDigest: EVP digest failed");
  }
  cleanup();
  return dg;
}

// BatchTiming reports where wall time goes: the one-time session setup (COT mesh
// + input authentication, amortized over all indices), and per-index compute
// (garble+evaluate) and reveal (open).
struct BatchTiming {
  double setup_s = 0.0;
  std::vector<double> compute_s;
  std::vector<double> reveal_s;
  double compute_total_s() const {
    double t = 0.0;
    for (double x : compute_s) t += x;
    return t;
  }
  double reveal_total_s() const {
    double t = 0.0;
    for (double x : reveal_s) t += x;
    return t;
  }
};

// RunDerivationBatch evaluates the derivation for every index under ONE session,
// so the expensive one-time setup (SoftSpoken COT mesh + input authentication) is
// paid once and amortized across all indices. Two explicit phases:
//   1. compute -- garble+evaluate each circuit (run_artifact) into an
//      authenticated output share. NOTHING is revealed here: each party holds only
//      its MAC/KEY share; an output value is produced ONLY by the interactive,
//      COT-check-gated reveal below. So neither party can learn any output in this
//      state without the other running reveal() in lockstep -- a single party that
//      calls reveal alone simply blocks on its peer. (This is structural to the
//      protocol, not a check we add.)
//   2. reveal -- open every output to both parties.
// The same authenticated seed shares are reused across all indices (only the
// circuit changes), and reveal does not prune already-materialized outputs, so the
// per-index outputs stay live until opened.
inline std::vector<protocol::Value> RunDerivationBatch(
    emp::NetIO* io, ThreadPool* pool, int party,
    const std::vector<uint64_t>& indices, const protocol::Value& my_share,
    BatchTiming& timing) {
  using Ctx = emp::AG2PCSession::DirectCtx;
  using BV = emp::BitVec_T<Ctx, protocol::kValueBits>;  // 256-bit input/output
  using Clock = std::chrono::steady_clock;
  auto secs = [](Clock::time_point a, Clock::time_point b) {
    return std::chrono::duration<double>(b - a).count();
  };

  if (indices.empty()) throw std::runtime_error("shachain2pc: empty index set");
  for (uint64_t I : indices) {
    if (I > protocol::kMaxIndex)
      throw std::runtime_error("shachain2pc: index exceeds 48 bits");
  }

  protocol::Circuit sha = protocol::LoadBristol(kDefaultSha256CompressPath);

  // Pre-agree on the index set + SHA gadget; clean early abort on mismatch.
  ExchangeCircuitDigest(io, party, BatchDigest(indices, sha));

  // ---- one-time setup: COT mesh (session ctor) + input authentication ----
  auto t0 = Clock::now();
  emp::AG2PCSession sess(io, pool, party);
  io->flush();
  std::array<bool, protocol::kValueBits> bob_clear{};
  std::array<bool, protocol::kValueBits> alice_clear{};
  {
    std::vector<uint8_t> share_bits = protocol::ValueToBits(my_share);
    std::array<bool, protocol::kValueBits>& mine =
        (party == kBob) ? bob_clear : alice_clear;
    for (int i = 0; i < protocol::kValueBits; ++i) mine[i] = share_bits[i] != 0;
  }
  BV bob_in = sess.input<BV>(kBob, bob_clear);
  BV alice_in = sess.input<BV>(kAlice, alice_clear);
  timing.setup_s = secs(t0, Clock::now());

  // ---- phase 1: compute every index (garble+evaluate), NO reveal ----
  std::vector<BV> outs;
  outs.reserve(indices.size());
  timing.compute_s.clear();
  timing.compute_s.reserve(indices.size());
  for (uint64_t I : indices) {
    protocol::Circuit c = protocol::BuildDerivationCircuit(sha, I);
    CheckDerivationCircuit(c, "generated circuit");
    emp::circuit::BooleanProgram prog = ToBooleanProgram(c);
    ReleaseVector(c.gates);
    auto tc = Clock::now();
    outs.push_back(sess.run_artifact<BV>(prog, bob_in, alice_in));
    timing.compute_s.push_back(secs(tc, Clock::now()));
  }

  // ---- phase 2: reveal every output to both parties ----
  std::vector<protocol::Value> results;
  results.reserve(indices.size());
  timing.reveal_s.clear();
  timing.reveal_s.reserve(indices.size());
  for (std::size_t k = 0; k < outs.size(); ++k) {
    auto tr = Clock::now();
    std::optional<std::array<bool, protocol::kValueBits>> rev =
        sess.reveal(outs[k], emp::PUBLIC);
    timing.reveal_s.push_back(secs(tr, Clock::now()));
    if (!rev.has_value())
      throw std::runtime_error("shachain2pc: reveal produced no value");
    std::vector<uint8_t> out_bits(protocol::kValueBits);
    for (int i = 0; i < protocol::kValueBits; ++i) out_bits[i] = (*rev)[i] ? 1 : 0;
    results.push_back(protocol::BitsToValue(out_bits));
  }
  io->flush();
  return results;
}

// RunDerivation: single-index convenience wrapper (used by tests / single runs).
inline protocol::Value RunDerivation(emp::NetIO* io, ThreadPool* pool, int party,
                                     uint64_t index,
                                     const protocol::Value& my_share) {
  BatchTiming timing;
  return RunDerivationBatch(io, pool, party, {index}, my_share, timing)[0];
}

}  // namespace shachain2pc::run

#endif  // SHACHAIN2PC_RUN_DERIVE_H
