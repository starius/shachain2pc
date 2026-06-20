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
#include <unordered_map>
#include <utility>
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
constexpr int kDefaultCacheTrunkChunkBlocks = 16;
constexpr int kDefaultCacheTileFanout = 16;  // recursive branch tile arity (2^4)
constexpr int kCacheTileHeight = 4;
constexpr int kCacheTileLeaves = 1 << kCacheTileHeight;
constexpr int kCacheTileBits = protocol::kValueBits * kCacheTileLeaves;

// Statistical security parameter for the authenticated-AND bucketing (emp's
// AG2PCSession `ssp`). 40 is emp's default, kept here for DEMO/RESEARCH
// performance. For PRODUCTION funds use ~60-64 (see below) -- 2^-20 per channel is
// not a production-grade target for theft-adjacent revocation material.
//
// CONSEQUENCE / OPERATING LIMIT. The bucketing soundness+leakage error is
// < 2^-kSsp PER compute_inplace, accumulating as N * 2^-kSsp against ONE seed,
// where N = the TOTAL compute_inplace bucketing instances run on that seed
// (every revealed branch, precomputed-but-unrevealed output, ABORTED attempt,
// trunk-refill chunk, and branch tile/chunk -- not just revealed secrets), bounded
// by computations performed, never the 2^48 index space. At kSsp = 40:
//     ~2^20 instances -> residual <= 2^-20  (~1 in a million)
//     ~2^10 instances -> residual <= 2^-30  (~1 in a billion)
// The residual is the prob of a single, undetected, ~1-bit leak (a real attempt
// aborts w.p. ~1-2^-kSsp; theft needs far more than one bit) -- adequate for
// demo/research, but 2^-20 is too thin for production funds.
//
// PRODUCTION: use kSsp ~60-64 (2^-40 residual over ~2^20-2^24 instances); count every
// compute_inplace against the seed, track the per-seed budget, and rotate the seed
// before crossing the chosen risk threshold.
//
// EXPANDING THE LIMIT:
//   1. Rotate the seed (fresh channel) -- budget is PER SEED, resets for free.
//   2. Raise kSsp. Cost ~linear: bucket B ~ kSsp/log2(L), so triple-gen compute
//      (~3B-2 COTs/AND), bandwidth, and round-trips/latency scale with it (memory
//      unaffected). kSsp = 64 buys ~2^24 instances at 2^-40 for ~1.3-1.6x. BOTH
//      parties MUST match -- a coordinated change, not a per-run flag.
// Full analysis: docs/shared-trunk-cache.md.
constexpr int kSsp = 40;

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
  emp::AG2PCSession sess(io, pool, party, kSsp);
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

// ---------------------------------------------------------------------------
// Block-chunking: evaluate ONE derivation as a sequence of smaller circuits to
// bound the per-circuit preprocessing peak. The chain's intermediate value is
// carried between chunks as an AUTHENTICATED wire (run_artifact reuses the
// carried AShareBundle directly -- it is never revealed and never re-input), and
// every per-link flip is an in-circuit public constant. So a malicious party
// cannot flip a bit of the carried value or substitute a different chain without
// breaking a MAC -- caught by the per-chunk COT consistency check and the final
// reveal. This is the malicious-secure equivalent of the one big circuit (it is
// exactly the steering attack the semi-honest re-input design suffers from).
struct ChunkTiming {
  double setup_s = 0.0;
  std::vector<double> chunk_s;  // per-chunk compute (garble+evaluate)
  double reveal_s = 0.0;
  int blocks_per_chunk = 0;
  int num_chunks = 0;
  uint64_t rounds = 0;       // NetIO direction-changes on the primary channel
  uint64_t bytes_sent = 0;
  uint64_t bytes_recv = 0;
  double chunk_total_s() const {
    double t = 0.0;
    for (double x : chunk_s) t += x;
    return t;
  }
};

// CheckChunkCircuit validates a chunk's shape: 256-bit output, and either a
// 256-bit carried input (later chunks) or a 512-bit two-share input (chunk 0).
inline void CheckChunkCircuit(const protocol::Circuit& c) {
  const int ni = c.n1 + c.n2;
  if ((ni != protocol::kValueBits && ni != 2 * protocol::kValueBits) ||
      c.n3 != protocol::kValueBits) {
    throw std::runtime_error("shachain2pc: chunk circuit has wrong shape");
  }
}

inline void CheckTileCircuit(const protocol::Circuit& c) {
  if (c.n1 != protocol::kValueBits || c.n2 != 0 ||
      c.n3 != kCacheTileBits) {
    throw std::runtime_error("shachain2pc: tile circuit has wrong shape");
  }
}

// ChunkSpecDigest pins index + chunk size + SHA gadget so both parties agree on
// the chunking before any work (a size mismatch would otherwise desync mid-run).
inline std::array<uint8_t, 32> ChunkSpecDigest(uint64_t index,
                                               int blocks_per_chunk,
                                               const protocol::Circuit& sha) {
  std::array<uint8_t, 32> sha_dg = CircuitDigest(sha, ToEmpGateArray(sha));
  std::array<uint8_t, 32> dg{};
  unsigned int len = 0;
  int bpc = blocks_per_chunk;
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (ctx == nullptr) throw std::runtime_error("ChunkSpecDigest: EVP_MD_CTX_new failed");
  auto cleanup = [&]() { EVP_MD_CTX_free(ctx); };
  if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
      EVP_DigestUpdate(ctx, &index, sizeof(index)) != 1 ||
      EVP_DigestUpdate(ctx, &bpc, sizeof(bpc)) != 1 ||
      EVP_DigestUpdate(ctx, sha_dg.data(), sha_dg.size()) != 1 ||
      EVP_DigestFinal_ex(ctx, dg.data(), &len) != 1 || len != dg.size()) {
    cleanup();
    throw std::runtime_error("ChunkSpecDigest: EVP digest failed");
  }
  cleanup();
  return dg;
}

// TamperFirstFlip (TEST ONLY) redirects a chunk's first bit-flip (Inv) gate to
// read input wire 0 instead of its intended wire -- a malicious party trying to
// steer the chain to a different I' WITHOUT changing the circuit shape (so it is
// not caught by the digest handshake; only authenticated garbling can catch it).
// gate 0 is the c0 constant (XorW(0,0)); c1 = Inv(c0); the real flips are Inv
// gates whose input is not the c0 wire. Used only by the abort/safety test.
inline void TamperFirstFlip(protocol::Circuit& c) {
  const int c0_wire = c.gates.empty() ? -1 : c.gates[0].out;
  for (protocol::Gate& g : c.gates) {
    if (g.type == protocol::Gate::kInv && g.in0 != c0_wire) {
      g.in0 = 0;  // read input wire 0 -> wrong function (steered chain)
      return;
    }
  }
}

// tamper_chunk >= 0 (TEST ONLY): this party garbles a steered flip in that chunk
// (see TamperFirstFlip). With one honest party, authenticated garbling must abort
// rather than reveal the steered value. -1 disables it (the normal path).
inline protocol::Value RunDerivationChunked(emp::NetIO* io, ThreadPool* pool,
                                            int party, uint64_t index,
                                            const protocol::Value& my_share,
                                            int blocks_per_chunk,
                                            ChunkTiming& timing,
                                            int tamper_chunk = -1) {
  using Ctx = emp::AG2PCSession::DirectCtx;
  using BV = emp::BitVec_T<Ctx, protocol::kValueBits>;
  using Clock = std::chrono::steady_clock;
  auto secs = [](Clock::time_point a, Clock::time_point b) {
    return std::chrono::duration<double>(b - a).count();
  };

  if (index > protocol::kMaxIndex)
    throw std::runtime_error("shachain2pc: index exceeds 48 bits");
  if (blocks_per_chunk < 1)
    throw std::runtime_error("shachain2pc: blocks_per_chunk must be >= 1");

  protocol::Circuit sha = protocol::LoadBristol(kDefaultSha256CompressPath);
  std::vector<std::vector<int>> groups =
      protocol::SplitChainBits(index, blocks_per_chunk);
  ExchangeCircuitDigest(io, party, ChunkSpecDigest(index, blocks_per_chunk, sha));

  // ---- one-time setup: COT mesh + input authentication ----
  auto t0 = Clock::now();
  emp::AG2PCSession sess(io, pool, party, kSsp);
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
  timing.blocks_per_chunk = blocks_per_chunk;
  timing.num_chunks = static_cast<int>(groups.size());
  timing.chunk_s.reserve(groups.size());

  // ---- chunk 0: recombine the seed shares, apply the first group of flips ----
  protocol::Circuit c0 = protocol::BuildChunkCircuit(sha, groups[0], true);
  if (tamper_chunk == 0) TamperFirstFlip(c0);  // TEST ONLY
  CheckChunkCircuit(c0);
  emp::circuit::BooleanProgram prog0 = ToBooleanProgram(c0);
  ReleaseVector(c0.gates);
  auto tc0 = Clock::now();
  BV cur = sess.run_artifact<BV>(prog0, bob_in, alice_in);
  timing.chunk_s.push_back(secs(tc0, Clock::now()));
  sess.checkpoint(cur);  // free the seed-share inputs; keep only the carried value

  // ---- chunks 1..: carry the authenticated value directly into the next ----
  for (std::size_t k = 1; k < groups.size(); ++k) {
    protocol::Circuit c = protocol::BuildChunkCircuit(sha, groups[k], false);
    if (static_cast<int>(k) == tamper_chunk) TamperFirstFlip(c);  // TEST ONLY
    CheckChunkCircuit(c);
    emp::circuit::BooleanProgram prog = ToBooleanProgram(c);
    ReleaseVector(c.gates);
    auto tc = Clock::now();
    cur = sess.run_artifact<BV>(prog, cur);
    timing.chunk_s.push_back(secs(tc, Clock::now()));
    sess.checkpoint(cur);  // free the previous chunk's intermediate
  }

  // ---- reveal the final value ----
  auto tr = Clock::now();
  std::optional<std::array<bool, protocol::kValueBits>> rev =
      sess.reveal(cur, emp::PUBLIC);
  timing.reveal_s = secs(tr, Clock::now());
  io->flush();
  timing.rounds = io->rounds;
  timing.bytes_sent = io->send_counter;
  timing.bytes_recv = io->recv_counter;
  if (!rev.has_value())
    throw std::runtime_error("shachain2pc: reveal produced no value");
  std::vector<uint8_t> out_bits(protocol::kValueBits);
  for (int i = 0; i < protocol::kValueBits; ++i) out_bits[i] = (*rev)[i] ? 1 : 0;
  return protocol::BitsToValue(out_bits);
}

// ---------------------------------------------------------------------------
// Shared-trunk derivation. shachain processes set bits high->low, so indices that
// share a high-bit prefix share that whole sub-chain. We compute the shared prefix
// ("trunk") ONCE into an authenticated value T, then derive each index's remaining
// low-bit "branch" from T. Branches are all computed first (NOT revealed), then
// revealed one-by-one. Throughput: the trunk is shared instead of recomputed per
// index. Memory: trunk (optionally chunked) + one branch at a time + the carried
// 256-bit outputs (tiny). Security is the same as the single circuit: T is carried
// as an authenticated wire (reused, never re-input) and branch flips are
// in-circuit constants, so a tampered branch aborts.
//
// Reveal scope: at the MPC level, reveal(out_k) opens only that branch's wires;
// the other branches keep their independent secret masks, so the protocol leaks
// no UN-revealed output. BUT shachain itself is a tree -- H(I) lets ANYONE derive
// H(I') for every descendant I' of I (I' = I with some of I's trailing-zero bits
// set). That derivation happens outside the MPC and is inherent to shachain, not
// an MPC leak. So this routine is safe for "derive all requested outputs now"
// (it reveals the whole set anyway). It is NOT automatically safe for "precompute
// a range, reveal only one later": the caller must ensure the still-secret set
// contains no descendant of an already-revealed index (e.g. reveal in increasing
// trailing-zero / ancestor-last order, or exclude ancestors), or accept that
// shachain-derivable descendants become known. The I=0 seed is the extreme case
// (it derives the whole tree) and is gated separately in the party CLI.

// SetBitsDesc returns the set bit positions of x (0..47), high to low.
inline std::vector<int> SetBitsDesc(uint64_t x) {
  std::vector<int> bits;
  for (int b = protocol::kIndexBits - 1; b >= 0; --b)
    if ((x >> b) & 1) bits.push_back(b);
  return bits;
}

struct TreeTiming {
  double setup_s = 0.0;
  double trunk_s = 0.0;
  int trunk_chunks = 0;
  int trunk_blocks = 0;
  int split_bit = -1;
  std::vector<double> branch_s;  // per-index branch compute
  std::vector<double> reveal_s;  // per-index reveal
  uint64_t rounds = 0, bytes_sent = 0, bytes_recv = 0;
  double branch_total_s() const {
    double t = 0.0; for (double x : branch_s) t += x; return t;
  }
  double reveal_total_s() const {
    double t = 0.0; for (double x : reveal_s) t += x; return t;
  }
};

inline std::array<uint8_t, 32> TreeDigest(const std::vector<uint64_t>& indices,
                                          int trunk_chunk_blocks,
                                          const protocol::Circuit& sha) {
  std::array<uint8_t, 32> sha_dg = CircuitDigest(sha, ToEmpGateArray(sha));
  std::array<uint8_t, 32> dg{};
  unsigned int len = 0;
  int tcb = trunk_chunk_blocks;
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (ctx == nullptr) throw std::runtime_error("TreeDigest: EVP_MD_CTX_new failed");
  auto cleanup = [&]() { EVP_MD_CTX_free(ctx); };
  if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
      EVP_DigestUpdate(ctx, indices.data(),
                       indices.size() * sizeof(uint64_t)) != 1 ||
      EVP_DigestUpdate(ctx, &tcb, sizeof(tcb)) != 1 ||
      EVP_DigestUpdate(ctx, sha_dg.data(), sha_dg.size()) != 1 ||
      EVP_DigestFinal_ex(ctx, dg.data(), &len) != 1 || len != dg.size()) {
    cleanup();
    throw std::runtime_error("TreeDigest: EVP digest failed");
  }
  cleanup();
  return dg;
}

// tamper_branch >= 0 (TEST ONLY): garble a steered flip in that branch to confirm
// authenticated garbling aborts even with the shared/reused trunk. -1 = normal.
inline std::vector<protocol::Value> RunDerivationTree(
    emp::NetIO* io, ThreadPool* pool, int party,
    const std::vector<uint64_t>& indices, const protocol::Value& my_share,
    int trunk_chunk_blocks, TreeTiming& timing, int tamper_branch = -1) {
  using Ctx = emp::AG2PCSession::DirectCtx;
  using BV = emp::BitVec_T<Ctx, protocol::kValueBits>;
  using Clock = std::chrono::steady_clock;
  auto secs = [](Clock::time_point a, Clock::time_point b) {
    return std::chrono::duration<double>(b - a).count();
  };

  if (indices.empty()) throw std::runtime_error("shachain2pc: empty index set");
  for (uint64_t I : indices)
    if (I > protocol::kMaxIndex)
      throw std::runtime_error("shachain2pc: index exceeds 48 bits");

  // Common high-bit prefix: split = highest bit where the indices differ; bits
  // above split are shared by all (the trunk), bits <= split are per-index (the
  // branch). split == -1 means all indices are equal (trunk = the whole chain).
  uint64_t diff = 0;
  for (uint64_t I : indices) diff |= (I ^ indices[0]);
  int split = -1;
  for (int b = protocol::kIndexBits - 1; b >= 0; --b)
    if ((diff >> b) & 1) { split = b; break; }
  const uint64_t low_mask =
      (split < 0) ? 0ULL : (((uint64_t)1 << (split + 1)) - 1);
  const uint64_t high_mask = protocol::kMaxIndex & ~low_mask;
  timing.split_bit = split;

  protocol::Circuit sha = protocol::LoadBristol(kDefaultSha256CompressPath);
  ExchangeCircuitDigest(io, party, TreeDigest(indices, trunk_chunk_blocks, sha));

  // ---- one-time setup: COT mesh + input authentication ----
  auto t0 = Clock::now();
  emp::AG2PCSession sess(io, pool, party, kSsp);
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

  // ---- trunk: chain over the shared high set bits (optionally chunked) ----
  const int cb =
      (trunk_chunk_blocks > 0) ? trunk_chunk_blocks : protocol::kIndexBits;
  std::vector<std::vector<int>> tgroups =
      protocol::SplitChainBits(indices[0] & high_mask, cb);
  for (const auto& g : tgroups) timing.trunk_blocks += (int)g.size();
  timing.trunk_chunks = (int)tgroups.size();

  // The trunk must contain >=1 hash so T carries a fresh AND-output mask. With an
  // empty trunk T would be a pure linear function of the session inputs, and
  // fanning that out to many branches is input reuse -- emp's c_gamma check
  // rejects it (it would also be the selective-failure case). No shared hashes
  // also means no sharing benefit; use batch mode for such ranges.
  if (timing.trunk_blocks == 0) {
    throw std::runtime_error(
        "shachain2pc: shared-trunk needs >=1 common high set bit (no shared "
        "hash in this range); use batch mode");
  }

  auto ttrunk = Clock::now();
  protocol::Circuit tc0 = protocol::BuildChunkCircuit(sha, tgroups[0], true);
  CheckChunkCircuit(tc0);
  BV T = sess.run_artifact<BV>(ToBooleanProgram(tc0), bob_in, alice_in);
  for (std::size_t k = 1; k < tgroups.size(); ++k) {
    protocol::Circuit tc = protocol::BuildChunkCircuit(sha, tgroups[k], false);
    CheckChunkCircuit(tc);
    T = sess.run_artifact<BV>(ToBooleanProgram(tc), T);
  }
  timing.trunk_s = secs(ttrunk, Clock::now());
  sess.checkpoint(T);  // free the seed inputs + trunk intermediates; keep T

  // ---- branches: one circuit per index from the carried trunk, NOT revealed ----
  std::vector<BV> outs;
  outs.reserve(indices.size());
  timing.branch_s.reserve(indices.size());
  for (std::size_t bi = 0; bi < indices.size(); ++bi) {
    std::vector<int> branch_bits = SetBitsDesc(indices[bi] & low_mask);
    protocol::Circuit bc = protocol::BuildChunkCircuit(sha, branch_bits, false);
    if (static_cast<int>(bi) == tamper_branch) TamperFirstFlip(bc);  // TEST ONLY
    CheckChunkCircuit(bc);
    emp::circuit::BooleanProgram prog = ToBooleanProgram(bc);
    ReleaseVector(bc.gates);
    auto tb = Clock::now();
    outs.push_back(sess.run_artifact<BV>(prog, T));  // reuse T (fan-out)
    timing.branch_s.push_back(secs(tb, Clock::now()));
  }

  // ---- reveal every branch output, one-by-one (materialized outs survive) ----
  std::vector<protocol::Value> results;
  results.reserve(indices.size());
  timing.reveal_s.reserve(indices.size());
  for (std::size_t k = 0; k < outs.size(); ++k) {
    auto trv = Clock::now();
    std::optional<std::array<bool, protocol::kValueBits>> rev =
        sess.reveal(outs[k], emp::PUBLIC);
    timing.reveal_s.push_back(secs(trv, Clock::now()));
    if (!rev.has_value())
      throw std::runtime_error("shachain2pc: reveal produced no value");
    std::vector<uint8_t> ob(protocol::kValueBits);
    for (int i = 0; i < protocol::kValueBits; ++i) ob[i] = (*rev)[i] ? 1 : 0;
    results.push_back(protocol::BitsToValue(ob));
  }
  io->flush();
  timing.rounds = io->rounds;
  timing.bytes_sent = io->send_counter;
  timing.bytes_recv = io->recv_counter;
  return results;
}

// ---------------------------------------------------------------------------
// In-session adaptive cache (the BOLT-03 cache truncated to the low-bit subtree,
// on authenticated values). For a committed range [lo, hi] (≤ 2^n updates) the
// chain splits at the common high-bit prefix: the (48-n) shared high blocks are
// the trunk (computed once, chunked, only the tip carried), and the low n bits are
// an n-bit subtree. Secrets are derived in DECREASING index order (the Lightning
// per-commitment order), maintaining a stack of cached intermediate nodes keyed by
// their set-bit prefix. Full aligned 16-leaf tiles are computed as one multi-output
// subtree circuit (15 SHA edges in one compute_inplace); partial edges fall back to
// one-SHA steps. Every cached node is a hash output reused as an authenticated wire
// (never re-input), and outputs are revealed only after precomputation, so the
// pre-reveal and reveal costs can be measured separately.
struct CacheTiming {
  double setup_s = 0.0;
  double trunk_s = 0.0;
  double branch_total_s = 0.0;  // tile + fallback branch compute, no reveal
  double reveal_total_s = 0.0;
  int trunk_chunks = 0;
  int trunk_blocks = 0;
  int split_bit = -1;
  int tile_leaves = kCacheTileLeaves;
  int tile_count = 0;
  int num_indices = 0;   // leaves derived (hi-lo+1)
  long new_hashes = 0;   // total subtree SHA edges computed after trunk
  long branch_instances = 0;  // branch compute_inplace instances after trunk
  uint64_t rounds = 0, bytes_sent = 0, bytes_recv = 0;
};

inline std::array<uint8_t, 32> CacheDigest(uint64_t lo, uint64_t hi,
                                           int trunk_chunk_blocks, int tile_fanout,
                                           const protocol::Circuit& sha) {
  std::array<uint8_t, 32> sha_dg = CircuitDigest(sha, ToEmpGateArray(sha));
  std::array<uint8_t, 32> dg{};
  unsigned int len = 0;
  int tcb = trunk_chunk_blocks;
  int tf = tile_fanout;  // binds the tile arity (and thus the whole cover shape)
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (ctx == nullptr) throw std::runtime_error("CacheDigest: EVP_MD_CTX_new failed");
  auto cleanup = [&]() { EVP_MD_CTX_free(ctx); };
  if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
      EVP_DigestUpdate(ctx, &lo, sizeof(lo)) != 1 ||
      EVP_DigestUpdate(ctx, &hi, sizeof(hi)) != 1 ||
      EVP_DigestUpdate(ctx, &tcb, sizeof(tcb)) != 1 ||
      EVP_DigestUpdate(ctx, &tf, sizeof(tf)) != 1 ||
      EVP_DigestUpdate(ctx, sha_dg.data(), sha_dg.size()) != 1 ||
      EVP_DigestFinal_ex(ctx, dg.data(), &len) != 1 || len != dg.size()) {
    cleanup();
    throw std::runtime_error("CacheDigest: EVP digest failed");
  }
  cleanup();
  return dg;
}

inline protocol::Value DecodeRevealedValue(
    const std::optional<std::array<bool, protocol::kValueBits>>& r) {
  if (!r.has_value())
    throw std::runtime_error("shachain2pc: reveal produced no value");
  std::vector<uint8_t> ob(protocol::kValueBits);
  for (int i = 0; i < protocol::kValueBits; ++i) ob[i] = (*r)[i] ? 1 : 0;
  return protocol::BitsToValue(ob);
}

template <int Slot, typename Ctx>
inline std::optional<std::array<bool, protocol::kValueBits>> RevealTileSlotRaw(
    emp::AG2PCSession& sess, const emp::BitVec_T<Ctx, kCacheTileBits>& tile) {
  static_assert(0 <= Slot && Slot < kCacheTileLeaves);
  auto leaf = tile.template slice<Slot * protocol::kValueBits,
                                  (Slot + 1) * protocol::kValueBits>();
  return sess.reveal(leaf, emp::PUBLIC);
}

template <typename Ctx>
inline std::optional<std::array<bool, protocol::kValueBits>> RevealTileSlotRaw(
    emp::AG2PCSession& sess, const emp::BitVec_T<Ctx, kCacheTileBits>& tile,
    int slot) {
  switch (slot) {
    case 0: return RevealTileSlotRaw<0>(sess, tile);
    case 1: return RevealTileSlotRaw<1>(sess, tile);
    case 2: return RevealTileSlotRaw<2>(sess, tile);
    case 3: return RevealTileSlotRaw<3>(sess, tile);
    case 4: return RevealTileSlotRaw<4>(sess, tile);
    case 5: return RevealTileSlotRaw<5>(sess, tile);
    case 6: return RevealTileSlotRaw<6>(sess, tile);
    case 7: return RevealTileSlotRaw<7>(sess, tile);
    case 8: return RevealTileSlotRaw<8>(sess, tile);
    case 9: return RevealTileSlotRaw<9>(sess, tile);
    case 10: return RevealTileSlotRaw<10>(sess, tile);
    case 11: return RevealTileSlotRaw<11>(sess, tile);
    case 12: return RevealTileSlotRaw<12>(sess, tile);
    case 13: return RevealTileSlotRaw<13>(sess, tile);
    case 14: return RevealTileSlotRaw<14>(sess, tile);
    case 15: return RevealTileSlotRaw<15>(sess, tile);
    default: throw std::runtime_error("shachain2pc: tile slot out of range");
  }
}

// ---- recursive tiling helpers (height-generic) ----------------------------
// The cache session uses one fixed wire context, so the tile value types are
// concrete (no per-call Ctx templating). A height-H tile carries 2^H * 256 bits.
using CacheCtx = emp::AG2PCSession::DirectCtx;
using CacheBV = emp::BitVec_T<CacheCtx, protocol::kValueBits>;
template <int H>
using CacheTileBV = emp::BitVec_T<CacheCtx, (1 << H) * protocol::kValueBits>;

template <int H>
inline void CheckTileShape(const protocol::Circuit& c) {
  if (c.n1 != protocol::kValueBits || c.n2 != 0 ||
      c.n3 != (1 << H) * protocol::kValueBits) {
    throw std::runtime_error("shachain2pc: tile circuit has wrong shape");
  }
}

// Split a height-H tile output into its 2^H authenticated 256-bit arms (no
// reveal). Slices are compile-time, unrolled over the arm indices.
template <int H, std::size_t... Is>
inline std::array<CacheBV, sizeof...(Is)> SplitTileImpl(
    const CacheTileBV<H>& t, std::index_sequence<Is...>) {
  return {t.template slice<Is * protocol::kValueBits,
                           (Is + 1) * protocol::kValueBits>()...};
}
template <int H>
inline std::array<CacheBV, (1 << H)> SplitTile(const CacheTileBV<H>& t) {
  return SplitTileImpl<H>(t, std::make_index_sequence<(1 << H)>{});
}

// Reveal one arm of a height-H tile (used for bottom-level leaves).
template <int H>
inline std::optional<std::array<bool, protocol::kValueBits>> RevealTileSlot(
    emp::AG2PCSession& sess, const CacheTileBV<H>& t, int slot) {
  std::array<CacheBV, (1 << H)> arms = SplitTile<H>(t);
  return sess.reveal(arms[slot], emp::PUBLIC);
}

// Run one inner (non-leaf) tile level of height H over the window starting at
// `bit_offset`: for every input root, run a tile and append its 2^H child roots
// to `out`. Children stay authenticated wires that feed the next lower level.
template <int H>
inline void RunInnerTileLevel(emp::AG2PCSession& sess,
                              const protocol::Circuit& sha, int bit_offset,
                              const std::vector<CacheBV>& roots,
                              std::vector<CacheBV>& out, CacheTiming& timing,
                              long& step, long tamper_step) {
  using Clock = std::chrono::steady_clock;
  protocol::Circuit tc = protocol::BuildTileCircuit(sha, bit_offset, H);
  CheckTileShape<H>(tc);
  emp::circuit::BooleanProgram prog = ToBooleanProgram(tc);
  ReleaseVector(tc.gates);
  out.reserve(out.size() + roots.size() * (std::size_t(1) << H));
  for (const CacheBV& root : roots) {
    const emp::circuit::BooleanProgram* p = &prog;
    emp::circuit::BooleanProgram tampered;
    if (step == tamper_step) {  // TEST ONLY: garble this tile
      protocol::Circuit tt = protocol::BuildTileCircuit(sha, bit_offset, H);
      TamperFirstFlip(tt);
      CheckTileShape<H>(tt);
      tampered = ToBooleanProgram(tt);
      ReleaseVector(tt.gates);
      p = &tampered;
    }
    auto tb = Clock::now();
    CacheTileBV<H> t = sess.run_artifact<CacheTileBV<H>>(*p, root);
    timing.branch_total_s +=
        std::chrono::duration<double>(Clock::now() - tb).count();
    timing.new_hashes += (1 << H) - 1;
    ++timing.branch_instances;
    ++timing.tile_count;
    ++step;
    std::array<CacheBV, (1 << H)> kids = SplitTile<H>(t);
    for (CacheBV& k : kids) out.push_back(k);
  }
}

inline void RunInnerTileLevelDyn(emp::AG2PCSession& sess,
                                 const protocol::Circuit& sha, int bit_offset,
                                 int height, const std::vector<CacheBV>& roots,
                                 std::vector<CacheBV>& out, CacheTiming& timing,
                                 long& step, long tamper_step) {
  switch (height) {
    case 1: RunInnerTileLevel<1>(sess, sha, bit_offset, roots, out, timing, step, tamper_step); break;
    case 2: RunInnerTileLevel<2>(sess, sha, bit_offset, roots, out, timing, step, tamper_step); break;
    case 3: RunInnerTileLevel<3>(sess, sha, bit_offset, roots, out, timing, step, tamper_step); break;
    case 4: RunInnerTileLevel<4>(sess, sha, bit_offset, roots, out, timing, step, tamper_step); break;
    default: throw std::runtime_error("shachain2pc: unsupported tile height (1..4)");
  }
}

// Run the bottom (leaf) tile level of height H at bit_offset 0: precompute every
// leaf tile (held authenticated), then reveal each requested index one-by-one in
// decreasing order. Bottom tile j holds subtree indices [j<<H, j<<H | mask], so
// index I -> tile (s>>H), slot (s & (2^H-1)) with s = I & low_mask.
template <int H>
inline void RunBottomTileLevel(emp::AG2PCSession& sess,
                               const protocol::Circuit& sha,
                               const std::vector<CacheBV>& roots, uint64_t lo,
                               uint64_t hi, uint64_t low_mask,
                               std::vector<protocol::Value>& results,
                               CacheTiming& timing, long& step,
                               long tamper_step) {
  using Clock = std::chrono::steady_clock;
  protocol::Circuit tc = protocol::BuildTileCircuit(sha, 0, H);
  CheckTileShape<H>(tc);
  emp::circuit::BooleanProgram prog = ToBooleanProgram(tc);
  ReleaseVector(tc.gates);
  std::vector<CacheTileBV<H>> bottoms;
  bottoms.reserve(roots.size());
  for (const CacheBV& root : roots) {
    const emp::circuit::BooleanProgram* p = &prog;
    emp::circuit::BooleanProgram tampered;
    if (step == tamper_step) {  // TEST ONLY: garble this leaf tile
      protocol::Circuit tt = protocol::BuildTileCircuit(sha, 0, H);
      TamperFirstFlip(tt);
      CheckTileShape<H>(tt);
      tampered = ToBooleanProgram(tt);
      ReleaseVector(tt.gates);
      p = &tampered;
    }
    auto tb = Clock::now();
    bottoms.push_back(sess.run_artifact<CacheTileBV<H>>(*p, root));
    timing.branch_total_s +=
        std::chrono::duration<double>(Clock::now() - tb).count();
    timing.new_hashes += (1 << H) - 1;
    ++timing.branch_instances;
    ++timing.tile_count;
    ++step;
  }
  const uint64_t leaves = (uint64_t(1) << H);
  for (uint64_t I = hi;; --I) {
    const uint64_t s = I & low_mask;
    auto trv = Clock::now();
    results[(std::size_t)(I - lo)] = DecodeRevealedValue(RevealTileSlot<H>(
        sess, bottoms[(std::size_t)(s >> H)], (int)(s & (leaves - 1))));
    timing.reveal_total_s +=
        std::chrono::duration<double>(Clock::now() - trv).count();
    if (I == lo) break;
  }
}

inline void RunBottomTileLevelDyn(emp::AG2PCSession& sess,
                                  const protocol::Circuit& sha, int height,
                                  const std::vector<CacheBV>& roots, uint64_t lo,
                                  uint64_t hi, uint64_t low_mask,
                                  std::vector<protocol::Value>& results,
                                  CacheTiming& timing, long& step,
                                  long tamper_step) {
  switch (height) {
    case 1: RunBottomTileLevel<1>(sess, sha, roots, lo, hi, low_mask, results, timing, step, tamper_step); break;
    case 2: RunBottomTileLevel<2>(sess, sha, roots, lo, hi, low_mask, results, timing, step, tamper_step); break;
    case 3: RunBottomTileLevel<3>(sess, sha, roots, lo, hi, low_mask, results, timing, step, tamper_step); break;
    case 4: RunBottomTileLevel<4>(sess, sha, roots, lo, hi, low_mask, results, timing, step, tamper_step); break;
    default: throw std::runtime_error("shachain2pc: unsupported tile height (1..4)");
  }
}

// tamper_step >= 0 (TEST ONLY): garble a steered flip on that branch push to
// confirm authenticated garbling aborts even with the reused cached trunk/nodes.
inline std::vector<protocol::Value> RunDerivationCache(
    emp::NetIO* io, ThreadPool* pool, int party, uint64_t lo, uint64_t hi,
    const protocol::Value& my_share, int trunk_chunk_blocks, int tile_fanout,
    CacheTiming& timing, long tamper_step = -1) {
  using Ctx = emp::AG2PCSession::DirectCtx;
  using BV = emp::BitVec_T<Ctx, protocol::kValueBits>;
  using TileBV = emp::BitVec_T<Ctx, kCacheTileBits>;
  using Clock = std::chrono::steady_clock;
  auto secs = [](Clock::time_point a, Clock::time_point b) {
    return std::chrono::duration<double>(b - a).count();
  };

  if (lo > hi) throw std::runtime_error("shachain2pc: cache range lo > hi");
  if (hi > protocol::kMaxIndex)
    throw std::runtime_error("shachain2pc: index exceeds 48 bits");

  // Tile fanout knob: power of two. fanout = 1 -> no recursive tiling (the
  // fallback stack-cache runs pure one-SHA edges); fanout >= 2 -> tile_height =
  // log2(fanout), used for the recursive aligned cover and the fallback tiles.
  if (tile_fanout < 1 || (tile_fanout & (tile_fanout - 1)) != 0)
    throw std::runtime_error("shachain2pc: tile_fanout must be a power of two");
  int tile_height = 0;
  while ((1 << tile_height) < tile_fanout) ++tile_height;
  if (tile_height > 4)
    throw std::runtime_error("shachain2pc: tile_fanout > 16 not supported");

  const uint64_t diff = lo ^ hi;
  int split = -1;
  for (int b = protocol::kIndexBits - 1; b >= 0; --b)
    if ((diff >> b) & 1) { split = b; break; }
  const uint64_t low_mask = (split < 0) ? 0ULL : (((uint64_t)1 << (split + 1)) - 1);
  const uint64_t high_mask = protocol::kMaxIndex & ~low_mask;
  timing.split_bit = split;
  timing.num_indices = (int)(hi - lo + 1);

  protocol::Circuit sha = protocol::LoadBristol(kDefaultSha256CompressPath);
  ExchangeCircuitDigest(io, party,
                        CacheDigest(lo, hi, trunk_chunk_blocks, tile_fanout, sha));

  // ---- setup ----
  auto t0 = Clock::now();
  emp::AG2PCSession sess(io, pool, party, kSsp);
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

  // ---- trunk: the shared high set bits, chunked; only the tip survives ----
  const int cb =
      (trunk_chunk_blocks > 0) ? trunk_chunk_blocks : protocol::kIndexBits;
  std::vector<std::vector<int>> tgroups =
      protocol::SplitChainBits(lo & high_mask, cb);
  for (const auto& g : tgroups) timing.trunk_blocks += (int)g.size();
  timing.trunk_chunks = (int)tgroups.size();
  if (timing.trunk_blocks == 0) {
    throw std::runtime_error(
        "shachain2pc: cache needs >=1 common high set bit (no shared trunk hash); "
        "use batch mode for this range");
  }
  auto ttrunk = Clock::now();
  {
    protocol::Circuit c0 = protocol::BuildChunkCircuit(sha, tgroups[0], true);
    CheckChunkCircuit(c0);
    BV T = sess.run_artifact<BV>(ToBooleanProgram(c0), bob_in, alice_in);
    for (std::size_t k = 1; k < tgroups.size(); ++k) {
      protocol::Circuit c = protocol::BuildChunkCircuit(sha, tgroups[k], false);
      CheckChunkCircuit(c);
      T = sess.run_artifact<BV>(ToBooleanProgram(c), T);
    }
    timing.trunk_s = secs(ttrunk, Clock::now());
    sess.checkpoint(T);  // free inputs + trunk internals; keep only the tip

    // ---- recursive tiled cover (aligned full subtree only) ----
    // When [lo,hi] is exactly a 2^(split+1) block and fanout >= 2, derive every
    // leaf through a tree of multi-output tiles: an upper tile fans the high
    // window into intermediate roots, lower tiles expand them, the bottom tiles
    // hold the leaves. Far fewer MPC instances (round groups) than one-SHA
    // prefixes; intermediate roots stay authenticated wires, never revealed.
    const int depth = split + 1;
    const bool aligned =
        ((lo & low_mask) == 0) && ((hi & low_mask) == low_mask);
    if (tile_height >= 1 && split >= 0 && aligned && depth >= tile_height) {
      std::vector<protocol::Value> results((std::size_t)(hi - lo + 1));
      timing.tile_leaves = (1 << tile_height);
      long step = 0;
      std::vector<CacheBV> roots;
      roots.push_back(T);
      std::vector<protocol::TileLevel> levels =
          protocol::PlanTileLevels(depth, tile_height);
      for (std::size_t L = 0; L + 1 < levels.size(); ++L) {
        std::vector<CacheBV> next;
        RunInnerTileLevelDyn(sess, sha, levels[L].bit_offset, levels[L].height,
                             roots, next, timing, step, tamper_step);
        roots = std::move(next);
      }
      const protocol::TileLevel& bottom = levels.back();
      RunBottomTileLevelDyn(sess, sha, bottom.height, roots, lo, hi, low_mask,
                            results, timing, step, tamper_step);
      io->flush();
      timing.rounds = io->rounds;
      timing.bytes_sent = io->send_counter;
      timing.bytes_recv = io->recv_counter;
      return results;
    }

	    // ---- subtree stack-cache, DECREASING index order ----
	    std::vector<int> stack_bits;     // set-bit prefix currently on the stack
	    std::vector<BV> stack_vals;      // stack_vals[0]=T; [k]=value after bits[0..k-1]
	    stack_vals.push_back(T);
	    protocol::Circuit tile_circuit =
	        protocol::BuildTileCircuit(sha, 0, kCacheTileHeight);
	    CheckTileCircuit(tile_circuit);
	    emp::circuit::BooleanProgram tile_prog = ToBooleanProgram(tile_circuit);
	    ReleaseVector(tile_circuit.gates);

	    struct TileOut {
	      uint64_t base;
	      TileBV value;
	    };
	    struct SingleOut {
	      uint64_t index;
	      BV value;
	    };
	    std::vector<TileOut> tile_outs;
	    std::vector<SingleOut> single_outs;
	    std::unordered_map<uint64_t, std::size_t> tile_pos;
	    std::unordered_map<uint64_t, std::size_t> single_pos;
	    std::vector<protocol::Value> results((std::size_t)(hi - lo + 1));
	    const uint64_t tile_mask = static_cast<uint64_t>(kCacheTileLeaves - 1);
	    const bool can_tile = tile_fanout >= 2 && split >= kCacheTileHeight - 1;
	    long step = 0;

	    auto align_stack = [&](const std::vector<int>& target) {
	      std::size_t p = 0;
	      while (p < stack_bits.size() && p < target.size() &&
	             stack_bits[p] == target[p]) ++p;
	      stack_bits.resize(p);
	      stack_vals.resize(p + 1);  // drop the divergent tail (shrink only)
	      for (std::size_t j = p; j < target.size(); ++j) {
	        protocol::Circuit bc = protocol::BuildChunkCircuit(sha, {target[j]}, false);
	        if (step == tamper_step) TamperFirstFlip(bc);  // TEST ONLY
	        CheckChunkCircuit(bc);
	        emp::circuit::BooleanProgram prog = ToBooleanProgram(bc);
	        ReleaseVector(bc.gates);
	        auto tb = Clock::now();
	        stack_vals.push_back(sess.run_artifact<BV>(prog, stack_vals.back()));
	        timing.branch_total_s += secs(tb, Clock::now());
	        stack_bits.push_back(target[j]);
	        ++timing.new_hashes;
	        ++timing.branch_instances;
	        ++step;
	      }
	    };

	    for (uint64_t I = hi;;) {
	      const uint64_t tile_base = I & ~tile_mask;
	      const bool full_tile =
	          can_tile && ((I & tile_mask) == tile_mask) && tile_base >= lo &&
	          tile_base + tile_mask <= hi;
	      if (full_tile) {
	        std::vector<int> prefix =
	            SetBitsDesc((tile_base & low_mask) & ~tile_mask);
	        align_stack(prefix);

	        emp::circuit::BooleanProgram* prog = &tile_prog;
	        emp::circuit::BooleanProgram tampered_prog;
	        if (step == tamper_step) {
	          protocol::Circuit tampered =
	              protocol::BuildTileCircuit(sha, 0, kCacheTileHeight);
	          TamperFirstFlip(tampered);  // TEST ONLY
	          CheckTileCircuit(tampered);
	          tampered_prog = ToBooleanProgram(tampered);
	          ReleaseVector(tampered.gates);
	          prog = &tampered_prog;
	        }

	        auto tb = Clock::now();
	        TileBV out = sess.run_artifact<TileBV>(*prog, stack_vals.back());
	        timing.branch_total_s += secs(tb, Clock::now());
	        timing.new_hashes += kCacheTileLeaves - 1;
	        ++timing.branch_instances;
	        ++timing.tile_count;
	        ++step;
	        tile_pos[tile_base] = tile_outs.size();
	        tile_outs.push_back(TileOut{tile_base, out});

	        if (tile_base == lo) break;
	        I = tile_base - 1;
	        continue;
	      }

	      std::vector<int> low = SetBitsDesc(I & low_mask);  // high to low
	      align_stack(low);
	      single_pos[I] = single_outs.size();
	      single_outs.push_back(SingleOut{I, stack_vals.back()});
	      if (I == lo) break;
	      --I;
	    }

	    // ---- reveal every requested output, one-by-one, after precomputation ----
	    for (uint64_t I = hi;; --I) {
	      auto trv = Clock::now();
	      const uint64_t tile_base = I & ~tile_mask;
	      auto tit = tile_pos.find(tile_base);
	      if (tit != tile_pos.end()) {
	        int slot = static_cast<int>(I & tile_mask);
	        results[(std::size_t)(I - lo)] = DecodeRevealedValue(
	            RevealTileSlotRaw(sess, tile_outs[tit->second].value, slot));
	      } else {
	        auto sit = single_pos.find(I);
	        if (sit == single_pos.end()) {
	          throw std::runtime_error("shachain2pc: missing cached output");
	        }
	        results[(std::size_t)(I - lo)] = DecodeRevealedValue(
	            sess.reveal(single_outs[sit->second].value, emp::PUBLIC));
	      }
	      timing.reveal_total_s += secs(trv, Clock::now());
	      if (I == lo) break;
	    }
	    io->flush();
    timing.rounds = io->rounds;
    timing.bytes_sent = io->send_counter;
    timing.bytes_recv = io->recv_counter;
    return results;
  }
}

}  // namespace shachain2pc::run

#endif  // SHACHAIN2PC_RUN_DERIVE_H
