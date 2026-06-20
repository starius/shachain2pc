// Plaintext verification of the generated derivation circuit against the
// single-party reference, over several indices and share splits. No MPC: this
// isolates circuit-correctness risk before wiring to emp-ag2pc.
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "../protocol/bristol.h"
#include "../protocol/circuit_gen.h"
#include "../protocol/wire_layout.h"
#include "../reference/shachain_ref.h"

namespace ref = shachain2pc::reference;
namespace proto = shachain2pc::protocol;

static std::string Hex(const proto::Value& v) {
  static const char* d = "0123456789abcdef";
  std::string s;
  for (uint8_t b : v) {
    s.push_back(d[b >> 4]);
    s.push_back(d[b & 0xf]);
  }
  return s;
}

static int PopCount(uint64_t x) {
  int n = 0;
  while (x) {
    n += x & 1;
    x >>= 1;
  }
  return n;
}

// Run the circuit for index I with seed split into (share, seed^share).
static proto::Value RunCircuit(const proto::Circuit& c, const proto::Value& seed,
                               const proto::Value& share) {
  proto::Value a = share;
  proto::Value b{};
  for (int i = 0; i < 32; ++i) b[i] = seed[i] ^ a[i];
  std::vector<uint8_t> in = proto::ValueToBits(a);
  std::vector<uint8_t> bb = proto::ValueToBits(b);
  in.insert(in.end(), bb.begin(), bb.end());
  return proto::BitsToValue(proto::EvalBristol(c, in));
}

// Evaluate the block-chunked chain (blocks_per_chunk = N) in plaintext: chunk 0
// takes a||b and recombines the seed; each later chunk takes the prior 256-bit
// value directly (the same value the MPC carries as an authenticated wire).
static proto::Value RunChunked(const proto::Circuit& sha, const proto::Value& seed,
                               const proto::Value& share, uint64_t I, int N) {
  proto::Value a = share;
  proto::Value b{};
  for (int i = 0; i < 32; ++i) b[i] = seed[i] ^ a[i];
  std::vector<std::vector<int>> groups = proto::SplitChainBits(I, N);
  std::vector<uint8_t> in = proto::ValueToBits(a);
  std::vector<uint8_t> bb = proto::ValueToBits(b);
  in.insert(in.end(), bb.begin(), bb.end());
  std::vector<uint8_t> v =
      proto::EvalBristol(proto::BuildChunkCircuit(sha, groups[0], true), in);
  for (size_t k = 1; k < groups.size(); ++k) {
    v = proto::EvalBristol(proto::BuildChunkCircuit(sha, groups[k], false), v);
  }
  return proto::BitsToValue(v);
}

static std::vector<proto::Value> RunTilePlain(const proto::Circuit& sha,
                                              const proto::Value& root,
                                              int bit_offset, int height) {
  std::vector<uint8_t> in = proto::ValueToBits(root);
  std::vector<uint8_t> out =
      proto::EvalBristol(proto::BuildTileCircuit(sha, bit_offset, height), in);
  const int leaves = 1 << height;
  std::vector<proto::Value> values;
  values.reserve(leaves);
  for (int s = 0; s < leaves; ++s) {
    std::vector<uint8_t> bits(out.begin() + s * proto::kValueBits,
                              out.begin() + (s + 1) * proto::kValueBits);
    values.push_back(proto::BitsToValue(bits));
  }
  return values;
}

// Evaluate the shared-trunk decomposition for index I within a range [lo,hi]:
// the trunk processes the high bits common to the range, the branch the low bits
// of I (the same split the MPC RunDerivationTree uses). Must equal the reference.
static proto::Value RunTreePlain(const proto::Circuit& sha, const proto::Value& seed,
                                 const proto::Value& share, uint64_t lo, uint64_t hi,
                                 uint64_t I) {
  uint64_t diff = lo ^ hi;
  int split = -1;
  for (int b = 47; b >= 0; --b)
    if ((diff >> b) & 1) { split = b; break; }
  uint64_t low_mask = (split < 0) ? 0ULL : (((uint64_t)1 << (split + 1)) - 1);
  uint64_t high_mask = (((uint64_t)1 << 48) - 1) & ~low_mask;
  proto::Value a = share;
  proto::Value b{};
  for (int i = 0; i < 32; ++i) b[i] = seed[i] ^ a[i];
  std::vector<uint8_t> in = proto::ValueToBits(a);
  std::vector<uint8_t> bb = proto::ValueToBits(b);
  in.insert(in.end(), bb.begin(), bb.end());
  std::vector<std::vector<int>> tg = proto::SplitChainBits(lo & high_mask, 48);
  std::vector<uint8_t> T =
      proto::EvalBristol(proto::BuildChunkCircuit(sha, tg[0], true), in);
  std::vector<int> branch = proto::SplitChainBits(I & low_mask, 48)[0];
  std::vector<uint8_t> v =
      proto::EvalBristol(proto::BuildChunkCircuit(sha, branch, false), T);
  return proto::BitsToValue(v);
}

// Plaintext mirror of RunDerivationCache's stack-cache: trunk once, then the range
// [lo,hi] in decreasing order through a set-bit-prefix stack. Verifies every H(I)
// equals the reference (validates the pop/push/prefix-reuse logic, not just one
// branch). Returns true iff all match.
static bool VerifyCachePlain(const proto::Circuit& sha, const proto::Value& seed,
                             const proto::Value& share, uint64_t lo, uint64_t hi) {
  uint64_t diff = lo ^ hi;
  int split = -1;
  for (int b = 47; b >= 0; --b)
    if ((diff >> b) & 1) { split = b; break; }
  uint64_t low_mask = (split < 0) ? 0ULL : (((uint64_t)1 << (split + 1)) - 1);
  uint64_t high_mask = (((uint64_t)1 << 48) - 1) & ~low_mask;
  proto::Value a = share;
  proto::Value b{};
  for (int i = 0; i < 32; ++i) b[i] = seed[i] ^ a[i];
  std::vector<uint8_t> in = proto::ValueToBits(a);
  std::vector<uint8_t> bb = proto::ValueToBits(b);
  in.insert(in.end(), bb.begin(), bb.end());
  std::vector<std::vector<int>> tg = proto::SplitChainBits(lo & high_mask, 48);
  std::vector<uint8_t> T =
      proto::EvalBristol(proto::BuildChunkCircuit(sha, tg[0], true), in);

  std::vector<int> sbits;
  std::vector<std::vector<uint8_t>> svals;
  svals.push_back(T);
  for (uint64_t I = hi;; --I) {
    std::vector<int> low = proto::SplitChainBits(I & low_mask, 48)[0];
    std::size_t p = 0;
    while (p < sbits.size() && p < low.size() && sbits[p] == low[p]) ++p;
    sbits.resize(p);
    svals.resize(p + 1);
    for (std::size_t j = p; j < low.size(); ++j) {
      svals.push_back(proto::EvalBristol(
          proto::BuildChunkCircuit(sha, {low[j]}, false), svals.back()));
      sbits.push_back(low[j]);
    }
    if (proto::BitsToValue(svals.back()) != ref::GenerateFromSeed(seed, I))
      return false;
    if (I == lo) break;
  }
  return true;
}

// Plaintext mirror of the recursive tiled cache (RunDerivationCache's recursive
// path) for an ALIGNED subtree: trunk once, then PlanTileLevels recursion via
// offset tiles, level by level. The bottom level's tiles are indexed exactly as
// the MPC driver indexes them (tile = s >> tile_height, slot = low tile_height
// bits). Verifies every leaf H(I) equals the reference. Returns true iff the
// range is a usable aligned subtree (depth >= tile_height) AND all leaves match.
static bool VerifyRecursiveCachePlain(const proto::Circuit& sha,
                                      const proto::Value& seed,
                                      const proto::Value& share, uint64_t lo,
                                      uint64_t hi, int tile_height) {
  uint64_t diff = lo ^ hi;
  int split = -1;
  for (int b = 47; b >= 0; --b)
    if ((diff >> b) & 1) { split = b; break; }
  if (split < 0) return false;
  uint64_t low_mask = (((uint64_t)1 << (split + 1)) - 1);
  uint64_t high_mask = (((uint64_t)1 << 48) - 1) & ~low_mask;
  if ((lo & low_mask) != 0 || (hi & low_mask) != low_mask) return false;  // aligned only
  const int depth = split + 1;
  if (depth < tile_height) return false;

  proto::Value a = share;
  proto::Value b{};
  for (int i = 0; i < 32; ++i) b[i] = seed[i] ^ a[i];
  std::vector<uint8_t> in = proto::ValueToBits(a);
  std::vector<uint8_t> bb = proto::ValueToBits(b);
  in.insert(in.end(), bb.begin(), bb.end());
  std::vector<std::vector<int>> tg = proto::SplitChainBits(lo & high_mask, 48);
  proto::Value T = proto::BitsToValue(
      proto::EvalBristol(proto::BuildChunkCircuit(sha, tg[0], true), in));

  std::vector<proto::TileLevel> levels = proto::PlanTileLevels(depth, tile_height);
  std::vector<proto::Value> roots = {T};
  for (std::size_t L = 0; L + 1 < levels.size(); ++L) {
    std::vector<proto::Value> next;
    for (const proto::Value& r : roots) {
      std::vector<proto::Value> kids =
          RunTilePlain(sha, r, levels[L].bit_offset, levels[L].height);
      for (proto::Value& k : kids) next.push_back(k);
    }
    roots = std::move(next);
  }
  const proto::TileLevel& bl = levels.back();
  const int th = bl.height;
  std::vector<std::vector<proto::Value>> bottoms;
  for (const proto::Value& r : roots)
    bottoms.push_back(RunTilePlain(sha, r, bl.bit_offset, th));

  const uint64_t leaves = (uint64_t)1 << th;
  for (uint64_t I = lo; I <= hi; ++I) {
    uint64_t s = I & low_mask;
    proto::Value got = bottoms[s >> th][s & (leaves - 1)];
    if (got != ref::GenerateFromSeed(seed, I)) return false;
  }
  return true;
}

int main() {
  proto::Circuit sha = proto::LoadBristol(
      ".deps/emp/include/emp-tool/circuits/files/bristol_format/sha-256.txt");

  struct Case {
    uint8_t seed_fill;
    uint64_t index;
  };
  const Case cases[] = {
      {0x00, 0xffffffffffffULL}, {0xff, 0xffffffffffffULL},
      {0xff, 0xaaaaaaaaaaaULL},  {0xff, 0x555555555555ULL},
      {0x01, 1ULL},             {0x00, 0ULL},
      {0xab, 0x123456789abcULL},
  };

  // Three share splits per case: all-zero (share == seed on B), a fixed
  // pattern, and a different pattern. The circuit XORs them back, so all must
  // agree with the reference.
  proto::Value split0{};
  proto::Value split1{};
  proto::Value split2{};
  for (int j = 0; j < 32; ++j) {
    split1[j] = static_cast<uint8_t>(j * 7 + 13);
    split2[j] = static_cast<uint8_t>(0xa5 ^ (j * 31));
  }

  int failures = 0;
  for (const Case& tc : cases) {
    proto::Value seed = ref::FillSeed(tc.seed_fill);
    proto::Value want = ref::GenerateFromSeed(seed, tc.index);
    proto::Circuit c = proto::BuildDerivationCircuit(sha, tc.index);

    bool ok = true;
    for (const proto::Value* sh : {&split0, &split1, &split2}) {
      proto::Value got = RunCircuit(c, seed, *sh);
      if (got != want) {
        ok = false;
        std::printf("  split mismatch: got %s\n", Hex(got).c_str());
      }
    }
    std::printf("seed=%02x I=%012llx pop=%2d gates=%8d  %s\n", tc.seed_fill,
                static_cast<unsigned long long>(tc.index), PopCount(tc.index),
                c.num_gate(), ok ? "PASS" : "FAIL");
    if (!ok) {
      std::printf("   want %s\n", Hex(want).c_str());
      ++failures;
    }
  }

  // Round-trip through the serializer (what emp will read).
  {
    proto::Circuit c = proto::BuildDerivationCircuit(sha, 1ULL);
    proto::SaveBristol(c, ".build/derive_I1.txt");
    proto::Circuit r = proto::LoadBristol(".build/derive_I1.txt");
    proto::Value seed = ref::FillSeed(0x01);
    bool ok = RunCircuit(r, seed, split1) == ref::GenerateFromSeed(seed, 1ULL);
    std::printf("serializer round-trip (I=1): %s\n", ok ? "PASS" : "FAIL");
    if (!ok) ++failures;
  }

  // Block-chunking: the chained chunks must equal the reference for every chunk
  // size, for each split. This pins that splitting the chain (and carrying the
  // intermediate) is functionally identical to the one big circuit.
  {
    const uint64_t idxs[] = {0ULL, 1ULL, 3ULL, 0x123456789abcULL, 0xffffffffffffULL};
    const int ns[] = {1, 2, 5, 48};
    bool ok = true;
    for (uint64_t I : idxs) {
      proto::Value want = ref::GenerateFromSeed(ref::FillSeed(0xab), I);
      for (int N : ns) {
        for (const proto::Value* sh : {&split0, &split1, &split2}) {
          proto::Value got = RunChunked(sha, ref::FillSeed(0xab), *sh, I, N);
          if (got != want) {
            ok = false;
            std::printf("  chunk mismatch I=%012llx N=%d: got %s\n",
                        static_cast<unsigned long long>(I), N, Hex(got).c_str());
          }
        }
      }
    }
    std::printf("block-chunking (all I x N x splits): %s\n", ok ? "PASS" : "FAIL");
    if (!ok) ++failures;
  }

  // Tile circuit: a 16-leaf low-bit subtree from an authenticated root must match
  // independent reference derivations for every suffix, in ascending output order.
  {
    proto::Value root = ref::FillSeed(0x42);
    std::vector<proto::Value> got = RunTilePlain(sha, root, 0, 4);
    bool ok = got.size() == 16;
    for (int s = 0; s < 16 && ok; ++s) {
      proto::Value want = ref::GenerateFromSeed(root, static_cast<uint64_t>(s));
      if (got[s] != want) {
        ok = false;
        std::printf("  tile mismatch suffix=%x: got %s\n", s, Hex(got[s]).c_str());
      }
    }
    std::printf("tile circuit (height=4, 16 leaves): %s\n", ok ? "PASS" : "FAIL");
    if (!ok) ++failures;
  }

  // Offset tiles: arm `suffix` of a tile over [bit_offset, bit_offset+height)
  // must equal generate_from_seed(root, suffix << bit_offset). This pins that the
  // intermediate roots feeding lower tile levels are the right ancestor values.
  {
    proto::Value root = ref::FillSeed(0x42);
    const int offsets[] = {0, 1, 4, 8, 20, 44};
    const int heights[] = {1, 2, 3, 4};
    bool ok = true;
    for (int off : offsets) {
      for (int h : heights) {
        if (off + h > 48) continue;
        std::vector<proto::Value> got = RunTilePlain(sha, root, off, h);
        if (static_cast<int>(got.size()) != (1 << h)) { ok = false; continue; }
        for (int s = 0; s < (1 << h) && ok; ++s) {
          uint64_t I = static_cast<uint64_t>(s) << off;
          if (got[s] != ref::GenerateFromSeed(root, I)) {
            ok = false;
            std::printf("  offset-tile mismatch off=%d h=%d s=%x\n", off, h, s);
          }
        }
      }
    }
    std::printf("offset tile circuits (bit_offset x height): %s\n",
                ok ? "PASS" : "FAIL");
    if (!ok) ++failures;
  }

  // Shared-trunk: trunk(common high bits) + per-I branch(low bits) must equal the
  // reference for every I in several ranges (incl. the degenerate single-index).
  {
    struct R { uint64_t lo, hi; };
    const R ranges[] = {{0xffffffffff00ULL, 0xffffffffffffULL},
                        {0x100ULL, 0x10fULL},
                        {0xabc0ULL, 0xabffULL},
                        {7ULL, 7ULL}};
    bool ok = true;
    for (const R& r : ranges) {
      for (uint64_t I = r.lo; I <= r.hi && ok; ++I) {
        proto::Value want = ref::GenerateFromSeed(ref::FillSeed(0xab), I);
        for (const proto::Value* sh : {&split0, &split1}) {
          if (RunTreePlain(sha, ref::FillSeed(0xab), *sh, r.lo, r.hi, I) != want) {
            ok = false;
            std::printf("  tree mismatch range[%llx,%llx] I=%llx\n",
                        static_cast<unsigned long long>(r.lo),
                        static_cast<unsigned long long>(r.hi),
                        static_cast<unsigned long long>(I));
          }
        }
      }
    }
    std::printf("shared-trunk (ranges x I x splits): %s\n", ok ? "PASS" : "FAIL");
    if (!ok) ++failures;
  }

  // Adaptive cache: the decreasing-order stack-cache must reproduce the reference
  // for every index in several ranges (exercises prefix reuse + pop/push).
  {
    struct R { uint64_t lo, hi; };
    const R ranges[] = {{0xffffffffff00ULL, 0xffffffffffffULL},
                        {0xfffffffffff0ULL, 0xffffffffffffULL},
                        {0x12300ULL, 0x123ffULL},
                        {0xabcdeULL, 0xabcdeULL}};
    bool ok = true;
    for (const R& r : ranges) {
      for (const proto::Value* sh : {&split0, &split1}) {
        if (!VerifyCachePlain(sha, ref::FillSeed(0xab), *sh, r.lo, r.hi)) {
          ok = false;
          std::printf("  cache mismatch range[%llx,%llx]\n",
                      static_cast<unsigned long long>(r.lo),
                      static_cast<unsigned long long>(r.hi));
        }
      }
    }
    std::printf("adaptive-cache (ranges x splits): %s\n", ok ? "PASS" : "FAIL");
    if (!ok) ++failures;
  }

  // Recursive tiled cache: aligned subtrees decomposed by PlanTileLevels into a
  // tree of offset tiles must reproduce the reference for every leaf, for each
  // tile height (validates level planning + bottom-tile indexing the MPC uses).
  {
    struct R { uint64_t lo, hi; };
    const R ranges[] = {
        {0xffffffffff00ULL, 0xffffffffffffULL},  // 256,  depth 8
        {0xfffffffffc00ULL, 0xffffffffffffULL},  // 1024, depth 10
        {0xfffffffffff0ULL, 0xffffffffffffULL},  // 16,   depth 4
    };
    const int heights[] = {1, 2, 3, 4};
    bool ok = true;
    for (const R& r : ranges) {
      uint64_t diff = r.lo ^ r.hi;
      int split = -1;
      for (int bpos = 47; bpos >= 0; --bpos)
        if ((diff >> bpos) & 1) { split = bpos; break; }
      for (int th : heights) {
        if (split < 0 || split + 1 < th) continue;
        for (const proto::Value* sh : {&split0, &split1}) {
          if (!VerifyRecursiveCachePlain(sha, ref::FillSeed(0xab), *sh, r.lo, r.hi,
                                         th)) {
            ok = false;
            std::printf("  recursive-cache mismatch range[%llx,%llx] th=%d\n",
                        static_cast<unsigned long long>(r.lo),
                        static_cast<unsigned long long>(r.hi), th);
          }
        }
      }
    }
    std::printf("recursive tiled cache (ranges x heights x splits): %s\n",
                ok ? "PASS" : "FAIL");
    if (!ok) ++failures;
  }

  std::printf("%s\n",
              failures == 0 ? "circuit verify: OK" : "circuit verify: FAILED");
  return failures == 0 ? 0 : 1;
}
