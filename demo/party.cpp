// One party of the maliciously-secure two-party derivation. Party 1 is the emp
// garbler (ALICE) and listens; party 2 is the evaluator (BOB) and connects to
// the peer. Each supplies only its own seed share.
//
// The index argument is an I-spec: a single 48-bit hex index ("64") or an
// inclusive hex range ("64-c8"). A range is evaluated under ONE session: all
// indices are computed (garbled+evaluated) with NOTHING revealed, then all are
// revealed -- so the one-time setup (COT mesh + input authentication) is paid
// once and amortized. On success a single index prints "RESULT <hex>"; a range
// prints one "RESULT <I> <hex>" line per index. The setup/compute/reveal time
// split is printed to stderr.
#include <emp-tool/emp-tool.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <string>
#include <vector>

#include "../run/derive.h"
#include "../util/hex.h"

// SetTransportTimeout bounds how long any blocking recv/send on the connected
// socket waits, so a stalled or dead-but-open peer aborts the run (emp surfaces
// the timed-out recv as a clean error/exit) instead of hanging forever. It is a
// per-call inactivity timeout, generous by default so it never trips on a
// legitimate slow phase; override the seconds via SHACHAIN2PC_TIMEOUT_SECS
// (0 disables it).
static void SetTransportTimeout(emp::NetIO* io) {
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

// ParseIndexSpec parses the I-spec: a single 48-bit hex index ("64") or an
// inclusive hex range ("64-c8"). Sets *is_range. Throws (clean abort) on a
// malformed spec, LO>HI, or an over-large range.
static std::vector<uint64_t> ParseIndexSpec(const char* spec, bool* is_range) {
  std::string s(spec);
  std::size_t dash = s.find('-');
  std::vector<uint64_t> out;
  if (dash == std::string::npos) {
    *is_range = false;
    out.push_back(shachain2pc::util::FromHexU48(s));
    return out;
  }
  *is_range = true;
  std::string lo_s = s.substr(0, dash);
  std::string hi_s = s.substr(dash + 1);
  if (lo_s.empty() || hi_s.empty())
    throw std::runtime_error("range must be LO-HI (both hex)");
  uint64_t lo = shachain2pc::util::FromHexU48(lo_s);
  uint64_t hi = shachain2pc::util::FromHexU48(hi_s);
  if (lo > hi) throw std::runtime_error("range LO must be <= HI");
  uint64_t count = hi - lo + 1;
  const uint64_t kMaxBatch = 100000;
  if (count > kMaxBatch)
    throw std::runtime_error("range too large (max 100000 indices)");
  out.reserve(count);
  for (uint64_t i = lo;; ++i) {
    out.push_back(i);
    if (i == hi) break;
  }
  return out;
}

int main(int argc, char** argv) {
  if (argc < 5) {
    std::fprintf(
        stderr,
        "usage: %s <1|2> <port> <I_spec> <share_hex> [peer_ip]\n"
        "  1 = ALICE (garbler, listens), 2 = BOB (evaluator, connects)\n"
        "  I_spec = single hex index (\"64\") or inclusive hex range "
        "(\"64-c8\")\n",
        argv[0]);
    return 2;
  }
  using namespace shachain2pc;
  int party = std::atoi(argv[1]);
  int port = std::atoi(argv[2]);
  std::vector<uint64_t> indices;
  bool is_range = false;
  protocol::Value share{};
  try {
    if (party != run::kAlice && party != run::kBob) {
      throw std::runtime_error("party must be 1 or 2");
    }
    if (port <= 0 || port > 65535) {
      throw std::runtime_error("port must be in 1..65535");
    }
    indices = ParseIndexSpec(argv[3], &is_range);
    share = util::FromHex32(argv[4]);
  } catch (const std::exception& e) {
    std::fprintf(stderr, "ABORT %s\n", e.what());
    return 1;
  }
  const char* peer = argc > 5 ? argv[5] : "127.0.0.1";

  const char* addr = (party == run::kAlice) ? nullptr : peer;
  // quiet=true: keep stdout clean (only RESULT lines) -- emp's NetIO otherwise
  // prints "connected" and a network-stats block to stdout.
  emp::NetIO* io = new emp::NetIO(addr, port, /*quiet=*/true);
  SetTransportTimeout(io);  // bound blocking recv/send so a stalled peer aborts
  ThreadPool pool(run::kThreads);  // session-local compute parallelism (global type)
  try {
    // Block-chunking mode (single index only): SHACHAIN2PC_CHUNK_BLOCKS=N runs the
    // derivation as a chain of N-block chunks, carrying the authenticated
    // intermediate, to cap the memory peak. Reports per-chunk timing + net rounds.
    if (const char* ce = std::getenv("SHACHAIN2PC_CHUNK_BLOCKS")) {
      int chunk_blocks = std::atoi(ce);
      if (chunk_blocks > 0) {
        if (is_range) {
          throw std::runtime_error(
              "SHACHAIN2PC_CHUNK_BLOCKS is single-index only (no range)");
        }
        // SHACHAIN2PC_TAMPER=<chunk> (TEST ONLY): garble a steered flip in that
        // chunk to confirm authenticated garbling aborts instead of revealing it.
        int tamper_chunk = -1;
        if (const char* te = std::getenv("SHACHAIN2PC_TAMPER")) {
          tamper_chunk = std::atoi(te);
        }
        run::ChunkTiming ct;
        protocol::Value out = run::RunDerivationChunked(
            io, &pool, party, indices[0], share, chunk_blocks, ct, tamper_chunk);
        delete io;
        std::printf("RESULT %s\n", util::ToHex(out).c_str());
        std::fprintf(stderr, "TIMING setup            %9.4f s\n", ct.setup_s);
        for (std::size_t k = 0; k < ct.chunk_s.size(); ++k) {
          std::fprintf(stderr, "TIMING chunk[%3zu]       %9.4f s\n", k,
                       ct.chunk_s[k]);
        }
        std::fprintf(stderr,
                     "TIMING compute total    %9.4f s   (%d chunks x %d blocks)\n",
                     ct.chunk_total_s(), ct.num_chunks, ct.blocks_per_chunk);
        std::fprintf(stderr, "TIMING reveal           %9.4f s\n", ct.reveal_s);
        std::fprintf(stderr, "TIMING grand-total      %9.4f s\n",
                     ct.setup_s + ct.chunk_total_s() + ct.reveal_s);
        std::fprintf(stderr, "NET   rounds=%llu sent=%llu recv=%llu (bytes)\n",
                     static_cast<unsigned long long>(ct.rounds),
                     static_cast<unsigned long long>(ct.bytes_sent),
                     static_cast<unsigned long long>(ct.bytes_recv));
        return 0;
      }
    }
    run::BatchTiming timing;
    std::vector<protocol::Value> outs =
        run::RunDerivationBatch(io, &pool, party, indices, share, timing);
    delete io;

    // Results on stdout. A single index keeps the original "RESULT <hex>" line
    // (backward compatible); a range prints one "RESULT <I> <hex>" per index.
    if (is_range) {
      for (std::size_t k = 0; k < indices.size(); ++k) {
        std::printf("RESULT %012llx %s\n",
                    static_cast<unsigned long long>(indices[k]),
                    util::ToHex(outs[k]).c_str());
      }
    } else {
      std::printf("RESULT %s\n", util::ToHex(outs[0]).c_str());
    }

    // Time split on stderr (stdout stays clean for scripting): one-time setup,
    // then per-index compute + reveal, then the totals.
    std::fprintf(stderr, "TIMING setup            %9.4f s\n", timing.setup_s);
    for (std::size_t k = 0; k < indices.size(); ++k) {
      std::fprintf(stderr,
                   "TIMING I=%012llx  compute %9.4f s   reveal %9.4f s\n",
                   static_cast<unsigned long long>(indices[k]),
                   timing.compute_s[k], timing.reveal_s[k]);
    }
    std::fprintf(stderr,
                 "TIMING total            compute %9.4f s   reveal %9.4f s\n",
                 timing.compute_total_s(), timing.reveal_total_s());
    std::fprintf(stderr,
                 "TIMING grand-total      %9.4f s   (setup+compute+reveal)\n",
                 timing.setup_s + timing.compute_total_s() +
                     timing.reveal_total_s());
    return 0;
  } catch (const std::exception& e) {
    delete io;
    std::fprintf(stderr, "ABORT %s\n", e.what());
    return 1;
  }
}
