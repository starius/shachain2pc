#include <emp-tool/emp-tool.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>
#include <unistd.h>

#include "emp-ag2pc/helper.h"

namespace {

constexpr int kAlice = 1;
constexpr int kBob = 2;
constexpr int kStreams = 3;
constexpr int kPartialBytes = 5;

struct FullBlockSet {
  emp::block data[2];
};

struct PartialBlockSet {
  emp::block data[3];
};

emp::block Block(uint64_t high, uint64_t low) {
  return emp::makeBlock(high, low);
}

std::array<uint8_t, 8> RawPayload(int party, int stream_id) {
  uint8_t tag = party == kAlice ? 0xa1 : 0xb2;
  return {tag,
          static_cast<uint8_t>(stream_id),
          static_cast<uint8_t>(0x10 + stream_id),
          static_cast<uint8_t>(0x20 + stream_id),
          static_cast<uint8_t>(0x30 + stream_id),
          static_cast<uint8_t>(0x40 + stream_id),
          static_cast<uint8_t>(0x50 + stream_id),
          static_cast<uint8_t>(0x60 + stream_id)};
}

FullBlockSet FullBlocks(int party, int stream_id) {
  FullBlockSet blocks;
  for (uint64_t i = 0; i < 2; ++i) {
    uint64_t role_tag = static_cast<uint64_t>(party);
    blocks.data[i] = Block(
        0xf000000000000000ULL | (role_tag << 16) |
            (static_cast<uint64_t>(stream_id) << 8) | i,
        0x0f00000000000000ULL | (role_tag << 16) |
            (static_cast<uint64_t>(stream_id) << 8) | i);
  }
  return blocks;
}

PartialBlockSet PartialBlocks(int party, int stream_id) {
  PartialBlockSet blocks;
  for (uint64_t i = 0; i < 3; ++i) {
    uint64_t role_tag = static_cast<uint64_t>(party);
    blocks.data[i] = Block(
        0xc000000000000000ULL | (role_tag << 16) |
            (static_cast<uint64_t>(stream_id) << 8) | i,
        0x0c00000000000000ULL | (role_tag << 16) |
            (static_cast<uint64_t>(stream_id) << 8) | i);
  }
  return blocks;
}

std::vector<uint8_t> BoolPatternBytes(int party, int stream_id,
                                      int ptr_mod8) {
  std::vector<uint8_t> out;
  int role_bias = party;
  for (int i = 0; i < 17 + stream_id; ++i) {
    out.push_back(((i * 5 + stream_id + role_bias + ptr_mod8) % 7) < 3 ? 1
                                                                        : 0);
  }
  return out;
}

void FillBoolArray(bool* out, const std::vector<uint8_t>& values) {
  for (size_t i = 0; i < values.size(); ++i) {
    out[i] = values[i] != 0;
  }
}

void ExpectBytes(const void* actual, const void* expected, size_t len,
                 const char* label) {
  if (std::memcmp(actual, expected, len) != 0) {
    throw std::runtime_error(std::string("mismatch: ") + label);
  }
}

void ExpectBlocks(const emp::block* actual, const emp::block* expected,
                  size_t count, const char* label) {
  for (size_t i = 0; i < count; ++i) {
    ExpectBytes(&actual[i], &expected[i], sizeof(emp::block), label);
  }
}

void ExpectPartialBlocks(const emp::block* actual, const emp::block* expected,
                         size_t count, const char* label) {
  for (size_t i = 0; i < count; ++i) {
    ExpectBytes(&actual[i], &expected[i], kPartialBytes, label);
  }
}

void ExpectBools(const bool* actual, const std::vector<uint8_t>& expected,
                 const char* label) {
  for (size_t i = 0; i < expected.size(); ++i) {
    if (static_cast<uint8_t>(actual[i] ? 1 : 0) != expected[i]) {
      throw std::runtime_error(std::string("bool mismatch: ") + label);
    }
  }
}

void SendBoolBytes(emp::NetIO* io, int party, int stream_id, int ptr_mod8) {
  std::vector<uint8_t> values = BoolPatternBytes(party, stream_id, ptr_mod8);
  alignas(8) std::array<uint8_t, 64> storage{};
  bool* bits = reinterpret_cast<bool*>(storage.data() + ptr_mod8);
  FillBoolArray(bits, values);
  io->send_bool(bits, values.size());
}

void RecvBoolBytes(emp::NetIO* io, int party, int stream_id, int ptr_mod8) {
  std::vector<uint8_t> expected = BoolPatternBytes(party, stream_id, ptr_mod8);
  alignas(8) std::array<uint8_t, 64> storage{};
  bool* bits = reinterpret_cast<bool*>(storage.data() + ptr_mod8);
  io->recv_bool(bits, expected.size());
  ExpectBools(bits, expected, "bool");
}

void SendFullBlocks(emp::NetIO* io, int party, int stream_id) {
  FullBlockSet blocks = FullBlocks(party, stream_id);
  io->send_block(blocks.data, 2);
}

void RecvFullBlocks(emp::NetIO* io, int party, int stream_id) {
  FullBlockSet expected = FullBlocks(party, stream_id);
  FullBlockSet actual;
  io->recv_block(actual.data, 2);
  ExpectBlocks(actual.data, expected.data, 2, "full block");
}

void SendPartialBlocks(emp::NetIO* io, int party, int stream_id) {
  PartialBlockSet blocks = PartialBlocks(party, stream_id);
  emp::send_partial_block<emp::NetIO, kPartialBytes>(
      io, blocks.data, 3);
}

void RecvPartialBlocks(emp::NetIO* io, int party, int stream_id) {
  PartialBlockSet expected = PartialBlocks(party, stream_id);
  PartialBlockSet actual;
  for (emp::block& block : actual.data) block = Block(0, 0);
  emp::recv_partial_block<emp::NetIO, kPartialBytes>(
      io, actual.data, 3);
  ExpectPartialBlocks(actual.data, expected.data, 3, "partial block");
}

void ExerciseStream(emp::NetIO* io, int party, int stream_id) {
  if (party == kAlice) {
    auto alice_raw = RawPayload(kAlice, stream_id);
    io->send_data(alice_raw.data(), alice_raw.size());
    io->flush();

    auto bob_raw = RawPayload(kBob, stream_id);
    std::array<uint8_t, 8> got_raw{};
    io->recv_data(got_raw.data(), got_raw.size());
    ExpectBytes(got_raw.data(), bob_raw.data(), got_raw.size(), "raw bob");

    SendFullBlocks(io, kAlice, stream_id);
    io->flush();
    RecvFullBlocks(io, kBob, stream_id);

    SendBoolBytes(io, kAlice, stream_id, 0);
    io->flush();
    RecvBoolBytes(io, kBob, stream_id, 0);

    SendBoolBytes(io, kAlice, stream_id, 1);
    io->flush();
    RecvBoolBytes(io, kBob, stream_id, 1);

    SendPartialBlocks(io, kAlice, stream_id);
    io->flush();
    RecvPartialBlocks(io, kBob, stream_id);
  } else {
    auto alice_raw = RawPayload(kAlice, stream_id);
    std::array<uint8_t, 8> got_raw{};
    io->recv_data(got_raw.data(), got_raw.size());
    ExpectBytes(got_raw.data(), alice_raw.data(), got_raw.size(),
                "raw alice");

    auto bob_raw = RawPayload(kBob, stream_id);
    io->send_data(bob_raw.data(), bob_raw.size());
    io->flush();

    RecvFullBlocks(io, kAlice, stream_id);
    SendFullBlocks(io, kBob, stream_id);
    io->flush();

    RecvBoolBytes(io, kAlice, stream_id, 0);
    SendBoolBytes(io, kBob, stream_id, 0);
    io->flush();

    RecvBoolBytes(io, kAlice, stream_id, 1);
    SendBoolBytes(io, kBob, stream_id, 1);
    io->flush();

    RecvPartialBlocks(io, kAlice, stream_id);
    SendPartialBlocks(io, kBob, stream_id);
    io->flush();
  }
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 3 || argc > 4) {
    std::fprintf(stderr, "usage: %s <1|2> <port> [peer_ip]\n", argv[0]);
    return 2;
  }

  int party = std::atoi(argv[1]);
  int port = std::atoi(argv[2]);
  const char* peer = argc > 3 ? argv[3] : "127.0.0.1";

  try {
    if (party != kAlice && party != kBob) {
      throw std::runtime_error("party must be 1 or 2");
    }
    if (port <= 0 || port > 65535) {
      throw std::runtime_error("port must be in 1..65535");
    }

    emp::NetIO main(party == kAlice ? nullptr : peer, port, true);
    usleep(1000);
    emp::NetIO fpre_io0(party == kAlice ? nullptr : peer, port, true);
    usleep(1000);
    emp::NetIO fpre_io2_0(party == kAlice ? nullptr : peer, port, true);

    emp::NetIO* streams[kStreams] = {&main, &fpre_io0, &fpre_io2_0};
    for (int i = 0; i < kStreams; ++i) {
      ExerciseStream(streams[i], party, i);
    }
  } catch (const std::exception& e) {
    std::fprintf(stderr, "emp_wire_probe: %s\n", e.what());
    return 1;
  }
  return 0;
}
