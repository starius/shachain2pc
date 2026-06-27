#include <emp-tool/emp-tool.h>
#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "emp-ag2pc/helper.h"

#include "../protocol/circuit_gen.h"
#include "../reference/shachain_ref.h"
#include "../run/derive.h"

namespace {

constexpr const char* kSchema = "shachain2pc.compat_probe.v1";
constexpr const char* kCompatSpec = "compat/v1/spec.toml";

class CaptureIO : public emp::IOChannel<CaptureIO> {
 public:
  bool is_server = false;
  std::string addr;
  int port = 0;
  std::vector<uint8_t> sent;
  std::vector<uint8_t> recv;
  size_t recv_pos = 0;

  void send_data_internal(const void* data, size_t len) {
    const auto* p = static_cast<const uint8_t*>(data);
    sent.insert(sent.end(), p, p + len);
  }

  void recv_data_internal(void* data, size_t len) {
    if (recv_pos + len > recv.size()) {
      throw std::runtime_error("CaptureIO: recv underflow");
    }
    std::memcpy(data, recv.data() + recv_pos, len);
    recv_pos += len;
  }

  void flush() {}
};

static_assert(emp::C2PC<CaptureIO>::SSP == 5,
              "compat v1 assumes EMP ag2pc SSP is 5 bytes");
static_assert(emp::Fpre<CaptureIO>::THDS == 1,
              "compat v1 assumes EMP Fpre uses one thread");

std::string HexBytes(const uint8_t* data, size_t len) {
  static const char* d = "0123456789abcdef";
  std::string out;
  out.reserve(len * 2);
  for (size_t i = 0; i < len; ++i) {
    out.push_back(d[data[i] >> 4]);
    out.push_back(d[data[i] & 0x0f]);
  }
  return out;
}

std::string HexBytes(const std::vector<uint8_t>& v) {
  return HexBytes(v.data(), v.size());
}

template <size_t N>
std::string HexBytes(const std::array<uint8_t, N>& v) {
  return HexBytes(v.data(), v.size());
}

std::string HexBlock(const emp::block& b) {
  std::array<uint8_t, 16> bytes{};
  std::memcpy(bytes.data(), &b, bytes.size());
  return HexBytes(bytes);
}

std::string HexString(const std::string& s) {
  return HexBytes(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

std::string JsonQuote(const std::string& s) {
  std::ostringstream out;
  out << '"';
  for (unsigned char c : s) {
    switch (c) {
      case '"':
        out << "\\\"";
        break;
      case '\\':
        out << "\\\\";
        break;
      case '\b':
        out << "\\b";
        break;
      case '\f':
        out << "\\f";
        break;
      case '\n':
        out << "\\n";
        break;
      case '\r':
        out << "\\r";
        break;
      case '\t':
        out << "\\t";
        break;
      default:
        if (c < 0x20) {
          out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
              << static_cast<int>(c) << std::dec << std::setfill(' ');
        } else {
          out << static_cast<char>(c);
        }
    }
  }
  out << '"';
  return out.str();
}

std::string JsonHex(const std::string& hex) { return JsonQuote(hex); }

void Emit(const std::string& probe, const std::string& case_name,
          const std::string& inputs_json, const std::string& outputs_json) {
  std::cout << "{\"schema\":" << JsonQuote(kSchema)
            << ",\"probe\":" << JsonQuote(probe)
            << ",\"case\":" << JsonQuote(case_name)
            << ",\"compat_spec\":" << JsonQuote(kCompatSpec)
            << ",\"inputs\":" << inputs_json << ",\"outputs\":"
            << outputs_json << "}\n";
}

emp::block Block(uint64_t high, uint64_t low) {
  return emp::makeBlock(high, low);
}

emp::BigInt BigIntFromU64(uint64_t v) {
  std::array<uint8_t, 8> bytes{};
  for (int i = 7; i >= 0; --i) {
    bytes[static_cast<size_t>(i)] = static_cast<uint8_t>(v & 0xff);
    v >>= 8;
  }
  emp::BigInt n;
  n.from_bin(bytes.data(), static_cast<int>(bytes.size()));
  return n;
}

std::string PointBytes(emp::Point& p) {
  const size_t len = p.size();
  std::vector<uint8_t> bytes(len);
  p.to_bin(bytes.data(), bytes.size());
  return HexBytes(bytes);
}

std::string SendPointBytes(emp::Point& p) {
  CaptureIO io;
  io.send_pt(&p);
  return HexBytes(io.sent);
}

std::string BoolPatternJson(const bool* values, size_t len) {
  std::ostringstream out;
  out << '[';
  for (size_t i = 0; i < len; ++i) {
    if (i) out << ',';
    out << (values[i] ? "true" : "false");
  }
  out << ']';
  return out.str();
}

std::string BlockArrayJson(const emp::block* blocks, size_t len) {
  std::ostringstream out;
  out << '[';
  for (size_t i = 0; i < len; ++i) {
    if (i) out << ',';
    out << JsonHex(HexBlock(blocks[i]));
  }
  out << ']';
  return out.str();
}

int CountGates(const shachain2pc::protocol::Circuit& c,
               shachain2pc::protocol::Gate::Type type) {
  return static_cast<int>(
      std::count_if(c.gates.begin(), c.gates.end(),
                    [type](const shachain2pc::protocol::Gate& g) {
                      return g.type == type;
                    }));
}

std::string HexU48(uint64_t v) {
  std::ostringstream out;
  out << std::hex << std::nouppercase << std::setw(12) << std::setfill('0')
      << v;
  return out.str();
}

std::string ValueHex(const shachain2pc::reference::Hash& h) {
  return HexBytes(h.data(), h.size());
}

void ProbeEmpBlock() {
  struct Case {
    const char* name;
    uint64_t high;
    uint64_t low;
  };
  const Case cases[] = {
      {"zero", 0, 0},
      {"pattern", 0x0102030405060708ULL, 0x1112131415161718ULL},
      {"lsb", 0, 1},
      {"all_ones", 0xffffffffffffffffULL, 0xffffffffffffffffULL},
  };
  for (const auto& c : cases) {
    emp::block b = Block(c.high, c.low);
    emp::block sig = emp::sigma(b);
    emp::block x = b ^ Block(0xfeedfacecafebeefULL, 0x0123456789abcdefULL);
    std::ostringstream in;
    in << "{\"high\":\"" << std::hex << c.high << "\",\"low\":\"" << c.low
       << "\"}";
    std::ostringstream out;
    out << "{\"block\":" << JsonHex(HexBlock(b))
        << ",\"get_lsb\":" << (emp::getLSB(b) ? "true" : "false")
        << ",\"sigma\":" << JsonHex(HexBlock(sig))
        << ",\"xor_probe\":" << JsonHex(HexBlock(x)) << "}";
    Emit("emp_block", c.name, in.str(), out.str());
  }
}

void ProbeEmpBool() {
  for (size_t len : {size_t{7}, size_t{8}, size_t{9}, size_t{15}, size_t{16},
                     size_t{17}}) {
    for (size_t offset : {size_t{0}, size_t{1}}) {
      alignas(8) std::array<uint8_t, 64> storage{};
      bool* bits = reinterpret_cast<bool*>(storage.data() + offset);
      for (size_t i = 0; i < len; ++i) bits[i] = ((i * 5 + len) % 7) < 3;
      CaptureIO io;
      io.send_bool(bits, len);
      std::ostringstream in;
      in << "{\"len\":" << len << ",\"offset\":" << offset
         << ",\"ptr_mod8\":"
         << (reinterpret_cast<uintptr_t>(bits) % 8)
         << ",\"bits\":" << BoolPatternJson(bits, len) << "}";
      std::ostringstream out;
      out << "{\"sent\":" << JsonHex(HexBytes(io.sent)) << "}";
      Emit("emp_bool", "send_bool", in.str(), out.str());
    }
  }
}

void ProbePartialBlock() {
  emp::block blocks[] = {
      Block(0x0102030405060708ULL, 0x1112131415161718ULL),
      Block(0x2122232425262728ULL, 0x3132333435363738ULL),
      Block(0xffffffffffffffffULL, 0x0000000000000001ULL),
  };
  CaptureIO io;
  emp::send_partial_block<CaptureIO, 5>(&io, blocks,
                                        static_cast<int>(std::size(blocks)));
  std::ostringstream in;
  in << "{\"blocks\":" << BlockArrayJson(blocks, std::size(blocks))
     << ",\"partial_bytes\":5}";
  std::ostringstream out;
  out << "{\"sent\":" << JsonHex(HexBytes(io.sent)) << "}";
  Emit("emp_partial_block", "send_partial_block_5", in.str(), out.str());
}

void ProbeHashPrpPrg() {
  {
    std::array<uint8_t, emp::Hash::DIGEST_SIZE> dg{};
    emp::Hash::hash_once(dg.data(), "", 0);
    Emit("emp_hash", "hash_once_empty", "{\"message_hex\":\"\"}",
         "{\"sha256\":" + JsonHex(HexBytes(dg)) + "}");
  }

  {
    const std::string msg = "shachain2pc compat probe";
    std::array<uint8_t, emp::Hash::DIGEST_SIZE> dg{};
    emp::Hash::hash_once(dg.data(), msg.data(), static_cast<int>(msg.size()));
    std::ostringstream in;
    in << "{\"message_hex\":" << JsonHex(HexString(msg)) << "}";
    std::ostringstream out;
    out << "{\"sha256\":" << JsonHex(HexBytes(dg)) << "}";
    Emit("emp_hash", "hash_once", in.str(), out.str());
  }

  {
    std::string msg;
    for (int i = 0; i < 200; ++i) {
      msg.push_back(static_cast<char>((i * 37 + 11) & 0xff));
    }
    std::array<uint8_t, emp::Hash::DIGEST_SIZE> dg{};
    emp::Hash::hash_once(dg.data(), msg.data(), static_cast<int>(msg.size()));
    std::ostringstream in;
    in << "{\"message_hex\":" << JsonHex(HexString(msg)) << "}";
    std::ostringstream out;
    out << "{\"sha256\":" << JsonHex(HexBytes(dg)) << "}";
    Emit("emp_hash", "hash_once_200_bytes", in.str(), out.str());
  }

  {
    emp::PRP prp_zero;
    emp::block data[3] = {
        Block(0, 0),
        Block(0x0102030405060708ULL, 0x1112131415161718ULL),
        Block(0xffffffffffffffffULL, 0x0123456789abcdefULL),
    };
    emp::block before[3];
    std::memcpy(before, data, sizeof(data));
    prp_zero.permute_block(data, 3);
    std::ostringstream in;
    in << "{\"key\":" << JsonHex(HexBlock(Block(0, 0)))
       << ",\"blocks\":" << BlockArrayJson(before, 3) << "}";
    std::ostringstream out;
    out << "{\"permuted\":" << BlockArrayJson(data, 3) << "}";
    Emit("emp_prp", "zero_key", in.str(), out.str());
  }

  {
    emp::block key = Block(0x0011223344556677ULL, 0x8899aabbccddeeffULL);
    emp::PRP prp_key(key);
    emp::block data[2] = {
        Block(0x1020304050607080ULL, 0x90a0b0c0d0e0f000ULL),
        Block(0x0f0e0d0c0b0a0908ULL, 0x0706050403020100ULL),
    };
    emp::block before[2];
    std::memcpy(before, data, sizeof(data));
    prp_key.permute_block(data, 2);
    std::ostringstream in;
    in << "{\"key\":" << JsonHex(HexBlock(key))
       << ",\"blocks\":" << BlockArrayJson(before, 2) << "}";
    std::ostringstream out;
    out << "{\"permuted\":" << BlockArrayJson(data, 2) << "}";
    Emit("emp_prp", "fixed_key", in.str(), out.str());
  }

  {
    emp::block seed = Block(0x0a0b0c0d0e0f1011ULL, 0x1213141516171819ULL);
    emp::PRG prg(&seed, 0x4242);
    emp::block blocks[5];
    prg.random_block(blocks, static_cast<int>(std::size(blocks)));
    alignas(16) std::array<uint8_t, 23> bytes{};
    prg.random_data(bytes.data(), static_cast<int>(bytes.size()));
    alignas(16) bool bools[17];
    prg.random_bool(bools, 17);
    std::ostringstream in;
    in << "{\"seed\":" << JsonHex(HexBlock(seed)) << ",\"id\":16962}";
    std::ostringstream out;
    out << "{\"blocks\":" << BlockArrayJson(blocks, std::size(blocks))
        << ",\"random_data_23\":" << JsonHex(HexBytes(bytes))
        << ",\"random_bool_17\":" << BoolPatternJson(bools, 17) << "}";
    Emit("emp_prg", "seeded", in.str(), out.str());
  }
}

void EmpGarbleHashPreprocess(emp::block H[4][2], const emp::block& a,
                             const emp::block& b, const emp::block& delta,
                             uint64_t gate_index) {
  // Mirrors emp-ag2pc/2pc.h C2PC::Hash(block H[4][2], ...)
  // at lines 470..488 in the pinned EMP source.
  emp::block A[2], B[2];
  A[0] = a;
  A[1] = a ^ delta;
  B[0] = b;
  B[1] = b ^ delta;
  A[0] = emp::sigma(A[0]);
  A[1] = emp::sigma(A[1]);
  B[0] = emp::sigma(emp::sigma(B[0]));
  B[1] = emp::sigma(emp::sigma(B[1]));

  H[0][1] = H[0][0] = A[0] ^ B[0];
  H[1][1] = H[1][0] = A[0] ^ B[1];
  H[2][1] = H[2][0] = A[1] ^ B[0];
  H[3][1] = H[3][0] = A[1] ^ B[1];
  for (uint64_t j = 0; j < 4; ++j) {
    H[j][0] = H[j][0] ^ emp::makeBlock(4 * gate_index + j, 0);
    H[j][1] = H[j][1] ^ emp::makeBlock(4 * gate_index + j, 1);
  }
  emp::PRP prp;
  prp.permute_block(reinterpret_cast<emp::block*>(H), 8);
}

void EmpGarbleHashOnline(emp::block H[2], emp::block a, emp::block b,
                         uint64_t gate_index, uint64_t row) {
  // Mirrors emp-ag2pc/2pc.h C2PC::Hash(block H[2], ...)
  // at lines 490..496 in the pinned EMP source.
  a = emp::sigma(a);
  b = emp::sigma(emp::sigma(b));
  H[0] = H[1] = a ^ b;
  H[0] = H[0] ^ emp::makeBlock(4 * gate_index + row, 0);
  H[1] = H[1] ^ emp::makeBlock(4 * gate_index + row, 1);
  emp::PRP prp;
  prp.permute_block(H, 2);
}

std::string GarbleHashMatrixJson(emp::block H[4][2]) {
  std::ostringstream out;
  out << '[';
  for (int r = 0; r < 4; ++r) {
    if (r) out << ',';
    out << '[' << JsonHex(HexBlock(H[r][0])) << ','
        << JsonHex(HexBlock(H[r][1])) << ']';
  }
  out << ']';
  return out.str();
}

void ProbeGarbleHash() {
  const emp::block a =
      Block(0x0011223344556677ULL, 0x8899aabbccddeeffULL);
  const emp::block b =
      Block(0x0f1e2d3c4b5a6978ULL, 0x8796a5b4c3d2e1f0ULL);
  const emp::block delta =
      Block(0xfedcba9876543210ULL, 0x0123456789abcdefULL);
  constexpr uint64_t gate_index = 12345;

  emp::block pre[4][2];
  EmpGarbleHashPreprocess(pre, a, b, delta, gate_index);
  std::ostringstream in;
  in << "{\"a\":" << JsonHex(HexBlock(a)) << ",\"b\":"
     << JsonHex(HexBlock(b)) << ",\"delta\":" << JsonHex(HexBlock(delta))
     << ",\"gate_index\":" << gate_index << "}";
  std::ostringstream out;
  out << "{\"source\":\"C2PC::Hash 4x2 composition from emp-ag2pc/2pc.h\","
      << "\"rows\":" << GarbleHashMatrixJson(pre) << "}";
  Emit("emp_garble_hash", "preprocess_4x2", in.str(), out.str());

  for (uint64_t row : {uint64_t{0}, uint64_t{1}, uint64_t{3}}) {
    emp::block online[2];
    EmpGarbleHashOnline(online, a, b, gate_index, row);
    std::ostringstream row_in;
    row_in << "{\"a\":" << JsonHex(HexBlock(a)) << ",\"b\":"
           << JsonHex(HexBlock(b)) << ",\"gate_index\":" << gate_index
           << ",\"row\":" << row << "}";
    std::ostringstream row_out;
    row_out << "{\"source\":\"C2PC::Hash 2-block composition from "
            << "emp-ag2pc/2pc.h\",\"blocks\":["
            << JsonHex(HexBlock(online[0])) << ','
            << JsonHex(HexBlock(online[1])) << "]}";
    Emit("emp_garble_hash", "online_row_" + std::to_string(row),
         row_in.str(), row_out.str());
  }
}

void ProbePointsAndOtco() {
  emp::Group group;
  for (uint64_t scalar : {uint64_t{1}, uint64_t{2}, uint64_t{7},
                          uint64_t{19}}) {
    emp::BigInt s = BigIntFromU64(scalar);
    emp::Point p = group.mul_gen(s);
    emp::block kdf1 = emp::Hash::KDF(p, 1);
    emp::block kdf42 = emp::Hash::KDF(p, 42);
    std::ostringstream in;
    in << "{\"scalar\":" << scalar << "}";
    std::ostringstream out;
    out << "{\"point\":" << JsonHex(PointBytes(p))
        << ",\"send_pt\":" << JsonHex(SendPointBytes(p))
        << ",\"kdf_id_1\":" << JsonHex(HexBlock(kdf1))
        << ",\"kdf_id_42\":" << JsonHex(HexBlock(kdf42)) << "}";
    Emit("emp_point", "mul_gen", in.str(), out.str());
  }

  // Deterministic OTCO fixture. This mirrors emp-ot/co.h with fixed sender and
  // receiver scalars instead of calling OTCO::send/recv, whose randomness is not
  // injectable. The point arithmetic, point encoding, and Hash::KDF calls are
  // still EMP's implementations.
  const int length = 4;
  emp::BigInt a = BigIntFromU64(7);
  emp::Point A = group.mul_gen(a);
  emp::Point AaInv = A.mul(a).inv();
  const uint64_t receiver_scalars[length] = {11, 13, 17, 19};
  const bool choices[length] = {false, true, true, false};
  emp::block data0[length] = {
      Block(0x1000000000000000ULL, 0x0000000000000001ULL),
      Block(0x1000000000000001ULL, 0x0000000000000002ULL),
      Block(0x1000000000000002ULL, 0x0000000000000003ULL),
      Block(0x1000000000000003ULL, 0x0000000000000004ULL),
  };
  emp::block data1[length] = {
      Block(0x2000000000000000ULL, 0x0000000000000011ULL),
      Block(0x2000000000000001ULL, 0x0000000000000012ULL),
      Block(0x2000000000000002ULL, 0x0000000000000013ULL),
      Block(0x2000000000000003ULL, 0x0000000000000014ULL),
  };

  std::ostringstream items;
  items << '[';
  for (int i = 0; i < length; ++i) {
    emp::BigInt bb = BigIntFromU64(receiver_scalars[i]);
    emp::Point B = group.mul_gen(bb);
    if (choices[i]) B = B.add(A);
    emp::Point sender_mask0_point = B.mul(a);
    emp::Point sender_mask1_point = sender_mask0_point.add(AaInv);
    emp::block mask0 = emp::Hash::KDF(sender_mask0_point, i);
    emp::block mask1 = emp::Hash::KDF(sender_mask1_point, i);
    emp::block ct0 = mask0 ^ data0[i];
    emp::block ct1 = mask1 ^ data1[i];
    emp::Point receiver_mask_point = A.mul(bb);
    emp::block receiver_mask = emp::Hash::KDF(receiver_mask_point, i);
    emp::block recovered = receiver_mask ^ (choices[i] ? ct1 : ct0);

    if (i) items << ',';
    items << "{\"i\":" << i << ",\"receiver_scalar\":"
          << receiver_scalars[i]
          << ",\"choice\":" << (choices[i] ? "true" : "false")
          << ",\"B_point\":" << JsonHex(PointBytes(B))
          << ",\"B_send_pt\":" << JsonHex(SendPointBytes(B))
          << ",\"mask0_point\":" << JsonHex(PointBytes(sender_mask0_point))
          << ",\"mask1_point\":" << JsonHex(PointBytes(sender_mask1_point))
          << ",\"mask0\":" << JsonHex(HexBlock(mask0))
          << ",\"mask1\":" << JsonHex(HexBlock(mask1))
          << ",\"data0\":" << JsonHex(HexBlock(data0[i]))
          << ",\"data1\":" << JsonHex(HexBlock(data1[i]))
          << ",\"ciphertext0\":" << JsonHex(HexBlock(ct0))
          << ",\"ciphertext1\":" << JsonHex(HexBlock(ct1))
          << ",\"ciphertext_pair_wire\":"
          << JsonHex(HexBlock(ct0) + HexBlock(ct1))
          << ",\"receiver_mask_point\":"
          << JsonHex(PointBytes(receiver_mask_point))
          << ",\"receiver_mask\":" << JsonHex(HexBlock(receiver_mask))
          << ",\"recovered\":" << JsonHex(HexBlock(recovered)) << "}";
  }
  items << ']';

  std::ostringstream in;
  in << "{\"protocol\":\"OTCO\",\"sender_scalar\":7,\"length\":" << length
     << "}";
  std::ostringstream out;
  out << "{\"A_point\":" << JsonHex(PointBytes(A))
      << ",\"A_send_pt\":" << JsonHex(SendPointBytes(A))
      << ",\"items\":" << items.str() << "}";
  Emit("emp_otco_transcript", "fixed_scalars_len4", in.str(), out.str());
}

int FpreBatchSize(int requested) {
  // Mirrors emp-ag2pc/fpre.h Fpre::set_batch_size in the pinned EMP source.
  // Constructing Fpre would open sockets, so this probe pins the formula and
  // static_asserts THDS above instead of instantiating the class.
  constexpr int thds = emp::Fpre<CaptureIO>::THDS;
  int size = std::max(requested, 320);
  return ((size + thds * 2 - 1) / (2 * thds)) * thds * 2;
}

int FpreBucketSize(int batch_size) {
  if (batch_size >= 280 * 1000) return 3;
  if (batch_size >= 3100) return 4;
  return 5;
}

void ProbeFpreParams() {
  std::ostringstream cases;
  cases << '[';
  bool first = true;
  for (int requested : {1, 319, 320, 3099, 3100, 279999, 280000}) {
    int batch = FpreBatchSize(requested);
    if (!first) cases << ',';
    first = false;
    cases << "{\"requested\":" << requested << ",\"batch_size\":" << batch
          << ",\"bucket_size\":" << FpreBucketSize(batch) << "}";
  }
  cases << ']';
  Emit("fpre_params", "thresholds", "{}", "{\"cases\":" + cases.str() + "}");
}

void ProbeCircuitDigest() {
  const uint64_t indices[] = {0x000000000000ULL, 0x000000000001ULL,
                              0x800000000000ULL, 0xaaaaaaaaaaaaULL,
                              0x555555555555ULL, 0xffffffffffffULL};
  for (uint64_t index : indices) {
    shachain2pc::protocol::Circuit c =
        shachain2pc::run::BuildCircuitForIndex(index);
    std::vector<int> gate_arr = shachain2pc::run::ToEmpGateArray(c);
    std::array<uint8_t, 32> dg = shachain2pc::run::CircuitDigest(c, gate_arr);
    const int ands = CountGates(c, shachain2pc::protocol::Gate::kAnd);
    const int xors = CountGates(c, shachain2pc::protocol::Gate::kXor);
    const int invs = CountGates(c, shachain2pc::protocol::Gate::kInv);
    std::ostringstream in;
    in << "{\"index_hex\":" << JsonQuote(HexU48(index)) << "}";
    std::ostringstream out;
    out << "{\"num_gate\":" << c.num_gate()
        << ",\"num_wire\":" << c.num_wire << ",\"n1\":" << c.n1
        << ",\"n2\":" << c.n2 << ",\"n3\":" << c.n3
        << ",\"and_gates\":" << ands << ",\"xor_gates\":" << xors
        << ",\"inv_gates\":" << invs
        << ",\"emp_gate_array_ints\":" << gate_arr.size()
        << ",\"digest\":" << JsonHex(HexBytes(dg))
        << ",\"fpre_batch_size\":" << FpreBatchSize(ands)
        << ",\"fpre_bucket_size\":" << FpreBucketSize(FpreBatchSize(ands))
        << "}";
    Emit("circuit_digest", HexU48(index), in.str(), out.str());
  }
}

void ProbeReference() {
  std::vector<shachain2pc::reference::Hash> seeds;
  seeds.push_back(shachain2pc::reference::FillSeed(0x00));
  seeds.push_back(shachain2pc::reference::FillSeed(0xff));
  shachain2pc::reference::Hash seq{};
  for (size_t i = 0; i < seq.size(); ++i) seq[i] = static_cast<uint8_t>(i);
  seeds.push_back(seq);

  const uint64_t indices[] = {0x000000000000ULL, 0x000000000001ULL,
                              0x800000000000ULL, 0xaaaaaaaaaaaaULL,
                              0x555555555555ULL, 0xffffffffffffULL};
  for (size_t si = 0; si < seeds.size(); ++si) {
    for (uint64_t index : indices) {
      shachain2pc::reference::Hash out =
          shachain2pc::reference::GenerateFromSeed(seeds[si], index);
      std::ostringstream in;
      in << "{\"seed_case\":" << si
         << ",\"seed\":" << JsonHex(ValueHex(seeds[si]))
         << ",\"index_hex\":" << JsonQuote(HexU48(index)) << "}";
      std::ostringstream outputs;
      outputs << "{\"value\":" << JsonHex(ValueHex(out)) << "}";
      Emit("shachain_reference", "generate_from_seed", in.str(),
           outputs.str());
    }
  }
}

}  // namespace

int main() {
  try {
    ProbeEmpBlock();
    ProbeEmpBool();
    ProbePartialBlock();
    ProbeHashPrpPrg();
    ProbeGarbleHash();
    ProbePointsAndOtco();
    ProbeFpreParams();
    ProbeCircuitDigest();
    ProbeReference();
  } catch (const std::exception& e) {
    std::cerr << "compat_probe: " << e.what() << "\n";
    return 1;
  }
  return 0;
}
