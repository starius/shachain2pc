// Minimal hex helpers for 32-byte values, shared by the CLIs.
#ifndef SHACHAIN2PC_UTIL_HEX_H
#define SHACHAIN2PC_UTIL_HEX_H

#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>

namespace shachain2pc::util {

inline std::string ToHex(const std::array<uint8_t, 32>& v) {
  static const char* d = "0123456789abcdef";
  std::string s;
  s.reserve(64);
  for (uint8_t b : v) {
    s.push_back(d[b >> 4]);
    s.push_back(d[b & 0xf]);
  }
  return s;
}

inline int NibbleVal(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  throw std::runtime_error(std::string("bad hex char '") + c + "'");
}

inline uint64_t FromHexU48(const std::string& s) {
  std::string hex = s;
  if (hex.size() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
    hex = hex.substr(2);
  }
  if (hex.empty() || hex.size() > 12) {
    throw std::runtime_error("FromHexU48: expected 1..12 hex chars");
  }
  uint64_t v = 0;
  for (char c : hex) {
    v = (v << 4) | static_cast<uint64_t>(NibbleVal(c));
  }
  return v;
}

inline std::array<uint8_t, 32> FromHex32(const std::string& s) {
  if (s.size() != 64) {
    throw std::runtime_error("FromHex32: expected 64 hex chars, got " +
                             std::to_string(s.size()));
  }
  std::array<uint8_t, 32> v{};
  for (int i = 0; i < 32; ++i) {
    v[i] = static_cast<uint8_t>((NibbleVal(s[2 * i]) << 4) | NibbleVal(s[2 * i + 1]));
  }
  return v;
}

}  // namespace shachain2pc::util

#endif  // SHACHAIN2PC_UTIL_HEX_H
