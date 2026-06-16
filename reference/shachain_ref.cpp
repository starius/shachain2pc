#include "shachain_ref.h"

#include <openssl/sha.h>

namespace shachain2pc::reference {

Hash GenerateFromSeed(const Hash& seed, uint64_t I) {
  Hash p = seed;
  for (int b = kMaxHeight - 1; b >= 0; --b) {
    if (((I >> b) & 1) == 0) {
      continue;
    }
    p[b / 8] ^= static_cast<uint8_t>(1u << (b % 8));
    Hash out;
    SHA256(p.data(), p.size(), out.data());
    p = out;
  }
  return p;
}

Hash Combine(const Hash& a, const Hash& b) {
  Hash r;
  for (size_t i = 0; i < r.size(); ++i) {
    r[i] = a[i] ^ b[i];
  }
  return r;
}

Hash FillSeed(uint8_t b) {
  Hash s;
  s.fill(b);
  return s;
}

}  // namespace shachain2pc::reference
