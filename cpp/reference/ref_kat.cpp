// Known-answer test for the single-party reference, against the published
// BOLT-03 generation vectors. Exit code 0 on success.
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

#include "shachain_ref.h"

namespace ref = shachain2pc::reference;

static std::string hex(const ref::Hash& h) {
  static const char* d = "0123456789abcdef";
  std::string s;
  for (uint8_t b : h) {
    s.push_back(d[b >> 4]);
    s.push_back(d[b & 0xf]);
  }
  return s;
}

struct Vec {
  const char* name;
  uint8_t seed_fill;
  uint64_t index;
  const char* output;
};

int main() {
  const Vec vectors[] = {
      {"0 final node", 0x00, 0xffffffffffffULL,
       "02a40c85b6f28da08dfdbe0926c53fab2de6d28c10301f8f7c4073d5e42e3148"},
      {"FF final node", 0xff, 0xffffffffffffULL,
       "7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc"},
      {"FF alternate bits 1", 0xff, 0xaaaaaaaaaaaULL,
       "56f4008fb007ca9acf0e15b054d5c9fd12ee06cea347914ddbaed70d1c13a528"},
      {"FF alternate bits 2", 0xff, 0x555555555555ULL,
       "9015daaeb06dba4ccc05b91b2f73bd54405f2be9f217fbacd3c5ac2e62327d31"},
      {"01 last nontrivial node", 0x01, 1ULL,
       "915c75942a26bb3a433a8ce2cb0427c29ec6c1775cfc78328b57f6ba7bfeaa9c"},
  };

  int failures = 0;
  for (const Vec& v : vectors) {
    ref::Hash got = ref::GenerateFromSeed(ref::FillSeed(v.seed_fill), v.index);
    std::string g = hex(got);
    bool ok = (g == v.output);
    std::printf("%-26s %s\n", v.name, ok ? "PASS" : "FAIL");
    if (!ok) {
      std::printf("   got  %s\n   want %s\n", g.c_str(), v.output);
      ++failures;
    }
  }
  std::printf("%s\n", failures == 0 ? "reference KAT: OK" : "reference KAT: FAILED");
  return failures == 0 ? 0 : 1;
}
