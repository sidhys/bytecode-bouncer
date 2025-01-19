#include "bouncer/hash.hpp"

#if defined(__APPLE__) && __has_include(<CommonCrypto/CommonDigest.h>)
#include <CommonCrypto/CommonDigest.h>
#define BOUNCER_HAS_COMMONCRYPTO 1
#endif

#include <iomanip>
#include <sstream>

namespace bouncer {
namespace {

std::string stable_hash_hex_bytes(const std::uint8_t *data, std::size_t size) {
#if defined(BOUNCER_HAS_COMMONCRYPTO)
  auto hex_bytes = [](const unsigned char *bytes, std::size_t count) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(count * 2);
    for (std::size_t i = 0; i < count; ++i) {
      const unsigned char byte = bytes[i];
      out.push_back(digits[byte >> 4]);
      out.push_back(digits[byte & 0x0f]);
    }
    return out;
  };

  unsigned char digest[CC_SHA256_DIGEST_LENGTH];
  CC_SHA256(data, static_cast<CC_LONG>(size), digest);
  return hex_bytes(digest, CC_SHA256_DIGEST_LENGTH);
#else
  constexpr std::uint64_t fnv_offset = 14695981039346656037ull;
  constexpr std::uint64_t fnv_prime = 1099511628211ull;

  auto hash_for = [&](std::uint64_t seed) {
    std::uint64_t hash = fnv_offset ^ seed;
    for (std::size_t i = 0; i < size; ++i) {
      hash ^= data[i];
      hash *= fnv_prime;
    }
    return hash;
  };

  auto hex64 = [](std::uint64_t value) {
    std::ostringstream out;
    out << std::hex << std::setfill('0') << std::setw(16) << value;
    return out.str();
  };

  const auto left = hash_for(0x243f6a8885a308d3ull);
  const auto right = hash_for(0x9e3779b97f4a7c15ull);
  return hex64(left) + hex64(right);
#endif
}

} // namespace

std::string stable_hash_hex(std::string_view text) {
  const auto *data = reinterpret_cast<const std::uint8_t *>(text.data());
  return stable_hash_hex_bytes(data, text.size());
}

std::string stable_hash_hex(const std::vector<std::uint8_t> &bytes) {
  return stable_hash_hex_bytes(bytes.data(), bytes.size());
}

} // namespace bouncer