#include "bouncer/signing.hpp"

#include "bouncer/hash.hpp"

#if defined(__APPLE__) && __has_include(<CommonCrypto/CommonHMAC.h>)
#include <CommonCrypto/CommonHMAC.h>
#define BOUNCER_HAS_COMMONCRYPTO 1
#endif

namespace bouncer {
namespace {

constexpr const char *algorithm = "bb-hmac-sha256-v1";

std::string key_id_from_secret(std::string_view secret_key) {
  return stable_hash_hex(std::string("key-id|") + std::string(secret_key));
}

std::string mac_hex(std::string_view payload_json,
                    std::string_view secret_key) {
#if defined(BOUNCER_HAS_COMMONCRYPTO)
  auto hex_encode = [](const unsigned char *bytes, std::size_t size) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(size * 2);
    for (std::size_t i = 0; i < size; ++i) {
      const unsigned char byte = bytes[i];
      out.push_back(digits[byte >> 4]);
      out.push_back(digits[byte & 0x0f]);
    }
    return out;
  };

  unsigned char digest[CC_SHA256_DIGEST_LENGTH];
  CCHmac(kCCHmacAlgSHA256, secret_key.data(), secret_key.size(),
         payload_json.data(), payload_json.size(), digest);
  return hex_encode(digest, CC_SHA256_DIGEST_LENGTH);
#else
  return stable_hash_hex(std::string(secret_key) + "|" +
                         std::string(payload_json));
#endif
}

} // namespace

SigningKey make_local_key(std::string_view seed) {
  SigningKey pair;
  pair.secret_key = stable_hash_hex(std::string("secret|") + std::string(seed));
  pair.key_id = key_id_from_secret(pair.secret_key);
  return pair;
}

std::string sign_payload(std::string_view payload_json,
                         std::string_view secret_key) {
  return mac_hex(payload_json, secret_key);
}

} // namespace bouncer