#include "bouncer/signing.hpp"

#include "bouncer/hash.hpp"

namespace bouncer {
namespace {

std::string key_id_from_secret(std::string_view secret_key) {
  return stable_hash_hex(std::string("key-id|") + std::string(secret_key));
}

} // namespace

} // namespace bouncer