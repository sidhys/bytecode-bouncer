#pragma once

#include <string>
#include <string_view>

namespace bouncer {

struct SigningKey {
  std::string key_id;
  std::string secret_key;
};

SigningKey make_local_key(std::string_view seed);

} // namespace bouncer