#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace bouncer {

std::string stable_hash_hex(std::string_view text);

} // namespace bouncer
