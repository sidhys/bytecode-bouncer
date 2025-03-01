#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace bouncer {

std::string stable_hash_hex(std::string_view text);
std::string stable_hash_hex(const std::vector<std::uint8_t> &bytes);
std::vector<std::uint8_t> bytes_from_text(std::string_view text);

} // namespace bouncer
