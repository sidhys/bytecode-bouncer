#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace bouncer {

std::string stable_hash_hex(std::string_view text);
std::string stable_hash_hex(const std::vector<std::uint8_t> &bytes);
std::string stable_hash_hex(const std::uint8_t *data, std::size_t size);
std::vector<std::uint8_t> bytes_from_text(std::string_view text);

std::optional<std::string> sha256_file_hex(const std::string &path);
std::string hmac_sha256_hex(std::string_view key, std::string_view message);
bool constant_time_equals(std::string_view a, std::string_view b);

} // namespace bouncer
