#include "bouncer/hash.hpp"

#include <array>
#include <cstring>
#include <fstream>
#include <sys/stat.h>

namespace bouncer {
namespace {

// one portable sha-256 for every platform. the previous build only used a
// real hash on macos and fell back to fnv-1a elsewhere, which is useless as
// an integrity check because collisions are trivial to construct.
struct Sha256 {
  std::uint32_t state[8];
  std::uint64_t bit_len = 0;
  std::uint8_t buffer[64];
  std::size_t buffer_len = 0;

  Sha256() {
    state[0] = 0x6a09e667;
    state[1] = 0xbb67ae85;
    state[2] = 0x3c6ef372;
    state[3] = 0xa54ff53a;
    state[4] = 0x510e527f;
    state[5] = 0x9b05688c;
    state[6] = 0x1f83d9ab;
    state[7] = 0x5be0cd19;
  }

  static std::uint32_t rotr(std::uint32_t value, unsigned bits) {
    return (value >> bits) | (value << (32 - bits));
  }

  void compress(const std::uint8_t block[64]) {
    static constexpr std::uint32_t k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
        0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
        0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
        0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
        0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
        0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
        0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
        0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

    std::uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
      w[i] = (std::uint32_t(block[i * 4]) << 24) |
             (std::uint32_t(block[i * 4 + 1]) << 16) |
             (std::uint32_t(block[i * 4 + 2]) << 8) |
             std::uint32_t(block[i * 4 + 3]);
    }
    for (int i = 16; i < 64; ++i) {
      const auto s0 =
          rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
      const auto s1 =
          rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    std::uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    std::uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
    for (int i = 0; i < 64; ++i) {
      const auto s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const auto ch = (e & f) ^ (~e & g);
      const auto temp1 = h + s1 + ch + k[i] + w[i];
      const auto s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const auto maj = (a & b) ^ (a & c) ^ (b & c);
      const auto temp2 = s0 + maj;
      h = g;
      g = f;
      f = e;
      e = d + temp1;
      d = c;
      c = b;
      b = a;
      a = temp1 + temp2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
  }

  void update(const std::uint8_t *data, std::size_t size) {
    bit_len += std::uint64_t(size) * 8;
    while (size > 0) {
      if (buffer_len == 0 && size >= 64) {
        compress(data);
        data += 64;
        size -= 64;
        continue;
      }
      const std::size_t take =
          size < (64 - buffer_len) ? size : (64 - buffer_len);
      std::memcpy(buffer + buffer_len, data, take);
      buffer_len += take;
      data += take;
      size -= take;
      if (buffer_len == 64) {
        compress(buffer);
        buffer_len = 0;
      }
    }
  }

  std::array<std::uint8_t, 32> finish() {
    const std::uint64_t total_bits = bit_len;
    const std::uint8_t pad = 0x80;
    const std::uint8_t zero = 0x00;
    update(&pad, 1);
    while (buffer_len != 56) {
      update(&zero, 1);
    }
    for (int i = 7; i >= 0; --i) {
      buffer[buffer_len++] = std::uint8_t(total_bits >> (i * 8));
    }
    compress(buffer);
    buffer_len = 0;

    std::array<std::uint8_t, 32> digest{};
    for (int i = 0; i < 8; ++i) {
      digest[i * 4] = std::uint8_t(state[i] >> 24);
      digest[i * 4 + 1] = std::uint8_t(state[i] >> 16);
      digest[i * 4 + 2] = std::uint8_t(state[i] >> 8);
      digest[i * 4 + 3] = std::uint8_t(state[i]);
    }
    return digest;
  }
};

std::string hex_encode(const std::uint8_t *bytes, std::size_t count) {
  static constexpr char digits[] = "0123456789abcdef";
  std::string out;
  out.reserve(count * 2);
  for (std::size_t i = 0; i < count; ++i) {
    out.push_back(digits[bytes[i] >> 4]);
    out.push_back(digits[bytes[i] & 0x0f]);
  }
  return out;
}

std::array<std::uint8_t, 32> sha256_digest(const std::uint8_t *data,
                                           std::size_t size) {
  Sha256 sha;
  sha.update(data, size);
  return sha.finish();
}

} // namespace

std::string stable_hash_hex(const std::uint8_t *data, std::size_t size) {
  const auto digest = sha256_digest(data, size);
  return hex_encode(digest.data(), digest.size());
}

std::string stable_hash_hex(std::string_view text) {
  return stable_hash_hex(reinterpret_cast<const std::uint8_t *>(text.data()),
                         text.size());
}

std::string stable_hash_hex(const std::vector<std::uint8_t> &bytes) {
  return stable_hash_hex(bytes.data(), bytes.size());
}

std::vector<std::uint8_t> bytes_from_text(std::string_view text) {
  return std::vector<std::uint8_t>(text.begin(), text.end());
}

std::optional<std::string> sha256_file_hex(const std::string &path) {
  struct stat status {};
  if (::stat(path.c_str(), &status) != 0 || !S_ISREG(status.st_mode)) {
    return std::nullopt;
  }
  std::ifstream input(path, std::ios::binary);
  if (!input) {
    return std::nullopt;
  }

  Sha256 sha;
  std::vector<char> buffer(1 << 16);
  while (true) {
    input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
    const auto got = input.gcount();
    if (got > 0) {
      sha.update(reinterpret_cast<const std::uint8_t *>(buffer.data()),
                 static_cast<std::size_t>(got));
    }
    if (got < static_cast<std::streamsize>(buffer.size())) {
      break;
    }
  }
  const auto digest = sha.finish();
  return hex_encode(digest.data(), digest.size());
}

std::string hmac_sha256_hex(std::string_view key, std::string_view message) {
  std::array<std::uint8_t, 64> block{};
  if (key.size() > block.size()) {
    const auto digest = sha256_digest(
        reinterpret_cast<const std::uint8_t *>(key.data()), key.size());
    std::memcpy(block.data(), digest.data(), digest.size());
  } else {
    std::memcpy(block.data(), key.data(), key.size());
  }

  std::array<std::uint8_t, 64> inner_pad{};
  std::array<std::uint8_t, 64> outer_pad{};
  for (std::size_t i = 0; i < block.size(); ++i) {
    inner_pad[i] = block[i] ^ 0x36;
    outer_pad[i] = block[i] ^ 0x5c;
  }

  Sha256 inner;
  inner.update(inner_pad.data(), inner_pad.size());
  inner.update(reinterpret_cast<const std::uint8_t *>(message.data()),
               message.size());
  const auto inner_digest = inner.finish();

  Sha256 outer;
  outer.update(outer_pad.data(), outer_pad.size());
  outer.update(inner_digest.data(), inner_digest.size());
  const auto digest = outer.finish();
  return hex_encode(digest.data(), digest.size());
}

bool constant_time_equals(std::string_view a, std::string_view b) {
  if (a.size() != b.size()) {
    return false;
  }
  unsigned char diff = 0;
  for (std::size_t i = 0; i < a.size(); ++i) {
    diff |= static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i]);
  }
  return diff == 0;
}

} // namespace bouncer
