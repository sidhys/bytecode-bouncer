#pragma once

#include "bouncer/hash.hpp"

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace bouncer {

struct ClassChange {
  std::string class_name;
  std::string previous_hash;
  std::string current_hash;
  std::size_t previous_size = 0;
  std::size_t current_size = 0;
  bool manifest_mismatch = false;
};

class ClassHashTracker {
public:
  std::optional<ClassChange> observe(std::string class_name,
                                     const std::vector<std::uint8_t> &bytecode);
  std::optional<ClassChange> observe_hashed(std::string class_name,
                                            std::string hash,
                                            std::size_t size);
  void expect_hash(std::string class_name, std::string sha256_hex);

  std::optional<std::string> current_hash(const std::string &class_name) const;
  std::size_t tracked_count() const;
  std::map<std::string, std::string> observed_hashes() const;

private:
  struct Snapshot {
    std::string hash;
    std::size_t size = 0;
  };

  std::unordered_map<std::string, Snapshot> snapshots_;
  std::unordered_map<std::string, std::string> expected_;
};

} // namespace bouncer
