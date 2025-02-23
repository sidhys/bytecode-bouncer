#pragma once

#include "bouncer/hash.hpp"

#include <cstddef>
#include <cstdint>
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
};

class ClassHashTracker {
public:
  std::optional<ClassChange> observe(std::string class_name,
                                     const std::vector<std::uint8_t> &bytecode);
  std::optional<std::string> current_hash(const std::string &class_name) const;
  std::size_t tracked_count() const;

private:
  struct Snapshot {
    std::string hash;
    std::size_t size = 0;
  };

  std::unordered_map<std::string, Snapshot> snapshots_;
};

} // namespace bouncer
