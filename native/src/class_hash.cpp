#include "bouncer/class_hash.hpp"

namespace bouncer {

std::optional<ClassChange>
ClassHashTracker::observe(std::string class_name,
                          const std::vector<std::uint8_t> &bytecode) {
  const Snapshot next{stable_hash_hex(bytecode), bytecode.size()};
  auto found = snapshots_.find(class_name);

  if (found == snapshots_.end()) {
    snapshots_.emplace(std::move(class_name), next);
    return std::nullopt;
  }

  if (found->second.hash == next.hash) {
    found->second = next;
    return std::nullopt;
  }

  ClassChange change{found->first, found->second.hash, next.hash,
                     found->second.size, next.size};
  found->second = next;
  return change;
}

std::optional<std::string>
ClassHashTracker::current_hash(const std::string &class_name) const {
  const auto found = snapshots_.find(class_name);
  if (found == snapshots_.end()) {
    return std::nullopt;
  }
  return found->second.hash;
}

} // namespace bouncer