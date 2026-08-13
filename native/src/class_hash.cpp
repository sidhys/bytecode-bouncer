#include "bouncer/class_hash.hpp"

namespace bouncer {

std::optional<ClassChange>
ClassHashTracker::observe(std::string class_name,
                          const std::vector<std::uint8_t> &bytecode) {
  return observe_hashed(std::move(class_name), stable_hash_hex(bytecode),
                        bytecode.size());
}

std::optional<ClassChange>
ClassHashTracker::observe_hashed(std::string class_name, std::string hash,
                                 std::size_t size) {
  auto found = snapshots_.find(class_name);

  if (found == snapshots_.end()) {
    std::optional<ClassChange> change;
    const auto expected = expected_.find(class_name);
    if (expected != expected_.end() && expected->second != hash) {
      change = ClassChange{class_name, expected->second, hash, 0, size, true};
    }
    snapshots_.emplace(std::move(class_name), Snapshot{std::move(hash), size});
    return change;
  }

  if (found->second.hash == hash) {
    found->second.size = size;
    return std::nullopt;
  }

  ClassChange change{found->first, found->second.hash, hash,
                     found->second.size, size,          false};
  found->second = Snapshot{std::move(hash), size};
  return change;
}

void ClassHashTracker::expect_hash(std::string class_name,
                                   std::string sha256_hex) {
  expected_[std::move(class_name)] = std::move(sha256_hex);
}

std::optional<std::string>
ClassHashTracker::current_hash(const std::string &class_name) const {
  const auto found = snapshots_.find(class_name);
  if (found == snapshots_.end()) {
    return std::nullopt;
  }
  return found->second.hash;
}

std::size_t ClassHashTracker::tracked_count() const {
  return snapshots_.size();
}

std::map<std::string, std::string> ClassHashTracker::observed_hashes() const {
  std::map<std::string, std::string> observed;
  for (const auto &[name, snapshot] : snapshots_) {
    observed.emplace(name, snapshot.hash);
  }
  return observed;
}

} // namespace bouncer
