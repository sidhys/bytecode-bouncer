#include "bouncer/class_hash.hpp"

namespace bouncer {

std::optional<ClassChange>
ClassHashTracker::observe(std::string class_name,
                          const std::vector<std::uint8_t> &bytecode,
                          std::uint64_t loader_id) {
  const Snapshot next{stable_hash_hex(bytecode), bytecode.size()};
  std::lock_guard<std::mutex> lock(mutex_);
  auto &classes = snapshots_[loader_id];
  auto found = classes.find(class_name);

  if (found == classes.end()) {
    classes.emplace(std::move(class_name), next);
    return std::nullopt;
  }

  if (found->second.hash == next.hash) {
    found->second = next;
    return std::nullopt;
  }

  ClassChange change{found->first, found->second.hash, next.hash,
                     found->second.size, next.size, loader_id};
  found->second = next;
  return change;
}

std::optional<std::string>
ClassHashTracker::current_hash(const std::string &class_name,
                               std::uint64_t loader_id) const {
  std::lock_guard<std::mutex> lock(mutex_);
  const auto loader = snapshots_.find(loader_id);
  if (loader == snapshots_.end()) {
    return std::nullopt;
  }
  const auto found = loader->second.find(class_name);
  if (found == loader->second.end()) {
    return std::nullopt;
  }
  return found->second.hash;
}

void ClassHashTracker::forget_loader(std::uint64_t loader_id) {
  std::lock_guard<std::mutex> lock(mutex_);
  snapshots_.erase(loader_id);
}

std::size_t ClassHashTracker::tracked_count() const {
  std::lock_guard<std::mutex> lock(mutex_);
  std::size_t count = 0;
  for (const auto &loader : snapshots_) {
    count += loader.second.size();
  }
  return count;
}

} // namespace bouncer
