#include "bouncer/module_trust.hpp"

#include "bouncer/hash.hpp"

#include <algorithm>
#include <climits>
#include <cstdlib>

namespace bouncer {
namespace {

std::string short_hex(const std::string &hex) {
  return hex.size() > 12 ? hex.substr(0, 12) : hex;
}

} // namespace

std::string ModuleTrustPolicy::normalize_path(const std::string &path) {
  if (path.empty()) {
    return path;
  }
  char resolved[PATH_MAX];
  if (::realpath(path.c_str(), resolved) != nullptr) {
    return std::string(resolved);
  }
  return path;
}

std::string ModuleTrustPolicy::parent_directory(const std::string &path) {
  const auto slash = path.find_last_of('/');
  if (slash == std::string::npos) {
    return "";
  }
  if (slash == 0) {
    return "/";
  }
  return path.substr(0, slash);
}

void ModuleTrustPolicy::trust_directory(const std::string &directory) {
  std::string normalized = normalize_path(directory);
  while (normalized.size() > 1 && normalized.back() == '/') {
    normalized.pop_back();
  }
  // trusting "/" would trust every module on the machine
  if (normalized.empty() || normalized == "/") {
    return;
  }
  if (std::find(trusted_dirs_.begin(), trusted_dirs_.end(), normalized) ==
      trusted_dirs_.end()) {
    trusted_dirs_.push_back(std::move(normalized));
  }
}

bool ModuleTrustPolicy::pin_module(const std::string &path) {
  const std::string normalized = normalize_path(path);
  const auto found = pins_.find(normalized);
  if (found != pins_.end()) {
    return found->second.hashable;
  }
  const auto hash = sha256_file_hex(normalized);
  pins_.emplace(normalized, Pin{hash.value_or(""), hash.has_value()});
  return hash.has_value();
}

bool ModuleTrustPolicy::is_trusted_path(const std::string &path) const {
  const std::string normalized = normalize_path(path);
  return std::any_of(
      trusted_dirs_.begin(), trusted_dirs_.end(), [&](const std::string &dir) {
        if (normalized == dir) {
          return true;
        }
        return normalized.size() > dir.size() &&
               normalized.compare(0, dir.size(), dir) == 0 &&
               normalized[dir.size()] == '/';
      });
}

bool ModuleTrustPolicy::is_pinned(const std::string &path) const {
  return pins_.find(normalize_path(path)) != pins_.end();
}

std::optional<Detection>
ModuleTrustPolicy::check_module(const std::string &path, RehashPolicy rehash) {
  const std::string normalized = normalize_path(path);
  const auto found = pins_.find(normalized);

  if (found == pins_.end()) {
    if (is_trusted_path(normalized)) {
      pin_module(normalized);
      return std::nullopt;
    }
    if (!reported_.insert(normalized).second) {
      return std::nullopt;
    }
    return Detection{Severity::high, "untrusted-native-module", normalized,
                     "loaded from outside every trusted directory"};
  }

  if (rehash == RehashPolicy::verify_content && found->second.hashable) {
    const auto current = sha256_file_hex(normalized);
    if (!current.has_value()) {
      if (reported_.insert(normalized + "#gone").second) {
        return Detection{Severity::high, "modified-native-module", normalized,
                         "pinned file is no longer readable"};
      }
      return std::nullopt;
    }
    if (*current != found->second.sha256_hex) {
      if (reported_.insert(normalized + "#changed").second) {
        return Detection{Severity::high, "modified-native-module", normalized,
                         "content hash changed since pin " +
                             short_hex(found->second.sha256_hex) + " -> " +
                             short_hex(*current)};
      }
      return std::nullopt;
    }
  }

  return std::nullopt;
}

std::size_t ModuleTrustPolicy::pinned_count() const { return pins_.size(); }

std::size_t ModuleTrustPolicy::trusted_directory_count() const {
  return trusted_dirs_.size();
}

std::vector<Detection> sweep_modules(const std::vector<NativeModule> &modules,
                                     ModuleTrustPolicy &policy,
                                     RehashPolicy rehash) {
  std::vector<Detection> findings;
  for (const auto &module : modules) {
    if (auto finding = policy.check_module(module.path, rehash)) {
      findings.push_back(std::move(*finding));
    }
  }
  return findings;
}

} // namespace bouncer
