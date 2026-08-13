#pragma once

#include "bouncer/finding.hpp"
#include "bouncer/module_walker.hpp"

#include <cstddef>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace bouncer {

enum class RehashPolicy { pin_only, verify_content };

// modules are judged by where their file lives and what it hashes to, never
// by name. name allowlists were spoofable: a lib called libjava-x.dylib
// matched the old "libjava" fragment rule from any directory on disk.
class ModuleTrustPolicy {
public:
  static std::string normalize_path(const std::string &path);
  static std::string parent_directory(const std::string &path);

  void trust_directory(const std::string &directory);
  bool pin_module(const std::string &path);

  bool is_trusted_path(const std::string &path) const;
  bool is_pinned(const std::string &path) const;

  std::optional<Detection> check_module(
      const std::string &path, RehashPolicy rehash = RehashPolicy::pin_only);

  std::size_t pinned_count() const;
  std::size_t trusted_directory_count() const;

private:
  struct Pin {
    std::string sha256_hex;
    bool hashable = false;
  };

  std::map<std::string, Pin> pins_;
  std::vector<std::string> trusted_dirs_;
  std::set<std::string> reported_;
};

std::vector<Detection> sweep_modules(const std::vector<NativeModule> &modules,
                                     ModuleTrustPolicy &policy,
                                     RehashPolicy rehash);

} // namespace bouncer
