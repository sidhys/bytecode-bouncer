#pragma once

#include "bouncer/finding.hpp"

#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace bouncer {

struct NativeModule {
  std::string path;
  std::uintptr_t base_address = 0;
};

class ModuleAllowlist {
public:
  ModuleAllowlist();

  static ModuleAllowlist defaults();

  void add_allowed_fragment(std::string fragment);
  bool is_allowed(const NativeModule &module) const;

private:
  std::vector<std::string> allowed_fragments_;
};

std::vector<NativeModule> parse_proc_maps(std::string_view maps_text);
std::vector<NativeModule> parse_module_lines(std::string_view module_lines);
std::vector<NativeModule> walk_loaded_modules();

std::vector<Detection>
find_unallowed_modules(const std::vector<NativeModule> &modules,
                       const ModuleAllowlist &allowlist);
std::vector<Detection>
find_preload_environment(const std::map<std::string, std::string> &environment);
std::vector<Detection> find_preload_environment();

} // namespace bouncer
