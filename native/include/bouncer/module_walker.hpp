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

std::vector<NativeModule> parse_proc_maps(std::string_view maps_text);
std::vector<NativeModule> parse_module_lines(std::string_view module_lines);
std::vector<NativeModule> walk_loaded_modules();

std::vector<Detection>
find_preload_environment(const std::map<std::string, std::string> &environment);
std::vector<Detection> find_preload_environment();

} // namespace bouncer
