#include "bouncer/module_walker.hpp"

#include <cstdlib>
#include <set>
#include <sstream>

#if defined(__APPLE__)
#include <mach-o/dyld.h>
#elif defined(__linux__)
#include <link.h>
#endif

namespace bouncer {
namespace {

std::string trim(std::string value) {
  while (!value.empty() && (value.back() == '\n' || value.back() == '\r' ||
                            value.back() == ' ' || value.back() == '\t')) {
    value.pop_back();
  }
  std::size_t start = 0;
  while (start < value.size() &&
         (value[start] == ' ' || value[start] == '\t')) {
    ++start;
  }
  return value.substr(start);
}

std::uintptr_t parse_hex_prefix(const std::string &value) {
  std::uintptr_t parsed = 0;
  std::istringstream in(value);
  in >> std::hex >> parsed;
  return parsed;
}

void add_unique_module(std::vector<NativeModule> &modules,
                       std::set<std::string> &seen, std::string path,
                       std::uintptr_t base_address) {
  path = trim(std::move(path));
  if (path.empty() || path.front() != '/') {
    return;
  }
  const auto deleted = path.find(" (deleted)");
  if (deleted != std::string::npos) {
    path.erase(deleted);
  }
  if (seen.insert(path).second) {
    modules.push_back(NativeModule{path, base_address});
  }
}

#if defined(__linux__)
int collect_module(struct dl_phdr_info *info, std::size_t, void *data) {
  if (info == nullptr || data == nullptr || info->dlpi_name == nullptr ||
      info->dlpi_name[0] == '\0') {
    return 0;
  }
  auto *modules = static_cast<std::vector<NativeModule> *>(data);
  modules->push_back(NativeModule{
      info->dlpi_name, static_cast<std::uintptr_t>(info->dlpi_addr)});
  return 0;
}
#endif

} // namespace

std::vector<NativeModule> parse_proc_maps(std::string_view maps_text) {
  std::vector<NativeModule> modules;
  std::set<std::string> seen;
  std::istringstream input{std::string(maps_text)};
  std::string line;

  while (std::getline(input, line)) {
    const auto slash = line.find('/');
    if (slash == std::string::npos) {
      continue;
    }
    const auto dash = line.find('-');
    const auto base =
        dash == std::string::npos ? 0 : parse_hex_prefix(line.substr(0, dash));
    add_unique_module(modules, seen, line.substr(slash), base);
  }

  return modules;
}

std::vector<NativeModule> parse_module_lines(std::string_view module_lines) {
  std::vector<NativeModule> modules;
  std::set<std::string> seen;
  std::istringstream input{std::string(module_lines)};
  std::string line;

  while (std::getline(input, line)) {
    line = trim(std::move(line));
    if (line.empty() || line.front() == '#') {
      continue;
    }
    add_unique_module(modules, seen, line, 0);
  }

  return modules;
}

std::vector<NativeModule> walk_loaded_modules() {
  std::vector<NativeModule> modules;

#if defined(__APPLE__)
  const auto count = _dyld_image_count();
  for (std::uint32_t i = 0; i < count; ++i) {
    const char *image_name = _dyld_get_image_name(i);
    const mach_header *header = _dyld_get_image_header(i);
    if (image_name != nullptr && image_name[0] != '\0') {
      modules.push_back(
          NativeModule{image_name, reinterpret_cast<std::uintptr_t>(header)});
    }
  }
#elif defined(__linux__)
  dl_iterate_phdr(collect_module, &modules);
#endif

  return modules;
}

std::vector<Detection> find_preload_environment(
    const std::map<std::string, std::string> &environment) {
  std::vector<Detection> findings;
  for (const auto &name : {"LD_PRELOAD", "DYLD_INSERT_LIBRARIES"}) {
    const auto found = environment.find(name);
    if (found != environment.end() && !found->second.empty()) {
      findings.push_back(
          Detection{Severity::high, "native-preload-env", name, found->second});
    }
  }
  return findings;
}

std::vector<Detection> find_preload_environment() {
  std::map<std::string, std::string> environment;
  for (const auto &name : {"LD_PRELOAD", "DYLD_INSERT_LIBRARIES"}) {
    const char *value = std::getenv(name);
    if (value != nullptr) {
      environment.emplace(name, value);
    }
  }
  return find_preload_environment(environment);
}

} // namespace bouncer
