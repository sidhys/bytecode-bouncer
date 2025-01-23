#include "bouncer/module_walker.hpp"

#include <set>
#include <sstream>

namespace bouncer {
namespace {

std::string basename(const std::string &path) {
  const auto slash = path.find_last_of('/');
  if (slash == std::string::npos) {
    return path;
  }
  return path.substr(slash + 1);
}

bool fragment_matches_path(const std::string &path,
                           const std::string &fragment) {
  if (fragment.empty()) {
    return false;
  }
  if (fragment.find('/') != std::string::npos) {
    return path.compare(0, fragment.size(), fragment) == 0;
  }

  const std::string base = basename(path);
  if (base == fragment) {
    return true;
  }
  if (base.rfind(fragment, 0) != 0) {
    return false;
  }
  if (base.size() == fragment.size()) {
    return true;
  }

  const char next = base[fragment.size()];
  return next == '.' || next == '-' || next == '_' ||
         std::isdigit(static_cast<unsigned char>(next)) != 0;
}

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

} // namespace
} // namespace bouncer