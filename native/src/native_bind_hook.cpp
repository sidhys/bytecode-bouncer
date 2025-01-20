#include "bouncer/native_bind_hook.hpp"

#include <algorithm>

namespace bouncer {

namespace {

bool fragment_matches_path(const std::string &path,
                           const std::string &fragment) {
  if (fragment.empty()) {
    return false;
  }
  if (fragment.find('/') != std::string::npos) {
    return path.compare(0, fragment.size(), fragment) == 0;
  }

  const auto slash = path.find_last_of('/');
  const std::string base = (slash == std::string::npos) ? path : path.substr(slash + 1);
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

} // namespace

NativeBindTracker::NativeBindTracker() {
  add_allowed_module_fragment("libjava");
  add_allowed_module_fragment("libjvm");
  add_allowed_module_fragment("bouncer");
}

void NativeBindTracker::add_allowed_module_fragment(std::string fragment) {
  allowed_module_fragments_.push_back(std::move(fragment));
}

bool NativeBindTracker::is_allowed_module(
    const std::string &module_path) const {
  return std::any_of(allowed_module_fragments_.begin(),
                     allowed_module_fragments_.end(),
                     [&](const std::string &fragment) {
                       return fragment_matches_path(module_path, fragment);
                     });
}

} // namespace bouncer