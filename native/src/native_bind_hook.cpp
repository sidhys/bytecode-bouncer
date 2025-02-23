#include "bouncer/native_bind_hook.hpp"

#include <algorithm>
#include <cctype>
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

std::string bind_subject(const NativeBindEvent &event) {
  return event.java_class + "." + event.method_name + event.signature;
}

std::string bind_detail(const NativeBindEvent &event) {
  std::ostringstream detail;
  detail << "module="
         << (event.module_path.empty() ? "<unknown>" : event.module_path)
         << " address=" << event.address;
  return detail.str();
}

} // namespace

NativeBindTracker::NativeBindTracker() {
  add_allowed_module_fragment("libjava");
  add_allowed_module_fragment("libjvm");
  add_allowed_module_fragment("bouncer");
}

void NativeBindTracker::mark_vm_initialized() {
  vm_initialized_.store(true, std::memory_order_relaxed);
}

void NativeBindTracker::mark_vm_dead() {
  vm_initialized_.store(false, std::memory_order_relaxed);
}

void NativeBindTracker::add_allowed_module_fragment(std::string fragment) {
  allowed_module_fragments_.push_back(std::move(fragment));
}

bool NativeBindTracker::vm_initialized() const {
  return vm_initialized_.load(std::memory_order_relaxed);
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