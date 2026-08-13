#include "bouncer/native_bind_hook.hpp"

#include <sstream>

namespace bouncer {
namespace {

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

NativeBindTracker::NativeBindTracker(ModuleTrustPolicy &policy)
    : policy_(policy) {}

std::optional<Detection>
NativeBindTracker::observe_bind(const NativeBindEvent &event) {
  if (event.module_path.empty()) {
    if (!unresolved_reported_.insert(bind_subject(event)).second) {
      return std::nullopt;
    }
    return Detection{Severity::medium, "unresolved-native-bind",
                     bind_subject(event), bind_detail(event)};
  }

  if (policy_.check_module(event.module_path, RehashPolicy::pin_only)
          .has_value()) {
    return Detection{Severity::high, "untrusted-native-bind",
                     bind_subject(event), bind_detail(event)};
  }

  return std::nullopt;
}

} // namespace bouncer
