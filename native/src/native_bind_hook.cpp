#include "bouncer/native_bind_hook.hpp"

namespace bouncer {

NativeBindTracker::NativeBindTracker() {
  add_allowed_module_fragment("libjava");
  add_allowed_module_fragment("libjvm");
  add_allowed_module_fragment("bouncer");
}

void NativeBindTracker::add_allowed_module_fragment(std::string fragment) {
  allowed_module_fragments_.push_back(std::move(fragment));
}

} // namespace bouncer