#pragma once

#include "bouncer/finding.hpp"
#include "bouncer/module_trust.hpp"

#include <optional>
#include <set>
#include <string>

namespace bouncer {

struct NativeBindEvent {
  std::string java_class;
  std::string method_name;
  std::string signature;
  const void *address = nullptr;
  std::string module_path;
};

class NativeBindTracker {
public:
  explicit NativeBindTracker(ModuleTrustPolicy &policy);

  std::optional<Detection> observe_bind(const NativeBindEvent &event);

private:
  ModuleTrustPolicy &policy_;
  std::set<std::string> unresolved_reported_;
};

} // namespace bouncer
