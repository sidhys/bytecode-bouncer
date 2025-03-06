#pragma once

#include "bouncer/finding.hpp"

#include <atomic>
#include <optional>
#include <string>
#include <vector>

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
  NativeBindTracker();

  void mark_vm_initialized();
  void mark_vm_dead();
  void add_allowed_module_fragment(std::string fragment);

  bool vm_initialized() const;
  bool is_allowed_module(const std::string &module_path) const;
  std::optional<Detection> observe_bind(const NativeBindEvent &event) const;

private:
  std::atomic<bool> vm_initialized_{false};
  std::vector<std::string> allowed_module_fragments_;
};

} // namespace bouncer
