#pragma once

#include <string>

namespace bouncer {

struct NativeBindEvent {
  std::string java_class;
  std::string method_name;
  std::string signature;
  const void *address = nullptr;
  std::string module_path;
};

} // namespace bouncer