#pragma once

#include <string>
#include <vector>

namespace bouncer {

struct NativeModule {
  std::string path;
  std::uintptr_t base_address = 0;
};

class ModuleAllowlist {
public:
  ModuleAllowlist();

  void add_allowed_fragment(std::string fragment);

private:
  std::vector<std::string> allowed_fragments_;
};

} // namespace bouncer