#pragma once

#include <string>

namespace bouncer {

enum class Severity { low, medium, high };

struct Detection {
  Severity severity = Severity::low;
  std::string kind;
  std::string subject;
  std::string detail;
};

} // namespace bouncer