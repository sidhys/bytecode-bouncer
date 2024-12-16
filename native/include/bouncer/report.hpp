#pragma once

#include "bouncer/finding.hpp"

#include <map>
#include <string>

namespace bouncer {

struct ReportEvent {
  Severity severity = Severity::low;
  std::string kind;
  std::string subject;
  std::string detail;
  std::map<std::string, std::string> fields;
};

} // namespace bouncer