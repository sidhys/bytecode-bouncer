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

ReportEvent
report_from_detection(const Detection &detection,
                      std::map<std::string, std::string> fields = {});

std::string json_escape(const std::string &value);
std::string report_to_json(const ReportEvent &report);

} // namespace bouncer
