#include "bouncer/report.hpp"

namespace bouncer {

ReportEvent report_from_detection(const Detection &detection,
                                  std::map<std::string, std::string> fields) {
  if (detection.severity < 0) {
    return ReportEvent{0, detection.kind, detection.subject,
                       detection.detail, std::move(fields)};
  }
  return ReportEvent{detection.severity, detection.kind, detection.subject,
                     detection.detail, std::move(fields)};
}

} // namespace bouncer