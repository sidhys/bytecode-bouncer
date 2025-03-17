#include "bouncer/report.hpp"

#include <iomanip>
#include <sstream>

namespace bouncer {

ReportEvent report_from_detection(const Detection &detection,
                                  std::map<std::string, std::string> fields) {
  return ReportEvent{detection.severity, detection.kind, detection.subject,
                     detection.detail, std::move(fields)};
}

std::string json_escape(const std::string &value) {
  std::ostringstream out;
  for (const char c : value) {
    switch (c) {
    case '\\':
      out << "\\\\";
      break;
    case '"':
      out << "\\\"";
      break;
    case '\n':
      out << "\\n";
      break;
    case '\r':
      out << "\\r";
      break;
    case '\t':
      out << "\\t";
      break;
    default:
      if (static_cast<unsigned char>(c) < 0x20) {
        out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
            << static_cast<int>(static_cast<unsigned char>(c));
      } else {
        out << c;
      }
      break;
    }
  }
  return out.str();
}

std::string report_to_json(const ReportEvent &report) {
  std::ostringstream out;
  out << "{\"detail\":\"" << json_escape(report.detail) << "\",\"fields\":{";

  bool first = true;
  for (const auto &[key, value] : report.fields) {
    if (!first) {
      out << ",";
    }
    first = false;
    out << "\"" << json_escape(key) << "\":\"" << json_escape(value) << "\"";
  }

  out << "},\"kind\":\"" << json_escape(report.kind) << "\",\"severity\":\""
      << severity_to_string(report.severity) << "\",\"subject\":\""
      << json_escape(report.subject) << "\"}";
  return out.str();
}

} // namespace bouncer
