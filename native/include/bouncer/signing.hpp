#pragma once

#include "bouncer/report.hpp"

#include <string>
#include <string_view>

namespace bouncer {

struct SigningKey {
  std::string key_id;
  std::string secret_key;
};

struct SignedReport {
  std::string algorithm;
  std::string payload_json;
  std::string key_id;
  std::string mac;
};

SigningKey make_local_key(std::string_view seed);
std::string sign_payload(std::string_view payload_json,
                         std::string_view secret_key);
bool verify_payload(std::string_view payload_json, std::string_view secret_key,
                    std::string_view mac);

SignedReport sign_report(const ReportEvent &report, const SigningKey &key);
SignedReport sign_json_payload(std::string payload_json, const SigningKey &key);
bool verify_signed_report(const SignedReport &report,
                          std::string_view secret_key);
std::string signed_report_to_json(const SignedReport &report);

} // namespace bouncer
