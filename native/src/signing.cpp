#include "bouncer/signing.hpp"

#include "bouncer/hash.hpp"

namespace bouncer {
namespace {

constexpr const char *algorithm = "bb-hmac-sha256-v1";

std::string key_id_from_secret(std::string_view secret_key) {
  return stable_hash_hex(std::string("key-id|") + std::string(secret_key));
}

} // namespace

SigningKey make_local_key(std::string_view seed) {
  SigningKey pair;
  pair.secret_key = stable_hash_hex(std::string("secret|") + std::string(seed));
  pair.key_id = key_id_from_secret(pair.secret_key);
  return pair;
}

std::string sign_payload(std::string_view payload_json,
                         std::string_view secret_key) {
  return hmac_sha256_hex(secret_key, payload_json);
}

bool verify_payload(std::string_view payload_json, std::string_view secret_key,
                    std::string_view mac) {
  return constant_time_equals(sign_payload(payload_json, secret_key), mac);
}

SignedReport sign_report(const ReportEvent &report, const SigningKey &key) {
  return sign_json_payload(report_to_json(report), key);
}

SignedReport sign_json_payload(std::string payload_json,
                               const SigningKey &key) {
  std::string mac = sign_payload(payload_json, key.secret_key);
  return SignedReport{algorithm, std::move(payload_json), key.key_id,
                      std::move(mac)};
}

bool verify_signed_report(const SignedReport &report,
                          std::string_view secret_key) {
  return report.algorithm == algorithm &&
         key_id_from_secret(secret_key) == report.key_id &&
         verify_payload(report.payload_json, secret_key, report.mac);
}

std::string signed_report_to_json(const SignedReport &report) {
  return std::string("{\"algorithm\":\"") + json_escape(report.algorithm) +
         "\",\"payload\":\"" + json_escape(report.payload_json) +
         "\",\"key_id\":\"" + json_escape(report.key_id) + "\",\"mac\":\"" +
         json_escape(report.mac) + "\"}";
}

} // namespace bouncer
