#include "bouncer/class_hash.hpp"
#include "bouncer/classloader_rules.hpp"
#include "bouncer/module_trust.hpp"
#include "bouncer/module_walker.hpp"
#include "bouncer/native_bind_hook.hpp"
#include "bouncer/report.hpp"
#include "bouncer/signing.hpp"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <vector>

namespace {

std::string make_temp_dir() {
  std::string templ = "/tmp/bouncer-demo-XXXXXX";
  std::vector<char> buffer(templ.begin(), templ.end());
  buffer.push_back('\0');
  if (::mkdtemp(buffer.data()) == nullptr) {
    throw std::runtime_error("mkdtemp failed");
  }
  return std::string(buffer.data());
}

void write_file(const std::string &path, const std::string &content) {
  std::ofstream output(path, std::ios::binary);
  if (!output) {
    throw std::runtime_error("unable to write " + path);
  }
  output << content;
}

void print_findings(const std::vector<bouncer::Detection> &findings,
                    const char *label) {
  std::cout << label << '\n';
  if (findings.empty()) {
    std::cout << "  none\n";
    return;
  }
  for (const auto &finding : findings) {
    std::cout << "  [" << bouncer::severity_to_string(finding.severity) << "] "
              << finding.kind << " | " << finding.subject << " | "
              << finding.detail << '\n';
  }
}

std::vector<bouncer::Detection>
as_vector(const std::optional<bouncer::Detection> &finding) {
  if (finding.has_value()) {
    return {*finding};
  }
  return {};
}

} // namespace

int main() {
  std::cout << "bytecode bouncer demo\n\n";

  // a fake install dir plays the jdk: its contents get pinned and its
  // location becomes a trust root. the other dir plays ~/Downloads.
  const auto install_dir = make_temp_dir();
  const auto downloads_dir = make_temp_dir();

  const auto game_lib = install_dir + "/libgame.dylib";
  write_file(game_lib, "native game code v1");

  bouncer::ModuleTrustPolicy policy;
  policy.trust_directory(install_dir);
  policy.pin_module(game_lib);

  // the spoof name that walked straight through the old fragment allowlist
  const auto spoof_lib = downloads_dir + "/libjava-x.dylib";
  write_file(spoof_lib, "cheat pretending to be libjava");

  const std::vector<bouncer::NativeModule> loaded{{game_lib, 0x1000},
                                                  {spoof_lib, 0x2000}};
  auto sweep = bouncer::sweep_modules(loaded, policy,
                                      bouncer::RehashPolicy::verify_content);
  print_findings(sweep, "module sweep, spoof-named lib in an untrusted dir");

  write_file(game_lib, "native game code v1 plus a patched jump table");
  auto tamper =
      bouncer::sweep_modules({{game_lib, 0x1000}}, policy,
                             bouncer::RehashPolicy::verify_content);
  print_findings(tamper, "module sweep, pinned file rewritten on disk");

  bouncer::ClassHashTracker tracker;
  tracker.observe("demo/Game", bouncer::bytes_from_text("class-v1"));
  const auto change =
      tracker.observe("demo/Game", bouncer::bytes_from_text("class-v2"));
  std::vector<bouncer::Detection> class_findings;
  if (change.has_value()) {
    class_findings.push_back(bouncer::Detection{
        bouncer::Severity::high, "class-bytecode-changed", change->class_name,
        "hash " + change->previous_hash.substr(0, 12) + " -> " +
            change->current_hash.substr(0, 12)});
  }
  print_findings(class_findings, "class tracking, bytecode swapped at reload");

  const bouncer::ClassLoaderRuleModel loader_rules =
      bouncer::ClassLoaderRuleModel::defaults();
  const bouncer::ClassLoaderEvent loader_event{
      "demo.Game",
      "com.example.CustomLoader",
      "file:/workspace/demo.jar",
      false,
      {"jdk.internal.loader.ClassLoaders$AppClassLoader"}};
  print_findings(as_vector(loader_rules.evaluate(loader_event)),
                 "loader rules, unsigned custom classloader");

  bouncer::NativeBindTracker bind_tracker(policy);
  const auto cheat_lib = downloads_dir + "/libcheat.dylib";
  write_file(cheat_lib, "hook implementations");
  const bouncer::NativeBindEvent bind_event{
      "demo.Game", "nativeHook", "()V",
      reinterpret_cast<const void *>(0x1000), cheat_lib};
  print_findings(as_vector(bind_tracker.observe_bind(bind_event)),
                 "native bind resolving into the untrusted dir");

  print_findings(bouncer::find_preload_environment(
                     {{"LD_PRELOAD", "/tmp/libshim.dylib"}}),
                 "preload environment");

  // same envelope the jvmti agent writes at shutdown
  std::vector<bouncer::ReportEvent> events;
  for (const auto &finding : sweep) {
    events.push_back(bouncer::report_from_detection(finding));
  }
  for (const auto &finding : tamper) {
    events.push_back(bouncer::report_from_detection(finding));
  }
  for (const auto &finding : class_findings) {
    events.push_back(bouncer::report_from_detection(finding));
  }

  std::ostringstream payload;
  payload << "{\"agent\":\"bytecode-bouncer\",\"events\":[";
  for (std::size_t i = 0; i < events.size(); ++i) {
    if (i > 0) {
      payload << ',';
    }
    payload << bouncer::report_to_json(events[i]);
  }
  payload << "]}";

  const auto key = bouncer::make_local_key("demo-seed");
  const auto report = bouncer::sign_json_payload(payload.str(), key);

  std::cout << "\nsigned report verified: "
            << (bouncer::verify_signed_report(report, key.secret_key) ? "yes"
                                                                      : "no")
            << '\n';
  auto forged = report;
  forged.payload_json += " ";
  std::cout << "forged payload verified: "
            << (bouncer::verify_signed_report(forged, key.secret_key) ? "yes"
                                                                      : "no")
            << '\n';
  std::cout << bouncer::signed_report_to_json(report) << '\n';

  for (const auto &path : {game_lib, spoof_lib, cheat_lib}) {
    std::remove(path.c_str());
  }
  ::rmdir(install_dir.c_str());
  ::rmdir(downloads_dir.c_str());
  return 0;
}
