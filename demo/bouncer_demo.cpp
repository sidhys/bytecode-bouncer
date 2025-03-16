#include "bouncer/class_hash.hpp"
#include "bouncer/classloader_rules.hpp"
#include "bouncer/module_walker.hpp"
#include "bouncer/native_bind_hook.hpp"
#include "bouncer/report.hpp"
#include "bouncer/signing.hpp"

#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

std::string fixture_path() {
  return std::string(BOUNCER_FIXTURE_DIR) + "/sample_modules.txt";
}

std::string read_fixture() {
  std::ifstream input(fixture_path());
  if (!input) {
    throw std::runtime_error("unable to open fixture: " + fixture_path());
  }
  return std::string(std::istreambuf_iterator<char>(input),
                     std::istreambuf_iterator<char>());
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

} // namespace

int main() {
  const auto modules = bouncer::parse_module_lines(read_fixture());
  const auto allowlist = bouncer::ModuleAllowlist::defaults();
  const auto module_findings =
      bouncer::find_unallowed_modules(modules, allowlist);
  const auto preload_findings = bouncer::find_preload_environment({});

  bouncer::ClassHashTracker tracker;
  tracker.observe("demo/Game", bouncer::bytes_from_text("class-v1"));
  const auto change =
      tracker.observe("demo/Game", bouncer::bytes_from_text("class-v2"));

  bouncer::ClassLoaderRuleModel loader_rules =
      bouncer::ClassLoaderRuleModel::defaults();
  const bouncer::ClassLoaderEvent loader_event{
      "demo.Game",
      "com.example.CustomLoader",
      "file:/workspace/demo.jar",
      false,
      {"jdk.internal.loader.ClassLoaders$AppClassLoader"}};
  const auto loader_finding = loader_rules.evaluate(loader_event);

  bouncer::NativeBindTracker bind_tracker;
  bind_tracker.mark_vm_initialized();
  const bouncer::NativeBindEvent bind_event{
      "demo.Game", "nativeHook", "()V", reinterpret_cast<const void *>(0x1000),
      "/tmp/libcheat.dylib"};
  const auto bind_finding = bind_tracker.observe_bind(bind_event);

  const auto key = bouncer::make_local_key("demo-seed");
  const bouncer::Detection synthetic_detection{
      bouncer::Severity::high, "unsigned-classloader", loader_event.class_name,
      "demo classloader was not signed"};
  const auto report = bouncer::sign_report(
      bouncer::report_from_detection(synthetic_detection), key);

  std::cout << "bytecode bouncer demo\n";
  std::cout << "tracked class hash: "
            << tracker.current_hash("demo/Game").value_or("<missing>") << '\n';
  if (change.has_value()) {
    std::cout << "class change detected for " << change->class_name << '\n';
  }

  print_findings(module_findings, "native modules");
  print_findings(preload_findings, "preload env");
  print_findings(loader_finding
                     ? std::vector<bouncer::Detection>{*loader_finding}
                     : std::vector<bouncer::Detection>{},
                 "loader rules");
  print_findings(bind_finding ? std::vector<bouncer::Detection>{*bind_finding}
                              : std::vector<bouncer::Detection>{},
                 "native bind rules");

  std::cout << "signed report verified: "
            << (bouncer::verify_signed_report(report, key.secret_key) ? "yes"
                                                                      : "no")
            << '\n';
  std::cout << bouncer::signed_report_to_json(report) << '\n';
  return 0;
}
