#include "bouncer/class_hash.hpp"
#include "bouncer/classloader_rules.hpp"
#include "bouncer/finding.hpp"
#include "bouncer/module_walker.hpp"
#include "bouncer/native_bind_hook.hpp"
#include "bouncer/report.hpp"
#include "bouncer/signing.hpp"

#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

using TestFn = void (*)();

void check(bool condition, const std::string &message) {
  if (!condition) {
    throw std::runtime_error(message);
  }
}

std::string fixture_path(const std::string &name) {
  return std::string(BOUNCER_FIXTURE_DIR) + "/" + name;
}

std::string read_text_file(const std::string &path) {
  std::ifstream input(path);
  check(static_cast<bool>(input), "unable to open " + path);
  return std::string(std::istreambuf_iterator<char>(input),
                     std::istreambuf_iterator<char>());
}

void test_hash_and_class_tracking() {
  const auto a = bouncer::stable_hash_hex("hello");
  const auto b = bouncer::stable_hash_hex("hello");
  const auto c = bouncer::stable_hash_hex("world");
  check(a == b, "hash should be stable");
  check(a != c, "hash should change for different input");

  bouncer::ClassHashTracker tracker;
  const auto first =
      tracker.observe("demo/Test", bouncer::bytes_from_text("class-v1"));
  check(!first.has_value(), "first observe should not report a change");
  check(tracker.tracked_count() == 1, "tracker should remember one class");

  const auto same =
      tracker.observe("demo/Test", bouncer::bytes_from_text("class-v1"));
  check(!same.has_value(), "same bytecode should not report a change");

  const auto changed =
      tracker.observe("demo/Test", bouncer::bytes_from_text("class-v2"));
  check(changed.has_value(), "changed bytecode should report a change");
  check(changed->previous_hash != changed->current_hash,
        "hashes should differ");
  check(changed->previous_size == 8 && changed->current_size == 8,
        "sizes should match the sample");
}

void test_report_and_signing() {
  const auto key = bouncer::make_local_key("unit-test-seed");
  const bouncer::Detection detection{bouncer::Severity::high,
                                     "unsigned-classloader", "demo/Test",
                                     "loader=custom"};
  const auto report =
      bouncer::report_from_detection(detection, {{"build", "test"}});
  const auto signed_report = bouncer::sign_report(report, key);

  check(signed_report.algorithm == "bb-hmac-sha256-v1", "unexpected algorithm");
  check(!signed_report.key_id.empty(), "key id should be set");
  check(bouncer::verify_signed_report(signed_report, key.secret_key),
        "signed report should verify");
  check(!bouncer::verify_signed_report(signed_report, "wrong-secret"),
        "wrong secret should fail verification");

  const auto json = bouncer::signed_report_to_json(signed_report);
  check(json.find("\"key_id\"") != std::string::npos,
        "json should expose key_id");
  check(json.find("\"mac\"") != std::string::npos, "json should expose mac");
  check(json.find("unsigned-classloader") != std::string::npos,
        "payload should be embedded");
}

void test_module_walker() {
  const auto lines = read_text_file(fixture_path("sample_modules.txt"));
  const auto modules = bouncer::parse_module_lines(lines);
  check(modules.size() == 3, "fixture should yield three modules");
  check(modules[0].path == "/usr/lib/libSystem.B.dylib",
        "first module should be system lib");
  check(modules[1].path == "/tmp/libcheat.dylib",
        "second module should be the suspicious module");

  const auto maps = read_text_file(fixture_path("sample_proc_maps.txt"));
  const auto parsed = bouncer::parse_proc_maps(maps);
  check(parsed.size() == 2, "proc maps fixture should yield two modules");
  check(parsed[0].base_address == 0x1000, "first base address should parse");
  check(parsed[1].base_address == 0x2000, "second base address should parse");

  const auto allowlist = bouncer::ModuleAllowlist::defaults();
  const auto findings = bouncer::find_unallowed_modules(modules, allowlist);
  check(findings.size() == 1, "only the suspicious module should be flagged");
  check(findings[0].subject == "/tmp/libcheat.dylib",
        "flagged module should match fixture");

  const auto preload =
      bouncer::find_preload_environment({{"LD_PRELOAD", "/tmp/libshim.dylib"}});
  check(preload.size() == 1, "preload env should be flagged");
  check(preload[0].kind == "native-preload-env",
        "unexpected preload finding kind");
}

void test_loader_and_bind_rules() {
  bouncer::ClassLoaderRuleModel loader_rules =
      bouncer::ClassLoaderRuleModel::defaults();
  bouncer::ClassLoaderEvent signed_custom_loader{
      "demo.Test",
      "com.example.CustomLoader",
      "file:/workspace/app.jar",
      true,
      {"jdk.internal.loader.ClassLoaders$AppClassLoader"}};
  const auto signed_result = loader_rules.evaluate(signed_custom_loader);
  check(signed_result.has_value(),
        "signed custom loader should still be reviewed");
  check(signed_result->kind == "custom-classloader",
        "expected custom loader finding");

  bouncer::ClassLoaderEvent unsigned_loader{
      "demo.Test",
      "com.example.CustomLoader",
      "file:/workspace/app.jar",
      false,
      {"jdk.internal.loader.ClassLoaders$AppClassLoader"}};
  const auto unsigned_result = loader_rules.evaluate(unsigned_loader);
  check(unsigned_result.has_value(), "unsigned loader should be flagged");
  check(unsigned_result->kind == "unsigned-classloader",
        "expected unsigned loader finding");

  bouncer::NativeBindTracker bind_tracker;
  const bouncer::NativeBindEvent allowed_bind{
      "demo.Test", "nativeMethod", "(I)V",
      reinterpret_cast<const void *>(0x1234), "/usr/lib/libjava.dylib"};
  check(!bind_tracker.observe_bind(allowed_bind).has_value(),
        "allowed module should not trigger before vm init");

  const bouncer::NativeBindEvent suspicious_bind{
      "demo.Test", "nativeMethod", "(I)V",
      reinterpret_cast<const void *>(0x4321), "/tmp/libcheat.dylib"};
  const auto suspicious = bind_tracker.observe_bind(suspicious_bind);
  check(suspicious.has_value(), "suspicious bind should be flagged");
  check(suspicious->kind == "untrusted-native-bind",
        "unexpected native bind kind");

  bind_tracker.mark_vm_initialized();
  const auto late_bind = bind_tracker.observe_bind(allowed_bind);
  check(late_bind.has_value(), "late bind should be flagged");
  check(late_bind->kind == "late-native-bind",
        "late bind should be high severity");
  bind_tracker.mark_vm_dead();
  check(!bind_tracker.vm_initialized(), "vm should be marked dead");
}

void test_json_and_env_helpers() {
  const auto escaped = bouncer::json_escape("line\nquote\"slash\\tab\t");
  check(escaped.find("\\n") != std::string::npos, "newline should be escaped");
  check(escaped.find("\\\"") != std::string::npos, "quote should be escaped");
  check(escaped.find("\\\\") != std::string::npos,
        "backslash should be escaped");

  const auto env_findings = bouncer::find_preload_environment({});
  check(env_findings.empty(), "empty environment should not trigger findings");
}

} // namespace

int main() {
  const std::vector<std::pair<const char *, TestFn>> tests = {
      {"hash and class tracking", test_hash_and_class_tracking},
      {"report and signing", test_report_and_signing},
      {"module walker", test_module_walker},
      {"loader and bind rules", test_loader_and_bind_rules},
      {"json and env helpers", test_json_and_env_helpers},
  };

  std::size_t passed = 0;
  for (const auto &[name, fn] : tests) {
    try {
      fn();
      ++passed;
      std::cout << "[pass] " << name << '\n';
    } catch (const std::exception &error) {
      std::cerr << "[fail] " << name << ": " << error.what() << '\n';
      return 1;
    }
  }

  std::cout << "bouncer tests passed: " << passed << "/" << tests.size()
            << '\n';
  return 0;
}
