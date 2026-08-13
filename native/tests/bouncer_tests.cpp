#include "bouncer/class_hash.hpp"
#include "bouncer/classloader_rules.hpp"
#include "bouncer/finding.hpp"
#include "bouncer/module_trust.hpp"
#include "bouncer/module_walker.hpp"
#include "bouncer/native_bind_hook.hpp"
#include "bouncer/report.hpp"
#include "bouncer/signing.hpp"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <unistd.h>
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

std::string make_temp_dir() {
  std::string templ = "/tmp/bouncer-test-XXXXXX";
  std::vector<char> buffer(templ.begin(), templ.end());
  buffer.push_back('\0');
  check(::mkdtemp(buffer.data()) != nullptr, "mkdtemp failed");
  return std::string(buffer.data());
}

void write_file(const std::string &path, const std::string &content) {
  std::ofstream output(path, std::ios::binary);
  check(static_cast<bool>(output), "unable to write " + path);
  output << content;
}

void test_sha256_and_hmac_vectors() {
  check(bouncer::stable_hash_hex("") ==
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "sha-256 empty string vector");
  check(bouncer::stable_hash_hex("abc") ==
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "sha-256 abc vector");
  check(bouncer::stable_hash_hex(
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") ==
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        "sha-256 two-block vector");

  const std::string rfc_key_1(20, '\x0b');
  check(bouncer::hmac_sha256_hex(rfc_key_1, "Hi There") ==
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        "hmac rfc 4231 case 1");
  check(bouncer::hmac_sha256_hex("Jefe", "what do ya want for nothing?") ==
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        "hmac rfc 4231 case 2");
  const std::string rfc_key_6(131, '\xaa');
  check(bouncer::hmac_sha256_hex(
            rfc_key_6,
            "Test Using Larger Than Block-Size Key - Hash Key First") ==
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
        "hmac rfc 4231 case 6, key longer than one block");

  check(bouncer::constant_time_equals("same", "same"),
        "equal strings should compare equal");
  check(!bouncer::constant_time_equals("same", "sama"),
        "different strings should not compare equal");
  check(!bouncer::constant_time_equals("same", "samee"),
        "different lengths should not compare equal");

  const auto dir = make_temp_dir();
  const auto file = dir + "/abc.bin";
  write_file(file, "abc");
  const auto file_hash = bouncer::sha256_file_hex(file);
  check(file_hash.has_value(), "existing file should hash");
  check(*file_hash == bouncer::stable_hash_hex("abc"),
        "file hash should match in-memory hash");
  check(!bouncer::sha256_file_hex(dir + "/missing.bin").has_value(),
        "missing file should not hash");
  check(!bouncer::sha256_file_hex(dir).has_value(),
        "directories should not hash");
  std::remove(file.c_str());
  ::rmdir(dir.c_str());
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
  check(!changed->manifest_mismatch,
        "live change should not be a manifest mismatch");

  bouncer::ClassHashTracker pinned;
  pinned.expect_hash("demo/Pinned",
                     bouncer::stable_hash_hex(
                         bouncer::bytes_from_text("expected bytecode")));
  const auto mismatch =
      pinned.observe("demo/Pinned", bouncer::bytes_from_text("tampered"));
  check(mismatch.has_value(),
        "manifest mismatch should be reported on first load");
  check(mismatch->manifest_mismatch, "mismatch should be marked as manifest");

  bouncer::ClassHashTracker satisfied;
  satisfied.expect_hash("demo/Pinned",
                        bouncer::stable_hash_hex(
                            bouncer::bytes_from_text("expected bytecode")));
  const auto matching = satisfied.observe(
      "demo/Pinned", bouncer::bytes_from_text("expected bytecode"));
  check(!matching.has_value(),
        "matching manifest hash should stay quiet on first load");
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
  check(signed_report.mac.size() == 64, "mac should be a sha-256 hex digest");
  check(bouncer::verify_signed_report(signed_report, key.secret_key),
        "signed report should verify");
  check(!bouncer::verify_signed_report(signed_report, "wrong-secret"),
        "wrong secret should fail verification");

  auto forged = signed_report;
  forged.payload_json += " ";
  check(!bouncer::verify_signed_report(forged, key.secret_key),
        "modified payload should fail verification");

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

  const auto preload =
      bouncer::find_preload_environment({{"LD_PRELOAD", "/tmp/libshim.dylib"}});
  check(preload.size() == 1, "preload env should be flagged");
  check(preload[0].kind == "native-preload-env",
        "unexpected preload finding kind");
}

void test_module_trust_policy() {
  const auto trusted_dir = make_temp_dir();
  const auto untrusted_dir = make_temp_dir();

  const auto good = trusted_dir + "/libgood.dylib";
  write_file(good, "good v1");

  bouncer::ModuleTrustPolicy policy;
  policy.trust_directory(trusted_dir);
  check(policy.pin_module(good), "pin should hash the file");
  check(policy.is_pinned(good), "pinned module should be recorded");
  check(policy.is_trusted_path(good), "file under trusted dir is trusted");
  check(!policy
             .check_module(good, bouncer::RehashPolicy::verify_content)
             .has_value(),
        "unchanged pinned module should pass");

  // regression for the old fragment allowlist: a lib named libjava-x.dylib
  // matched the "libjava" fragment from any directory on disk
  const auto spoof = untrusted_dir + "/libjava-x.dylib";
  write_file(spoof, "not actually libjava");
  const auto flagged = policy.check_module(spoof);
  check(flagged.has_value(), "spoof-named lib should be flagged");
  check(flagged->kind == "untrusted-native-module",
        "spoof should be an untrusted-module finding");
  check(!policy.check_module(spoof).has_value(),
        "repeat check should not re-report the same module");

  const auto late = trusted_dir + "/liblate.dylib";
  write_file(late, "late v1");
  check(!policy.check_module(late).has_value(),
        "late load from a trusted dir should auto-pin quietly");
  check(policy.is_pinned(late), "late module should now be pinned");

  write_file(good, "good v1 but patched");
  const auto tampered =
      policy.check_module(good, bouncer::RehashPolicy::verify_content);
  check(tampered.has_value(), "rewritten pinned file should be flagged");
  check(tampered->kind == "modified-native-module",
        "tamper should be a modified-module finding");

  check(bouncer::ModuleTrustPolicy::parent_directory("/a/b/c.dylib") == "/a/b",
        "parent directory should strip the file name");
  bouncer::ModuleTrustPolicy no_root;
  no_root.trust_directory("/");
  check(!no_root.is_trusted_path("/anything.dylib"),
        "trusting the filesystem root should be refused");

  for (const auto &path : {good, spoof, late}) {
    std::remove(path.c_str());
  }
  ::rmdir(trusted_dir.c_str());
  ::rmdir(untrusted_dir.c_str());
}

void test_loader_and_bind_rules() {
  const bouncer::ClassLoaderRuleModel loader_rules =
      bouncer::ClassLoaderRuleModel::defaults();
  const bouncer::ClassLoaderEvent signed_custom_loader{
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

  const bouncer::ClassLoaderEvent unsigned_loader{
      "demo.Test",
      "com.example.CustomLoader",
      "file:/workspace/app.jar",
      false,
      {"jdk.internal.loader.ClassLoaders$AppClassLoader"}};
  const auto unsigned_result = loader_rules.evaluate(unsigned_loader);
  check(unsigned_result.has_value(), "unsigned loader should be flagged");
  check(unsigned_result->kind == "unsigned-classloader",
        "expected unsigned loader finding");

  const auto trusted_dir = make_temp_dir();
  const auto untrusted_dir = make_temp_dir();
  const auto trusted_lib = trusted_dir + "/libjava.dylib";
  write_file(trusted_lib, "real jdk lib");

  bouncer::ModuleTrustPolicy policy;
  policy.trust_directory(trusted_dir);
  policy.pin_module(trusted_lib);
  bouncer::NativeBindTracker bind_tracker(policy);

  const bouncer::NativeBindEvent trusted_bind{
      "demo.Test", "nativeMethod", "(I)V",
      reinterpret_cast<const void *>(0x1234), trusted_lib};
  check(!bind_tracker.observe_bind(trusted_bind).has_value(),
        "bind into a pinned trusted module should pass");

  const auto cheat_lib = untrusted_dir + "/libcheat.dylib";
  write_file(cheat_lib, "hook implementations");
  const bouncer::NativeBindEvent suspicious_bind{
      "demo.Test", "nativeMethod", "(I)V",
      reinterpret_cast<const void *>(0x4321), cheat_lib};
  const auto suspicious = bind_tracker.observe_bind(suspicious_bind);
  check(suspicious.has_value(), "bind into untrusted dir should be flagged");
  check(suspicious->kind == "untrusted-native-bind",
        "unexpected native bind kind");

  const bouncer::NativeBindEvent unresolved_bind{
      "demo.Test", "mysteryMethod", "()V",
      reinterpret_cast<const void *>(0x9999), ""};
  const auto unresolved = bind_tracker.observe_bind(unresolved_bind);
  check(unresolved.has_value(), "unresolved bind should be flagged");
  check(unresolved->kind == "unresolved-native-bind",
        "unexpected unresolved bind kind");
  check(!bind_tracker.observe_bind(unresolved_bind).has_value(),
        "repeat unresolved bind should not re-report");

  for (const auto &path : {trusted_lib, cheat_lib}) {
    std::remove(path.c_str());
  }
  ::rmdir(trusted_dir.c_str());
  ::rmdir(untrusted_dir.c_str());
}

void test_json_and_env_helpers() {
  const auto escaped = bouncer::json_escape("line\nquote\"slash\\tab\t");
  check(escaped.find("\\n") != std::string::npos, "newline should be escaped");
  check(escaped.find("\\\"") != std::string::npos, "quote should be escaped");
  check(escaped.find("\\\\") != std::string::npos,
        "backslash should be escaped");

  const auto env_findings = bouncer::find_preload_environment(
      std::map<std::string, std::string>{});
  check(env_findings.empty(), "empty environment should not trigger findings");
}

} // namespace

int main() {
  const std::vector<std::pair<const char *, TestFn>> tests = {
      {"sha-256 and hmac vectors", test_sha256_and_hmac_vectors},
      {"hash and class tracking", test_hash_and_class_tracking},
      {"report and signing", test_report_and_signing},
      {"module walker", test_module_walker},
      {"module trust policy", test_module_trust_policy},
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
