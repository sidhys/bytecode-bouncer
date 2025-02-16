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

  bouncer::ClassHashTracker tracker;
  tracker.observe("demo/Game", bouncer::bytes_from_text("class-v1"));
  const auto change =
      tracker.observe("demo/Game", bouncer::bytes_from_text("class-v2"));

  std::cout << "bytecode bouncer demo\n";
  std::cout << "tracked class hash: "
            << tracker.current_hash("demo/Game").value_or("<missing>") << '\n';
  if (change.has_value()) {
    std::cout << "class change detected for " << change->class_name << '\n';
  }

  print_findings(module_findings, "native modules");

  return 0;
}