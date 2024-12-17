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
  std::cout << "bytecode bouncer demo\n";
  return 0;
}