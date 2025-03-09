#include "bouncer/class_hash.hpp"

#include <iostream>
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

void test_hash_and_class_tracking() {
  const auto a = bouncer::stable_hash_hex("hello");
  const auto b = bouncer::stable_hash_hex("hello");
  const auto c = bouncer::stable_hash_hex("world");
  check(a == b, "hash should be stable");
  check(a != c, "hash should change for different input");
}

} // namespace

int main() {
  const std::vector<std::pair<const char *, TestFn>> tests = {
      {"hash and class tracking", test_hash_and_class_tracking},
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