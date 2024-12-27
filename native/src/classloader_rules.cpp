#include "bouncer/classloader_rules.hpp"

#include <algorithm>
#include <sstream>

namespace bouncer {

namespace {

bool starts_with(const std::string &value, const std::string &prefix) {
  return value.size() >= prefix.size() &&
         value.compare(0, prefix.size(), prefix) == 0;
}

} // namespace

ClassLoaderRuleModel::ClassLoaderRuleModel() {
  add_allowed_loader("");
  add_allowed_loader("<bootstrap>");
  add_allowed_loader("bootstrap");
  add_allowed_loader("platform");
  add_allowed_loader("app");
}

void ClassLoaderRuleModel::add_allowed_loader(std::string loader_name) {
  allowed_loaders_.insert(std::move(loader_name));
}

bool ClassLoaderRuleModel::is_allowed_loader(
    const std::string &loader_name) const {
  return allowed_loaders_.find(loader_name) != allowed_loaders_.end();
}

} // namespace bouncer