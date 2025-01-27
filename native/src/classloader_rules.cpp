#include "bouncer/classloader_rules.hpp"

#include <algorithm>
#include <sstream>

namespace bouncer {

namespace {

bool starts_with(const std::string &value, const std::string &prefix) {
  return value.size() >= prefix.size() &&
         value.compare(0, prefix.size(), prefix) == 0;
}

std::string chain_detail(const ClassLoaderEvent &event) {
  std::ostringstream detail;
  detail << "loader="
         << (event.loader_name.empty() ? "<bootstrap>" : event.loader_name);
  if (!event.code_source.empty()) {
    detail << " source=" << event.code_source;
  }
  if (!event.parent_chain.empty()) {
    detail << " parents=";
    for (std::size_t i = 0; i < event.parent_chain.size(); ++i) {
      if (i > 0) {
        detail << " -> ";
      }
      detail << event.parent_chain[i];
    }
  }
  return detail.str();
}

} // namespace

ClassLoaderRuleModel::ClassLoaderRuleModel() {
  add_allowed_loader("");
  add_allowed_loader("<bootstrap>");
  add_allowed_loader("bootstrap");
  add_allowed_loader("platform");
  add_allowed_loader("app");
  add_allowed_loader("jdk.internal.loader.ClassLoaders$PlatformClassLoader");
  add_allowed_loader("jdk.internal.loader.ClassLoaders$AppClassLoader");
}

void ClassLoaderRuleModel::add_allowed_loader(std::string loader_name) {
  allowed_loaders_.insert(std::move(loader_name));
}

bool ClassLoaderRuleModel::is_allowed_loader(
    const std::string &loader_name) const {
  return allowed_loaders_.find(loader_name) != allowed_loaders_.end();
}

} // namespace bouncer