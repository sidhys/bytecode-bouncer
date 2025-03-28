#include "bouncer/classloader_rules.hpp"

#include <algorithm>
#include <sstream>

namespace bouncer {

std::string severity_to_string(Severity severity) {
  switch (severity) {
  case Severity::low:
    return "LOW";
  case Severity::medium:
    return "MEDIUM";
  case Severity::high:
    return "HIGH";
  }
  return "LOW";
}

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

ClassLoaderRuleModel ClassLoaderRuleModel::defaults() {
  ClassLoaderRuleModel model;
  model.add_trusted_code_source_prefix("jrt:/");
  model.add_trusted_code_source_prefix("file:/usr/");
  model.add_trusted_code_source_prefix("file:/System/");
  model.add_trusted_code_source_prefix("file:/Library/Java/");
  model.add_trusted_code_source_prefix("file:/Applications/");
  return model;
}

void ClassLoaderRuleModel::add_allowed_loader(std::string loader_name) {
  allowed_loaders_.insert(std::move(loader_name));
}

void ClassLoaderRuleModel::add_trusted_code_source_prefix(std::string prefix) {
  trusted_code_source_prefixes_.push_back(std::move(prefix));
}

bool ClassLoaderRuleModel::is_allowed_loader(
    const std::string &loader_name) const {
  return allowed_loaders_.find(loader_name) != allowed_loaders_.end();
}

bool ClassLoaderRuleModel::is_trusted_code_source(
    const std::string &code_source) const {
  if (code_source.empty()) {
    return true;
  }
  return std::any_of(trusted_code_source_prefixes_.begin(),
                     trusted_code_source_prefixes_.end(),
                     [&](const std::string &prefix) {
                       return starts_with(code_source, prefix);
                     });
}

std::optional<Detection>
ClassLoaderRuleModel::evaluate(const ClassLoaderEvent &event) const {
  bool allowed_chain = is_allowed_loader(event.loader_name);
  for (const auto &parent : event.parent_chain) {
    allowed_chain = allowed_chain && is_allowed_loader(parent);
  }

  const bool trusted_source = is_trusted_code_source(event.code_source);
  if (allowed_chain && (event.signed_code_source || trusted_source)) {
    return std::nullopt;
  }

  if (!event.signed_code_source) {
    return Detection{Severity::high, "unsigned-classloader", event.class_name,
                     chain_detail(event)};
  }

  if (!allowed_chain) {
    return Detection{Severity::medium, "custom-classloader", event.class_name,
                     chain_detail(event)};
  }

  return Detection{Severity::medium, "untrusted-class-source", event.class_name,
                   chain_detail(event)};
}

} // namespace bouncer
