#pragma once

#include "bouncer/finding.hpp"

#include <optional>
#include <set>
#include <string>
#include <vector>

namespace bouncer {

struct ClassLoaderEvent {
  std::string class_name;
  std::string loader_name;
  std::string code_source;
  bool signed_code_source = false;
  std::vector<std::string> parent_chain;
};

class ClassLoaderRuleModel {
public:
  ClassLoaderRuleModel();

  static ClassLoaderRuleModel defaults();

  void add_allowed_loader(std::string loader_name);
  void add_trusted_code_source_prefix(std::string prefix);

  bool is_allowed_loader(const std::string &loader_name) const;
  bool is_trusted_code_source(const std::string &code_source) const;

  std::optional<Detection> evaluate(const ClassLoaderEvent &event) const;

private:
  std::set<std::string> allowed_loaders_;
  std::vector<std::string> trusted_code_source_prefixes_;
};

} // namespace bouncer
