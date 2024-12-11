#pragma once

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

  void add_allowed_loader(std::string loader_name);

  bool is_allowed_loader(const std::string &loader_name) const;

private:
  std::set<std::string> allowed_loaders_;
};

} // namespace bouncer