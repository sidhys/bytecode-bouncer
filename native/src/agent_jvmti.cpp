#include "bouncer/agent.hpp"

#include <iostream>

#if __has_include(<jvmti.h>)
#include <jvmti.h>

#include <dlfcn.h>

#include "bouncer/class_hash.hpp"
#include "bouncer/module_trust.hpp"
#include "bouncer/module_walker.hpp"
#include "bouncer/native_bind_hook.hpp"
#include "bouncer/report.hpp"
#include "bouncer/signing.hpp"

#include <fstream>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

namespace {

struct AgentConfig {
  std::string report_path = "bouncer-report.json";
  std::string key_seed = "bouncer-dev-seed";
  std::string class_manifest;
  std::string write_class_manifest;
  std::vector<std::string> extra_trust_dirs;
};

struct AgentState {
  std::mutex lock;
  AgentConfig config;
  bouncer::ClassHashTracker classes;
  bouncer::ModuleTrustPolicy modules;
  bouncer::NativeBindTracker binds{modules};
  std::vector<bouncer::ReportEvent> events;
  bouncer::SigningKey key;
  unsigned long long class_loads = 0;
  unsigned long long native_binds = 0;
  bool report_written = false;
};

// leaked on purpose: callbacks can still fire while the vm tears down
AgentState *state = nullptr;

AgentConfig parse_options(const char *options) {
  AgentConfig config;
  if (options == nullptr) {
    return config;
  }
  std::istringstream input(options);
  std::string item;
  while (std::getline(input, item, ',')) {
    const auto eq = item.find('=');
    if (eq == std::string::npos || eq == 0) {
      std::cerr << "[bouncer] ignoring malformed option: " << item << '\n';
      continue;
    }
    const auto key = item.substr(0, eq);
    const auto value = item.substr(eq + 1);
    if (key == "report") {
      config.report_path = value;
    } else if (key == "key-seed") {
      config.key_seed = value;
    } else if (key == "class-manifest") {
      config.class_manifest = value;
    } else if (key == "write-class-manifest") {
      config.write_class_manifest = value;
    } else if (key == "trust-dir") {
      config.extra_trust_dirs.push_back(value);
    } else {
      std::cerr << "[bouncer] ignoring unknown option: " << key << '\n';
    }
  }
  return config;
}

std::string short_hex(const std::string &hex) {
  return hex.size() > 12 ? hex.substr(0, 12) : hex;
}

// caller holds state->lock
void record(const bouncer::Detection &detection) {
  state->events.push_back(bouncer::report_from_detection(detection));
  std::cerr << "[bouncer] " << bouncer::severity_to_string(detection.severity)
            << ' ' << detection.kind << ' ' << detection.subject << " | "
            << detection.detail << '\n';
}

std::size_t load_class_manifest(const std::string &path,
                                bouncer::ClassHashTracker &classes) {
  std::ifstream input(path);
  if (!input) {
    std::cerr << "[bouncer] unable to open class manifest: " << path << '\n';
    return 0;
  }
  std::size_t loaded = 0;
  std::string line;
  while (std::getline(input, line)) {
    if (line.empty() || line.front() == '#') {
      continue;
    }
    const auto space = line.find(' ');
    if (space == std::string::npos || space == 0 ||
        space + 1 >= line.size()) {
      continue;
    }
    classes.expect_hash(line.substr(space + 1), line.substr(0, space));
    ++loaded;
  }
  return loaded;
}

void write_class_manifest(const std::string &path,
                          const bouncer::ClassHashTracker &classes) {
  std::ofstream output(path);
  if (!output) {
    std::cerr << "[bouncer] unable to write class manifest: " << path << '\n';
    return;
  }
  output << "# sha256 class-name, one per line\n";
  for (const auto &[name, hash] : classes.observed_hashes()) {
    output << hash << ' ' << name << '\n';
  }
  std::cerr << "[bouncer] wrote class manifest with "
            << classes.observed_hashes().size() << " entries -> " << path
            << '\n';
}

std::string pretty_class_signature(const char *signature) {
  if (signature == nullptr) {
    return "<unknown>";
  }
  std::string name(signature);
  if (name.size() >= 2 && name.front() == 'L' && name.back() == ';') {
    return name.substr(1, name.size() - 2);
  }
  return name;
}

// caller holds state->lock
void write_signed_report() {
  if (state->report_written) {
    return;
  }
  state->report_written = true;

  std::ostringstream payload;
  payload << "{\"agent\":\"bytecode-bouncer\",\"class_loads\":"
          << state->class_loads << ",\"events\":[";
  for (std::size_t i = 0; i < state->events.size(); ++i) {
    if (i > 0) {
      payload << ',';
    }
    payload << bouncer::report_to_json(state->events[i]);
  }
  payload << "],\"native_binds\":" << state->native_binds
          << ",\"tracked_classes\":" << state->classes.tracked_count() << "}";

  const auto signed_report =
      bouncer::sign_json_payload(payload.str(), state->key);
  std::ofstream output(state->config.report_path);
  if (output) {
    output << bouncer::signed_report_to_json(signed_report) << '\n';
    std::cerr << "[bouncer] signed report (" << state->events.size()
              << " findings) -> " << state->config.report_path << '\n';
  } else {
    std::cerr << "[bouncer] unable to write report: "
              << state->config.report_path << '\n';
  }
}

void JNICALL on_class_file_load(jvmtiEnv *, JNIEnv *,
                                jclass class_being_redefined, jobject,
                                const char *name, jobject,
                                jint class_data_len,
                                const unsigned char *class_data, jint *,
                                unsigned char **) {
  if (state == nullptr || class_data == nullptr || class_data_len <= 0) {
    return;
  }
  // hidden and anonymous classes arrive with no name; each is unique, so
  // tracking them under one key would fabricate endless "changes"
  if (name == nullptr) {
    return;
  }

  const auto size = static_cast<std::size_t>(class_data_len);
  const std::string hash = bouncer::stable_hash_hex(class_data, size);

  std::lock_guard<std::mutex> guard(state->lock);
  ++state->class_loads;
  const auto change = state->classes.observe_hashed(name, hash, size);
  if (!change.has_value()) {
    return;
  }

  std::ostringstream detail;
  detail << "hash " << short_hex(change->previous_hash) << " -> "
         << short_hex(change->current_hash) << " size "
         << change->previous_size << " -> " << change->current_size;
  if (class_being_redefined != nullptr) {
    detail << " (redefinition)";
  }
  record(bouncer::Detection{
      bouncer::Severity::high,
      change->manifest_mismatch ? "class-manifest-mismatch"
                                : "class-bytecode-changed",
      name, detail.str()});
}

void JNICALL on_native_method_bind(jvmtiEnv *jvmti, JNIEnv *, jthread,
                                   jmethodID method, void *address, void **) {
  if (state == nullptr) {
    return;
  }

  std::string class_name = "<unknown>";
  std::string method_name = "<unknown>";
  std::string signature;

  char *raw_name = nullptr;
  char *raw_signature = nullptr;
  if (jvmti->GetMethodName(method, &raw_name, &raw_signature, nullptr) ==
      JVMTI_ERROR_NONE) {
    if (raw_name != nullptr) {
      method_name = raw_name;
    }
    if (raw_signature != nullptr) {
      signature = raw_signature;
    }
    jvmti->Deallocate(reinterpret_cast<unsigned char *>(raw_name));
    jvmti->Deallocate(reinterpret_cast<unsigned char *>(raw_signature));
  }

  jclass declaring = nullptr;
  if (jvmti->GetMethodDeclaringClass(method, &declaring) == JVMTI_ERROR_NONE &&
      declaring != nullptr) {
    char *class_signature = nullptr;
    if (jvmti->GetClassSignature(declaring, &class_signature, nullptr) ==
        JVMTI_ERROR_NONE) {
      class_name = pretty_class_signature(class_signature);
      jvmti->Deallocate(reinterpret_cast<unsigned char *>(class_signature));
    }
  }

  std::string module_path;
  Dl_info info{};
  if (address != nullptr && dladdr(address, &info) != 0 &&
      info.dli_fname != nullptr) {
    module_path = info.dli_fname;
  }

  const bouncer::NativeBindEvent event{class_name, method_name, signature,
                                       address, module_path};

  std::lock_guard<std::mutex> guard(state->lock);
  ++state->native_binds;
  if (const auto finding = state->binds.observe_bind(event)) {
    record(*finding);
  }
}

void JNICALL on_vm_init(jvmtiEnv *, JNIEnv *, jthread) {
  if (state == nullptr) {
    return;
  }
  std::lock_guard<std::mutex> guard(state->lock);
  std::cerr << "[bouncer] vm live, " << state->modules.pinned_count()
            << " modules pinned across "
            << state->modules.trusted_directory_count()
            << " trusted directories\n";
}

void JNICALL on_vm_death(jvmtiEnv *, JNIEnv *) {
  if (state == nullptr) {
    return;
  }
  std::lock_guard<std::mutex> guard(state->lock);

  // final sweep: catches libraries that were dlopened without ever binding a
  // java method, and pinned files that changed on disk since startup
  const auto findings =
      bouncer::sweep_modules(bouncer::walk_loaded_modules(), state->modules,
                             bouncer::RehashPolicy::verify_content);
  for (const auto &finding : findings) {
    record(finding);
  }

  if (!state->config.write_class_manifest.empty()) {
    write_class_manifest(state->config.write_class_manifest, state->classes);
  }

  std::cerr << "[bouncer] shutdown: " << state->class_loads
            << " class loads hashed, " << state->native_binds
            << " native binds checked, " << state->events.size()
            << " findings\n";
  write_signed_report();
}

} // namespace

namespace bouncer {

bool jvmti_agent_compiled_with_headers() { return true; }

} // namespace bouncer

extern "C" JNIEXPORT jint JNICALL Agent_OnLoad(JavaVM *vm, char *options,
                                               void *) {
  jvmtiEnv *jvmti = nullptr;
  const jint result =
      vm->GetEnv(reinterpret_cast<void **>(&jvmti), JVMTI_VERSION_1_2);
  if (result != JNI_OK || jvmti == nullptr) {
    return JNI_ERR;
  }

  state = new AgentState();
  state->config = parse_options(options);
  state->key = bouncer::make_local_key(state->config.key_seed);

  jvmtiCapabilities caps{};
  caps.can_generate_all_class_hook_events = 1;
  caps.can_generate_native_method_bind_events = 1;
  if (jvmti->AddCapabilities(&caps) != JVMTI_ERROR_NONE) {
    return JNI_ERR;
  }

  jvmtiEventCallbacks callbacks{};
  callbacks.ClassFileLoadHook = &on_class_file_load;
  callbacks.NativeMethodBind = &on_native_method_bind;
  callbacks.VMInit = &on_vm_init;
  callbacks.VMDeath = &on_vm_death;
  if (jvmti->SetEventCallbacks(&callbacks, sizeof(callbacks)) !=
      JVMTI_ERROR_NONE) {
    return JNI_ERR;
  }
  jvmti->SetEventNotificationMode(JVMTI_ENABLE,
                                  JVMTI_EVENT_CLASS_FILE_LOAD_HOOK, nullptr);
  jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_NATIVE_METHOD_BIND,
                                  nullptr);
  jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_VM_INIT, nullptr);
  jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_VM_DEATH, nullptr);

  {
    std::lock_guard<std::mutex> guard(state->lock);

    // everything loaded before the agent is the baseline: pin file contents
    // and trust the directories they came from. later loads are judged
    // against that, so nothing depends on module names.
    char *java_home = nullptr;
    if (jvmti->GetSystemProperty("java.home", &java_home) ==
            JVMTI_ERROR_NONE &&
        java_home != nullptr) {
      state->modules.trust_directory(java_home);
      jvmti->Deallocate(reinterpret_cast<unsigned char *>(java_home));
    }
    for (const auto &dir : state->config.extra_trust_dirs) {
      state->modules.trust_directory(dir);
    }
    for (const auto &module : bouncer::walk_loaded_modules()) {
      const auto normalized =
          bouncer::ModuleTrustPolicy::normalize_path(module.path);
      state->modules.pin_module(normalized);
      state->modules.trust_directory(
          bouncer::ModuleTrustPolicy::parent_directory(normalized));
    }

    for (const auto &finding : bouncer::find_preload_environment()) {
      record(finding);
    }

    if (!state->config.class_manifest.empty()) {
      const auto loaded =
          load_class_manifest(state->config.class_manifest, state->classes);
      std::cerr << "[bouncer] loaded " << loaded
                << " expected class hashes from "
                << state->config.class_manifest << '\n';
    }

    std::cerr << "[bouncer] agent loaded, pinned "
              << state->modules.pinned_count() << " modules, trusting "
              << state->modules.trusted_directory_count() << " directories\n";
  }

  return JNI_OK;
}

extern "C" JNIEXPORT void JNICALL Agent_OnUnload(JavaVM *) {
  if (state == nullptr) {
    return;
  }
  std::lock_guard<std::mutex> guard(state->lock);
  // vm death normally writes the report; this is the fallback path
  write_signed_report();
}

#else

namespace bouncer {

bool jvmti_agent_compiled_with_headers() { return false; }

} // namespace bouncer

extern "C" int Agent_OnLoad(void *, char *, void *) {
  std::cerr << "bytecode-bouncer jvmti headers were not available at build time"
            << std::endl;
  return -1;
}

extern "C" void Agent_OnUnload(void *) {}

#endif
