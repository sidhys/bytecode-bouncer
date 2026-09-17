#include "bouncer/agent.hpp"
#include "bouncer/class_hash.hpp"
#include "bouncer/report.hpp"

#include <jvmti.h>

#include <atomic>
#include <cstdio>
#include <fstream>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>

namespace {

struct AgentState {
  bouncer::ClassHashTracker classes;
  std::mutex loader_mutex;
  std::mutex report_mutex;
  jlong next_loader_id = 1;
  std::ofstream output;
  std::atomic<unsigned long long> class_events{0};
  std::atomic<unsigned long long> bind_events{0};
  std::atomic<unsigned long long> changes{0};
  std::atomic<unsigned long long> errors{0};
};

// Created before callbacks are enabled; released only when the VM unloads us.
std::unique_ptr<AgentState> state;

void check_jvmti(jvmtiError error, const char *operation) {
  if (error != JVMTI_ERROR_NONE) {
    throw std::runtime_error(std::string(operation) + " failed (JVMTI error " +
                             std::to_string(error) + ")");
  }
}

void callback_error(const char *message) noexcept {
  state->errors.fetch_add(1, std::memory_order_relaxed);
  std::fprintf(stderr, "bytecode-bouncer monitor error: %s\n", message);
}

std::uint64_t loader_id(jvmtiEnv *jvmti, jobject loader) {
  if (loader == nullptr) {
    return 0; // Bootstrap loader.
  }
  // Tags belong to this JVMTI environment. JNI reference addresses do not
  // identify loaders: two references can point at the same object.
  std::lock_guard<std::mutex> lock(state->loader_mutex);
  jlong tag = 0;
  check_jvmti(jvmti->GetTag(loader, &tag), "GetTag");
  if (tag == 0) {
    tag = state->next_loader_id++;
    check_jvmti(jvmti->SetTag(loader, tag), "SetTag");
  }
  return static_cast<std::uint64_t>(tag);
}

void report_change(const bouncer::ClassChange &change, bool redefinition) {
  const auto report = bouncer::report_from_detection(
      {bouncer::Severity::medium, "class-bytecode-change", change.class_name,
       redefinition ? "different class bytes observed during redefinition or retransformation"
                    : "different class bytes observed on a later load"},
      {{"loader_id", std::to_string(change.loader_id)},
       {"previous_hash", change.previous_hash},
       {"current_hash", change.current_hash},
       {"previous_size", std::to_string(change.previous_size)},
       {"current_size", std::to_string(change.current_size)},
       {"event", redefinition ? "redefinition-or-retransformation" : "class-load"}});
  const auto json = bouncer::report_to_json(report);
  std::lock_guard<std::mutex> lock(state->report_mutex);
  if (state->output.is_open()) {
    state->output << json << '\n';
    state->output.flush();
    if (!state->output) {
      throw std::runtime_error("unable to write detection report");
    }
  }
  state->changes.fetch_add(1, std::memory_order_relaxed);
  std::fprintf(stderr, "[MEDIUM] class-bytecode-change | %s | loader=%llu\n",
               change.class_name.c_str(),
               static_cast<unsigned long long>(change.loader_id));
}

void JNICALL on_class_file_load(jvmtiEnv *jvmti, JNIEnv *, jclass redefined,
                                jobject loader, const char *name, jobject,
                                jint length, const unsigned char *bytes,
                                jint *, unsigned char **) noexcept {
  state->class_events.fetch_add(1, std::memory_order_relaxed);
  try {
    if (name == nullptr || bytes == nullptr || length <= 0) {
      return;
    }
    const auto identity = loader_id(jvmti, loader);
    const std::vector<std::uint8_t> bytecode(bytes, bytes + length);
    const auto change = state->classes.observe(name, bytecode, identity);
    if (change) {
      report_change(*change, redefined != nullptr);
    }
  } catch (const std::exception &error) {
    callback_error(error.what());
  } catch (...) {
    callback_error("unexpected exception in ClassFileLoadHook");
  }
}

void JNICALL on_native_method_bind(jvmtiEnv *, JNIEnv *, jthread, jmethodID,
                                   void *, void **) noexcept {
  state->bind_events.fetch_add(1, std::memory_order_relaxed);
}

void JNICALL on_object_free(jvmtiEnv *, jlong tag) noexcept {
  try {
    // Only loader objects are tagged. No JNI/JVMTI operations or loader_mutex
    // acquisition here: this callback runs during garbage collection.
    state->classes.forget_loader(static_cast<std::uint64_t>(tag));
  } catch (...) {
    callback_error("unable to release an unloaded classloader's snapshots");
  }
}

} // namespace

namespace bouncer {
bool jvmti_agent_compiled_with_headers() { return true; }
} // namespace bouncer

extern "C" JNIEXPORT jint JNICALL Agent_OnLoad(JavaVM *vm, char *options,
                                               void *) {
  if (state) {
    std::fprintf(stderr, "bytecode-bouncer startup error: agent is already loaded\n");
    return JNI_ERR;
  }
  jvmtiEnv *jvmti = nullptr;
  try {
    if (vm->GetEnv(reinterpret_cast<void **>(&jvmti), JVMTI_VERSION_1_2) !=
            JNI_OK ||
        jvmti == nullptr) {
      throw std::runtime_error("JVMTI 1.2 is unavailable");
    }

    auto next = std::make_unique<AgentState>();
    const std::string config = options == nullptr ? "" : options;
    if (!config.empty()) {
      if (config.rfind("output=", 0) != 0 || config.size() == 7) {
        throw std::runtime_error("expected agent option output=/path/to/report.jsonl");
      }
      next->output.open(config.substr(7), std::ios::out | std::ios::trunc);
      if (!next->output) {
        throw std::runtime_error("cannot open report output: " + config.substr(7));
      }
    }

    jvmtiCapabilities caps{};
    caps.can_generate_all_class_hook_events = 1;
    caps.can_generate_native_method_bind_events = 1;
    caps.can_retransform_classes = 1;
    caps.can_tag_objects = 1;
    caps.can_generate_object_free_events = 1;
    check_jvmti(jvmti->AddCapabilities(&caps), "AddCapabilities");

    jvmtiEventCallbacks callbacks{};
    callbacks.ClassFileLoadHook = &on_class_file_load;
    callbacks.NativeMethodBind = &on_native_method_bind;
    callbacks.ObjectFree = &on_object_free;
    check_jvmti(jvmti->SetEventCallbacks(&callbacks, sizeof(callbacks)),
                 "SetEventCallbacks");
    state = std::move(next);
    for (const auto event : {JVMTI_EVENT_CLASS_FILE_LOAD_HOOK,
                              JVMTI_EVENT_NATIVE_METHOD_BIND,
                              JVMTI_EVENT_OBJECT_FREE}) {
      check_jvmti(jvmti->SetEventNotificationMode(JVMTI_ENABLE, event, nullptr),
                   "SetEventNotificationMode");
    }

    std::fprintf(stderr, "bytecode-bouncer jvmti agent loaded\n");
    return JNI_OK;
  } catch (const std::exception &error) {
    std::fprintf(stderr, "bytecode-bouncer startup error: %s\n", error.what());
  } catch (...) {
    std::fprintf(stderr, "bytecode-bouncer startup error: unexpected exception\n");
  }
  if (jvmti != nullptr) {
    jvmti->DisposeEnvironment();
  }
  state.reset();
  return JNI_ERR;
}

extern "C" JNIEXPORT void JNICALL Agent_OnUnload(JavaVM *) {
  if (!state) {
    return;
  }
  std::fprintf(stderr,
               "bytecode-bouncer jvmti agent unloaded class_file_load_events=%llu"
               " native_method_bind_events=%llu changes=%llu errors=%llu\n",
               state->class_events.load(std::memory_order_relaxed),
               state->bind_events.load(std::memory_order_relaxed),
               state->changes.load(std::memory_order_relaxed),
               state->errors.load(std::memory_order_relaxed));
  state.reset();
}
