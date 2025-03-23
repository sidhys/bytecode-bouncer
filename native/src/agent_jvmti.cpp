#include "bouncer/agent.hpp"

#include <atomic>
#include <iostream>

#if __has_include(<jvmti.h>)
#include <jvmti.h>

namespace {

std::atomic<unsigned long long> class_file_load_events{0};
std::atomic<unsigned long long> native_method_bind_events{0};

void JNICALL on_class_file_load(jvmtiEnv *, JNIEnv *, jclass, jobject,
                                const char *, jobject, jint,
                                const unsigned char *, jint *,
                                unsigned char **) {
  class_file_load_events.fetch_add(1, std::memory_order_relaxed);
}

void JNICALL on_native_method_bind(jvmtiEnv *, JNIEnv *, jthread, jmethodID,
                                   void *, void **) {
  native_method_bind_events.fetch_add(1, std::memory_order_relaxed);
}

} // namespace

namespace bouncer {

bool jvmti_agent_compiled_with_headers() { return true; }

} // namespace bouncer

extern "C" JNIEXPORT jint JNICALL Agent_OnLoad(JavaVM *vm, char *options,
                                               void *) {
  (void)options;
  jvmtiEnv *jvmti = nullptr;
  const jint result =
      vm->GetEnv(reinterpret_cast<void **>(&jvmti), JVMTI_VERSION_1_2);
  if (result != JNI_OK || jvmti == nullptr) {
    return JNI_ERR;
  }

  jvmtiCapabilities caps{};
  caps.can_generate_all_class_hook_events = 1;
  caps.can_generate_native_method_bind_events = 1;
  caps.can_redefine_classes = 1;
  caps.can_retransform_classes = 1;
  jvmti->AddCapabilities(&caps);

  jvmtiEventCallbacks callbacks{};
  callbacks.ClassFileLoadHook = &on_class_file_load;
  callbacks.NativeMethodBind = &on_native_method_bind;
  if (jvmti->SetEventCallbacks(&callbacks, sizeof(callbacks)) !=
      JVMTI_ERROR_NONE) {
    return JNI_ERR;
  }
  jvmti->SetEventNotificationMode(JVMTI_ENABLE,
                                  JVMTI_EVENT_CLASS_FILE_LOAD_HOOK, nullptr);
  jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_NATIVE_METHOD_BIND,
                                  nullptr);

  std::cerr << "bytecode-bouncer jvmti agent loaded" << std::endl;
  return JNI_OK;
}

extern "C" JNIEXPORT void JNICALL Agent_OnUnload(JavaVM *) {
  std::cerr << "bytecode-bouncer jvmti agent unloaded"
            << " class_file_load_events="
            << class_file_load_events.load(std::memory_order_relaxed)
            << " native_method_bind_events="
            << native_method_bind_events.load(std::memory_order_relaxed)
            << std::endl;
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
