#include "bouncer/agent.hpp"

#include <iostream>

#if __has_include(<jvmti.h>)
#include <jvmti.h>

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

  std::cerr << "bytecode-bouncer jvmti agent loaded" << std::endl;
  return JNI_OK;
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

#endif