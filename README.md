# bytecode-bouncer

small c++ jvm anti-tamper prototype. it checks class hashes, classloader rules,
native modules, native binds, and signed reports. if a jdk is installed, it also
builds a jvmti agent.

## how to run

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
./build/native/bouncer_demo
java -agentpath:build/native/libbouncer_jvmti_agent.dylib -version
```

on linux the agent file is usually `libbouncer_jvmti_agent.so`.
