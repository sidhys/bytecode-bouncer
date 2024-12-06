# bytecode-bouncer

small c++ jvm anti-tamper prototype. it checks class hashes, classloader rules,
native modules, native binds, and signed reports. if a jdk is installed, it also
builds a jvmti agent.