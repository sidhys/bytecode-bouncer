# bytecode-bouncer

A C++ agent that reports when a loaded Java class changes.

Needs macOS, CMake 3.20+, a JDK and Python 3.

## Build

```sh
export JAVA_HOME=$(/usr/libexec/java_home)
cmake -S . -B build
cmake --build build
```

## Example

`Score.value()` starts out returning `10`. The example in `demo/` swaps in a
version that returns `9000` while Java is still running:

```java
System.out.println("before: " + Score.value());
ReplacementAgent.replace(Score.class, Files.readAllBytes(Paths.get(args[0])));
System.out.println("after: " + Score.value());
```

Compile both versions and package the Java agent that replaces the class:

```sh
mkdir -p build/example build/replacement
"$JAVA_HOME/bin/javac" -d build/example demo/java/bouncer/demo/*.java
"$JAVA_HOME/bin/javac" -d build/replacement demo/replacement/bouncer/demo/Score.java
"$JAVA_HOME/bin/jar" cfm build/replacement-agent.jar demo/java/MANIFEST.MF \
  -C build/example bouncer/demo/ReplacementAgent.class
```

Run the example with Bouncer loaded:

```sh
"$JAVA_HOME/bin/java" \
  "-agentpath:$PWD/build/native/libbouncer_jvmti_agent.dylib=output=$PWD/build/report.jsonl" \
  -javaagent:build/replacement-agent.jar \
  -cp build/example bouncer.demo.Demo build/replacement/bouncer/demo/Score.class
```

You'll see:

```text
before: 10
[MEDIUM] class-bytecode-change | bouncer/demo/Score | loader=1
after: 9000
```

The report in `build/report.jsonl` includes the class name and its old and new hashes.

## Use it on your app

```sh
"$JAVA_HOME/bin/java" \
  "-agentpath:$PWD/build/native/libbouncer_jvmti_agent.dylib=output=$PWD/build/report.jsonl" \
  -jar app.jar
```

Bouncer records each class as it loads and reports changes to its bytes.
