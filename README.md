# bytecode-bouncer

small c++ jvm anti-tamper prototype. a jvmti agent rides inside the jvm,
sha-256s every class as it loads, resolves every native method bind to the
library it lands in, and pins the file contents of every native module that
was present at startup. anything that shows up later is judged by where it
lives and what it hashes to, never by its file name. findings go to an
hmac-signed report you can verify off-box.

## how to run

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
./build/native/bouncer_demo
java -agentpath:build/native/libbouncer_jvmti_agent.dylib -version
```

on linux the agent file is usually `libbouncer_jvmti_agent.so`. a clean run
looks like this:

```
[bouncer] agent loaded, pinned 521 modules, trusting 347 directories
[bouncer] vm live, 522 modules pinned across 347 trusted directories
java version "19.0.1" 2022-10-18
Java(TM) SE Runtime Environment (build 19.0.1+10-21)
Java HotSpot(TM) 64-Bit Server VM (build 19.0.1+10-21, mixed mode, sharing)
[bouncer] shutdown: 16 class loads hashed, 188 native binds checked, 0 findings
[bouncer] signed report (0 findings) -> bouncer-report.json
```

## catching an injected library

the build also produces `libbouncer_fake_cheat.dylib`, a do-nothing library
that stands in for a cheat. load it from a directory the bouncer never
trusted and the shutdown sweep flags it:

```
$ mkdir -p /tmp/injected && cp build/native/libbouncer_fake_cheat.dylib /tmp/injected/
$ java -agentpath:build/native/libbouncer_jvmti_agent.dylib \
       -agentpath:/tmp/injected/libbouncer_fake_cheat.dylib -version
[bouncer] agent loaded, pinned 521 modules, trusting 347 directories
[bouncer] vm live, 522 modules pinned across 347 trusted directories
java version "19.0.1" 2022-10-18
[bouncer] HIGH untrusted-native-module /private/tmp/injected/libbouncer_fake_cheat.dylib | loaded from outside every trusted directory
[bouncer] shutdown: 16 class loads hashed, 188 native binds checked, 1 findings
[bouncer] signed report (1 findings) -> bouncer-report.json
```

renaming the file changes nothing. an earlier version of this project
allowlisted modules by name fragments, which meant a cheat called
`libjava-x.dylib` matched the `libjava` rule from anywhere on disk. trust is
now a property of the directory a module loads from plus its content hash,
and the spoof case is a regression test.

## class baselines

by default the class tracker is trust-on-first-use: the first load of each
class is the baseline and later redefinitions get flagged. to pin classes
across runs, record a manifest once and enforce it after:

```
$ java -agentpath:<agent>=write-class-manifest=classes.manifest Hello
[bouncer] wrote class manifest with 64 entries -> classes.manifest
$ java -agentpath:<agent>=class-manifest=classes.manifest Hello
[bouncer] loaded 64 expected class hashes from classes.manifest
[bouncer] shutdown: 64 class loads hashed, 197 native binds checked, 0 findings
```

a class that loads with bytecode the manifest does not expect:

```
[bouncer] HIGH class-manifest-mismatch Hello | hash aaaaaaaaaaaa -> e3446afe50a9 size 0 -> 422
```

## agent options

comma separated after `=` on the agentpath:

```
report=<path>                 where the signed report goes, default bouncer-report.json
key-seed=<seed>               hmac key seed, default bouncer-dev-seed
class-manifest=<path>         enforce expected class hashes
write-class-manifest=<path>   record observed class hashes at shutdown
trust-dir=<dir>               extra trust root, repeatable
```

## verifying reports

reports are json signed with hmac-sha256 (`bb-hmac-sha256-v1`). the hash and
hmac are a vendored implementation checked against the fips / rfc 4231 test
vectors, so macos and linux produce identical digests and mac comparison is
constant-time.

```
$ python3 tools/verify_report.py bouncer-report.json --seed bouncer-dev-seed
verified
$ sed 's/untrusted-native-module/totally-fine-module/' bouncer-report.json > tampered.json
$ python3 tools/verify_report.py tampered.json --seed bouncer-dev-seed
mac mismatch
```

## what it will not catch

honest limits, in rough order of how much they matter:

- the hmac key lives inside the process it guards, so a cheat that fully owns
  the process can sign its own clean report. a real deployment wants
  asymmetric signatures with the private key off-box.
- everything loaded before the agent is baseline. inject earlier than the
  bouncer and you are part of the trusted snapshot. on macos the hardened
  runtime already strips `DYLD_INSERT_LIBRARIES` for the jdk's java binary
  before anything runs; the `LD_PRELOAD` check mostly matters on linux.
- module pins hash files on disk. patching already-mapped code in memory
  does not touch the file, so only the class-level checks see that kind of
  tamper.
- an attacker who can write into a trusted directory (java.home, /usr/lib)
  is outside the threat model.
- the agent has to be on the command line. attach-after-start agents and
  whatever they retransform are not covered.
- `java -version` only hashes ~16 classes because almost nothing loads
  before it exits. real workloads hash everything that reaches
  ClassFileLoadHook.

## license

mit, see LICENSE.
