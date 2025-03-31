cmake_minimum_required(VERSION 3.20)

project(bytecode_bouncer VERSION 0.1.0 LANGUAGES CXX)

option(BOUNCER_BUILD_DEMO "Build the synthetic cheat demo runner" ON)
option(BOUNCER_BUILD_JVMTI_AGENT "Build the JVMTI shared library when a local JDK is available" ON)

enable_testing()

add_subdirectory(native)
