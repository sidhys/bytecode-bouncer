add_library(bouncer_core STATIC
    src/class_hash.cpp
    src/classloader_rules.cpp
    src/hash.cpp
    src/module_walker.cpp
    src/native_bind_hook.cpp
    src/report.cpp
    src/signing.cpp
)

target_include_directories(bouncer_core
    PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/include
)

target_compile_features(bouncer_core PUBLIC cxx_std_17)
set_target_properties(bouncer_core PROPERTIES POSITION_INDEPENDENT_CODE ON)
find_package(Threads REQUIRED)
target_link_libraries(bouncer_core PUBLIC Threads::Threads)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(bouncer_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(UNIX AND NOT APPLE)
    target_link_libraries(bouncer_core PUBLIC dl)
endif()

target_compile_definitions(bouncer_core
    PUBLIC
        BOUNCER_PROJECT_SOURCE_DIR="${PROJECT_SOURCE_DIR}"
)

add_executable(bouncer_tests
    tests/bouncer_tests.cpp
)

target_link_libraries(bouncer_tests PRIVATE bouncer_core)
target_compile_definitions(bouncer_tests PRIVATE
    BOUNCER_FIXTURE_DIR="${PROJECT_SOURCE_DIR}/fixtures"
)

add_test(NAME bouncer_tests COMMAND bouncer_tests)

if(BOUNCER_BUILD_JVMTI_AGENT)
    set(bouncer_jdk_home "")
    if(DEFINED ENV{JAVA_HOME} AND EXISTS "$ENV{JAVA_HOME}")
        set(bouncer_jdk_home "$ENV{JAVA_HOME}")
    elseif(EXISTS "/usr/libexec/java_home")
        execute_process(
            COMMAND /usr/libexec/java_home
            OUTPUT_VARIABLE bouncer_jdk_home
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET
        )
    endif()

    if(bouncer_jdk_home STREQUAL "")
        message(WARNING "skipping bouncer_jvmti_agent because no local JDK was found")
    else()
        if(NOT EXISTS "${bouncer_jdk_home}/include/jvmti.h" OR
           NOT EXISTS "${bouncer_jdk_home}/include/jni.h")
            message(FATAL_ERROR "JAVA_HOME must point to a JDK with JNI and JVMTI headers")
        endif()
        add_library(bouncer_jvmti_agent SHARED
            src/agent_jvmti.cpp
        )
        target_include_directories(bouncer_jvmti_agent PRIVATE
            "${bouncer_jdk_home}/include"
        )
        if(APPLE)
            target_include_directories(bouncer_jvmti_agent PRIVATE
                "${bouncer_jdk_home}/include/darwin"
            )
        elseif(UNIX)
            target_include_directories(bouncer_jvmti_agent PRIVATE
                "${bouncer_jdk_home}/include/linux"
            )
        endif()
        target_link_libraries(bouncer_jvmti_agent PRIVATE bouncer_core)
        target_compile_features(bouncer_jvmti_agent PRIVATE cxx_std_17)
        if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
            target_compile_options(bouncer_jvmti_agent PRIVATE -Wall -Wextra -Wpedantic)
        endif()

        if(BOUNCER_BUILD_DEMO)
            add_subdirectory("${PROJECT_SOURCE_DIR}/demo" "${PROJECT_BINARY_DIR}/demo")
        endif()
    endif()
endif()
