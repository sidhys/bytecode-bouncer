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

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(bouncer_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(UNIX AND NOT APPLE)
    target_link_libraries(bouncer_core PUBLIC dl)
endif()