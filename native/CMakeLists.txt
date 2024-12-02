add_library(bouncer_core STATIC)

target_include_directories(bouncer_core
    PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/include
)

target_compile_features(bouncer_core PUBLIC cxx_std_17)