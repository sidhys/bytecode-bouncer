find_package(Python3 REQUIRED COMPONENTS Interpreter)

set(bouncer_demo_classes "${CMAKE_CURRENT_BINARY_DIR}/classes")
set(bouncer_demo_replacement "${CMAKE_CURRENT_BINARY_DIR}/replacement")
set(bouncer_demo_jar "${CMAKE_CURRENT_BINARY_DIR}/replacement-agent.jar")
set(bouncer_demo_sources
    java/bouncer/demo/Demo.java
    java/bouncer/demo/Score.java
    java/bouncer/demo/ReplacementAgent.java
)
list(TRANSFORM bouncer_demo_sources PREPEND "${CMAKE_CURRENT_SOURCE_DIR}/")

add_custom_command(
    OUTPUT "${bouncer_demo_jar}"
           "${bouncer_demo_classes}/bouncer/demo/Score.class"
           "${bouncer_demo_replacement}/bouncer/demo/Score.class"
           "${bouncer_demo_classes}/bouncer/demo/Demo.class"
           "${bouncer_demo_classes}/bouncer/demo/ReplacementAgent.class"
    COMMAND ${CMAKE_COMMAND} -E make_directory
            "${bouncer_demo_classes}" "${bouncer_demo_replacement}"
    COMMAND "${bouncer_jdk_home}/bin/javac" -d "${bouncer_demo_classes}"
            ${bouncer_demo_sources}
    COMMAND "${bouncer_jdk_home}/bin/javac" -d "${bouncer_demo_replacement}"
            "${CMAKE_CURRENT_SOURCE_DIR}/replacement/bouncer/demo/Score.java"
    COMMAND "${bouncer_jdk_home}/bin/jar" cfm "${bouncer_demo_jar}"
            "${CMAKE_CURRENT_SOURCE_DIR}/java/MANIFEST.MF"
            -C "${bouncer_demo_classes}" bouncer/demo/ReplacementAgent.class
    DEPENDS ${bouncer_demo_sources}
            replacement/bouncer/demo/Score.java java/MANIFEST.MF
    VERBATIM
)
add_custom_target(bouncer_demo_classes DEPENDS "${bouncer_demo_jar}"
    "${bouncer_demo_classes}/bouncer/demo/Score.class"
    "${bouncer_demo_replacement}/bouncer/demo/Score.class"
    "${bouncer_demo_classes}/bouncer/demo/Demo.class"
    "${bouncer_demo_classes}/bouncer/demo/ReplacementAgent.class")

add_executable(bouncer_demo bouncer_demo.cpp)
set_target_properties(bouncer_demo PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/native")
target_compile_features(bouncer_demo PRIVATE cxx_std_17)
target_compile_definitions(bouncer_demo PRIVATE
    BOUNCER_DEMO_PYTHON="${Python3_EXECUTABLE}"
    BOUNCER_DEMO_RUNNER="${PROJECT_SOURCE_DIR}/tools/run_live_demo.py"
    BOUNCER_DEMO_JAVA="${bouncer_jdk_home}/bin/java"
    BOUNCER_DEMO_AGENT="$<TARGET_FILE:bouncer_jvmti_agent>"
    BOUNCER_DEMO_CLASSES="${bouncer_demo_classes}"
    BOUNCER_DEMO_REPLACEMENT="${bouncer_demo_replacement}"
    BOUNCER_DEMO_JAR="${bouncer_demo_jar}"
    BOUNCER_DEMO_REPORTS="${CMAKE_CURRENT_BINARY_DIR}/reports"
)
add_dependencies(bouncer_demo bouncer_jvmti_agent bouncer_demo_classes)

add_test(NAME bouncer_demo COMMAND bouncer_demo)
