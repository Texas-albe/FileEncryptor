cmake_minimum_required(VERSION 3.15)
project(yaml_cpp_android CXX)

# Android 侧最小构建：绕开官方 CMakeLists
# 官方树缺 yaml-cpp-config.cmake.in 等模板，直接 glob src
set(YAML_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../yaml-cpp")

file(GLOB_RECURSE YAML_SOURCES "${YAML_ROOT}/src/*.cpp")
list(FILTER YAML_SOURCES EXCLUDE REGEX "contrib")

add_library(yaml-cpp STATIC ${YAML_SOURCES})

target_include_directories(yaml-cpp PUBLIC
    "${YAML_ROOT}/include"
    "${YAML_ROOT}/src")

target_compile_features(yaml-cpp PUBLIC cxx_std_17)

install(TARGETS yaml-cpp ARCHIVE DESTINATION lib)
install(DIRECTORY "${YAML_ROOT}/include/yaml-cpp" DESTINATION include)
