cmake_minimum_required(VERSION 3.15)
project(libsodium C)

# Android 最小构建：只编核心实现
# 排除 x86 SIMD 与 amd64 专用目录（arm64 上无法编译）
file(GLOB_RECURSE SODIUM_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/libsodium/*.c)
list(FILTER SODIUM_SOURCES EXCLUDE REGEX
     "(sse2|ssse3|sse41|aesni|avx|xmm6|amd64|armcrypto|randombytes/internal)")

add_library(sodium STATIC ${SODIUM_SOURCES})

target_include_directories(sodium PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src/libsodium/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src/libsodium/include/sodium)

target_compile_definitions(sodium PRIVATE SODIUM_STATIC=1)

# 1.0.21 源码不引用 config.h，无需 autotools 生成的配置头
target_compile_options(sodium PRIVATE -fPIC)

# 安装为标准前缀，供 CLI 的 -DSODIUM_ROOT 使用
install(TARGETS sodium ARCHIVE DESTINATION lib)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/libsodium/include/sodium.h DESTINATION include)
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src/libsodium/include/sodium DESTINATION include)
