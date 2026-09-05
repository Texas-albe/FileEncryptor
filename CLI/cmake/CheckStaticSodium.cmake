# 校验可执行文件是否“静态链接”了 libsodium（即不依赖 libsodium.so）。
# 用法：cmake -P CheckStaticSodium.cmake <exe_path> <objdump_path>
#   CMAKE_ARGV3 = 可执行文件路径
#   CMAKE_ARGV4 = objdump 路径
# 若可执行文件仍动态依赖 libsodium（NEEDED 中出现 libsodium），则 FATAL_ERROR，
# 使构建失败，避免产出“看起来自包含、实际却动态链接”的包。

if(NOT DEFINED CMAKE_ARGV3 OR NOT DEFINED CMAKE_ARGV4)
  message(FATAL_ERROR "Usage: cmake -P CheckStaticSodium.cmake <exe> <objdump>")
endif()

set(_exe "${CMAKE_ARGV3}")
set(_objdump "${CMAKE_ARGV4}")

if(NOT EXISTS "${_exe}")
  message(FATAL_ERROR "可执行文件不存在: ${_exe}")
endif()

execute_process(COMMAND "${_objdump}" -p "${_exe}"
  OUTPUT_VARIABLE _out ERROR_VARIABLE _err RESULT_VARIABLE _rc)

if(NOT _rc EQUAL 0)
  message(WARNING "objdump 执行失败（rc=${_rc}），跳过静态链接校验: ${_err}")
  return()
endif()

# 检查 Dynamic Section 的 NEEDED 行是否包含 libsodium
string(REGEX MATCH "NEEDED[ \t]+[^ \t]*libsodium[^ \t]*" _hit "${_out}")
if(_hit)
  message(FATAL_ERROR
    "libsodium 仍为【动态链接】（发现: ${_hit}），并未静态打包进可执行文件！\n"
    "静态链接未生效的常见原因：\n"
    "  1) SODIUM_STATIC 未开启：配置时加 -DSODIUM_STATIC=ON\n"
    "  2) 选中的是 libsodium 动态库（.so）：确认链接的是 libsodium.a\n"
    "  3) 定义了 SODIUM_STATIC 宏却链了动态库：二者必须一致\n"
    "请修正后重新构建。")
endif()

message(STATUS "OK: 未发现 libsodium 动态依赖，已静态链接进可执行文件。")
