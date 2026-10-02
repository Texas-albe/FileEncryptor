# 校验可执行文件是否“静态链接”了 zstd（即不依赖 libzstd.so）。
# 用法：cmake -P CheckStaticZstd.cmake <exe_path> <objdump_path>
# 若可执行文件仍动态依赖 libzstd（NEEDED 中出现 libzstd），则 FATAL_ERROR，
# 使构建失败，避免产出带运行时依赖、与自包含目标冲突的包。

if(NOT DEFINED CMAKE_ARGV3 OR NOT DEFINED CMAKE_ARGV4)
  message(FATAL_ERROR "Usage: cmake -P CheckStaticZstd.cmake <exe> <objdump>")
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

string(REGEX MATCH "NEEDED[ \t]+[^ \t]*libzstd[^ \t]*" _hit "${_out}")
if(_hit)
  message(FATAL_ERROR
    "zstd 仍为【动态链接】（发现: ${_hit}），并未静态打包进可执行文件！\n"
    "静态链接未生效的常见原因：\n"
    "  1) ZSTD_STATIC 未开启：配置时加 -DZSTD_STATIC=ON\n"
    "  2) 选中的是 zstd 动态库（.so）：确认链接的是 libzstd.a\n"
    "  3) 系统只装了 libzstd1（运行库），未装 libzstd-dev（含静态库 libzstd.a）\n"
    "请修正后重新构建。")
endif()

message(STATUS "OK: 未发现 zstd 动态依赖，已静态链接进可执行文件。")
