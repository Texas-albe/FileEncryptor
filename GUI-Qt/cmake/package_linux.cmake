# package_linux.cmake — 构建后自动打包（DEB / RPM）
# ============================================================
# 由 CMakeLists 经 add_custom_target(... ALL) 调用，在主目标链接完成之后执行，
# 因此「构建 → 复制可执行文件（POST_BUILD）→ 打包」的顺序由构建图保证。
#
# 为什么需要它：VS+WSL 与 cmake --build 只会做 configure + build，永远不会触发
# cpack；手工执行又容易漏。挂进构建图后，一次构建即可同时得到二进制与安装包。
#
# 入参（cmake -D... -P）：
#   FE_PKG_BUILD_DIR  构建目录（须已 configure 出 CPackConfig.cmake）
#   FE_PKG_OUT_DIR    包输出目录（Windows 可见，如 /mnt/e/FileEncryptor/CLI/out/packages）
#   FE_PKG_GENERATORS 可选，默认 DEB;RPM

if(NOT FE_PKG_BUILD_DIR)
  message(FATAL_ERROR "package_linux.cmake: 缺少参数 FE_PKG_BUILD_DIR")
endif()
if(NOT FE_PKG_OUT_DIR)
  message(FATAL_ERROR "package_linux.cmake: 缺少参数 FE_PKG_OUT_DIR")
endif()
if(NOT FE_PKG_GENERATORS)
  set(FE_PKG_GENERATORS "DEB;RPM")
endif()

if(NOT EXISTS "${FE_PKG_BUILD_DIR}/CPackConfig.cmake")
  message(FATAL_ERROR "package_linux.cmake: 未找到 ${FE_PKG_BUILD_DIR}/CPackConfig.cmake（请先执行 cmake 配置）")
endif()

file(MAKE_DIRECTORY "${FE_PKG_OUT_DIR}")

# 定位 cpack：优先 CMake 自带的绝对路径，其次与 cmake 同目录，最后回落到 PATH
set(_cpack "")
if(CMAKE_CPACK_COMMAND AND EXISTS "${CMAKE_CPACK_COMMAND}")
  set(_cpack "${CMAKE_CPACK_COMMAND}")
else()
  get_filename_component(_cmake_dir "${CMAKE_COMMAND}" DIRECTORY)
  find_program(_cpack NAMES cpack HINTS "${_cmake_dir}" "${_cmake_dir}/bin")
endif()
if(NOT _cpack)
  message(WARNING "[package] 未找到 cpack，跳过打包（请安装 cmake 完整包：sudo apt install cmake）")
  return()
endif()

foreach(_gen IN LISTS FE_PKG_GENERATORS)
  # RPM 依赖 rpmbuild，Debian/Ubuntu 默认不带；缺失时只警告不中断，保证 DEB 照常产出
  if(_gen STREQUAL "RPM")
    find_program(_rpmbuild NAMES rpmbuild rpm)
    if(NOT _rpmbuild)
      message(WARNING "[package] 跳过 RPM：未找到 rpmbuild（可执行 sudo apt install rpm 后再构建）")
      continue()
    endif()
  endif()

  message(STATUS "[package] 生成 ${_gen} 包 ...")
  execute_process(
    COMMAND "${_cpack}" -G "${_gen}" --config "${FE_PKG_BUILD_DIR}/CPackConfig.cmake"
    WORKING_DIRECTORY "${FE_PKG_BUILD_DIR}"
    RESULT_VARIABLE _res
    OUTPUT_VARIABLE _out
    ERROR_VARIABLE  _err)
  if(_res EQUAL 0)
    string(STRIP "${_out}" _out)
    if(_out)
      message(STATUS "[package] ${_out}")
    endif()
  else()
    message(WARNING "[package] cpack -G ${_gen} 失败（退出码 ${_res}）：\n${_out}\n${_err}")
  endif()
endforeach()

# 汇总：包由 CPACK_PACKAGE_DIRECTORY 直接产出到 FE_PKG_OUT_DIR；
# 若该变量被旧版 CPack 忽略（仍落在构建目录），此处兜底回收。
if(NOT "${FE_PKG_BUILD_DIR}" STREQUAL "${FE_PKG_OUT_DIR}")
  file(GLOB _stray "${FE_PKG_BUILD_DIR}/*.deb" "${FE_PKG_BUILD_DIR}/*.rpm")
  if(_stray)
    file(COPY ${_stray} DESTINATION "${FE_PKG_OUT_DIR}")
  endif()
endif()

file(GLOB _pkgs "${FE_PKG_OUT_DIR}/*.deb" "${FE_PKG_OUT_DIR}/*.rpm")
if(_pkgs)
  list(SORT _pkgs)
  foreach(_p IN LISTS _pkgs)
    message(STATUS "[package] 产物: ${_p}")
  endforeach()
else()
  message(WARNING "[package] 未生成任何安装包，请检查上方 cpack 输出")
endif()
