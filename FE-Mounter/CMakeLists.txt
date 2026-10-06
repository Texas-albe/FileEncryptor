# FE-Mounter 独立构建（加密盘挂载 holder 进程）
#
# 为什么独立：FE-Mounter 不是 CLI 本体。CLI 只做文件加解密；加密盘挂载是可选能力，
# 在 GUI 的 MSI 里作为可勾选项（VaultFeature）随 GUI 分发。默认不随 CLI 构建。
#
# 用法（Windows，产物落到 CLI 的 bin 目录以便 GUI MSI 取用）：
#   cmake -S FE-Mounter -B CLI/out/build/fe-mounter
#   cmake --build CLI/out/build/fe-mounter --config Release
#   或 python .workbuddy\build_mounter.py
#
# 跨平台 / 单目录工作区：FE-Mounter 只依赖 CLI 里的一个头 vdisk.h。若本目录不在
# 仓库内（只同步了 FE-Mounter，或用 IDE 把它当独立工程打开），需要显式指路：
#   cmake -S FE-Mounter -B out -DFE_MOUNT_CLI_DIR=/path/to/FileEncryptor/CLI
#   cmake -S FE-Mounter -B out -DFE_MOUNT_CLI_INCLUDE=/path/to/vdisk.h
cmake_minimum_required(VERSION 3.15)
project(FileEncryptorMounter VERSION 3.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(MSVC)
  add_compile_options(/utf-8 /W3 /permissive- /Zc:strictStrings)
  add_compile_definitions(_CRT_SECURE_NO_WARNINGS NOMINMAX)
endif()

# ---- 定位 CLI 侧资源 ----
# vdisk.h：FE-Mounter 与 libvdisk 的唯一编译期依赖（118 行，只 include <stdint.h>，
# 完全自包含的 C ABI 契约）。定位顺序：
#   1) -DFE_MOUNT_CLI_INCLUDE=<vdisk.h 绝对路径>   显式指定，最优先
#   2) <FE_MOUNT_CLI_DIR>/include/vdisk.h        默认 ../CLI（与 CLI 同仓库）
#   3) 源码目录内自带一份 vdisk.h                  只同步了本目录时的兜底
set(FE_MOUNT_CLI_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../CLI"
    CACHE PATH "Path to the CLI directory (contains include/vdisk.h)")
set(FE_MOUNT_CLI_INCLUDE "" CACHE FILEPATH "Full path to vdisk.h (overrides FE_MOUNT_CLI_DIR)")

set(_fe_mount_inc "")
if(FE_MOUNT_CLI_INCLUDE)
  if(NOT EXISTS "${FE_MOUNT_CLI_INCLUDE}")
    message(FATAL_ERROR "FE_MOUNT_CLI_INCLUDE 指向的文件不存在：${FE_MOUNT_CLI_INCLUDE}")
  endif()
  get_filename_component(_fe_mount_inc "${FE_MOUNT_CLI_INCLUDE}" DIRECTORY)
elseif(EXISTS "${FE_MOUNT_CLI_DIR}/include/vdisk.h")
  set(_fe_mount_inc "${FE_MOUNT_CLI_DIR}/include")
elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/vdisk.h")
  # 自包含兜底：只同步了 FE-Mounter 目录时，同目录放一份 vdisk.h 即可编（无需整个 CLI）
  set(_fe_mount_inc "${CMAKE_CURRENT_SOURCE_DIR}")
  message(STATUS "vdisk.h 取自本目录（独立构建模式）")
else()
  message(FATAL_ERROR
    "找不到 vdisk.h（已找 ${FE_MOUNT_CLI_DIR}/include/vdisk.h 与 ${CMAKE_CURRENT_SOURCE_DIR}/vdisk.h）。\n"
    "FE-Mounter 需要仓库里的 CLI/include/vdisk.h（118 行，只依赖 <stdint.h>）。\n"
    "只同步了 FE-Mounter 目录时，任选一种：\n"
    "  - 把 CLI/include/vdisk.h 复制到 FE-Mounter/ 目录下（最省事）\n"
    "  - -DFE_MOUNT_CLI_INCLUDE=/abs/path/to/vdisk.h\n"
    "  - -DFE_MOUNT_CLI_DIR=/path/to/FileEncryptor/CLI")
endif()

# ---- 产物落点 ----
# 必须与 libvdisk（vdisk.dll / libvdisk.so）同目录：FE-Mounter 运行时按自身目录
# 绝对路径 dlopen/LoadLibrary 它。
# Windows：默认落到 CLI 的 out/build/windows-release/bin/<Config>/，供 GUI MSI 的 Stage 取用。
# 其他平台：落到本工程自己的 out/bin/<Config>/（CLI 的构建目录名是 Windows 专属的）。
if(WIN32)
  set(FE_MOUNT_BIN_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../CLI/out/build/windows-release/bin"
      CACHE PATH "Root of the output directory tree")
  set(FE_MOUNT_BIN_OUT "${FE_MOUNT_BIN_ROOT}/$<CONFIG>")
  if(CMAKE_BUILD_TYPE STREQUAL "")
    set(FE_MOUNT_BIN_OUT "${FE_MOUNT_BIN_ROOT}")   # 单配置生成器
  endif()
else()
  set(FE_MOUNT_BIN_OUT "${CMAKE_CURRENT_SOURCE_DIR}/out/bin/$<CONFIG>")
  if(CMAKE_BUILD_TYPE STREQUAL "")
    set(FE_MOUNT_BIN_OUT "${CMAKE_CURRENT_SOURCE_DIR}/out/bin")
  endif()
endif()

add_executable(FE-Mounter
  main.cpp
  fe_vdisk.cpp
  fe_ipc.cpp
  fe_service.cpp
  fe_winfsp.cpp)

target_include_directories(FE-Mounter PRIVATE "${_fe_mount_inc}")
message(STATUS "vdisk.h 目录: ${_fe_mount_inc}")
message(STATUS "产物目录: ${FE_MOUNT_BIN_OUT}")

# 所有配置都指向同一目录（VS 的 <CONFIG> 已是 Release/Debug；单配置已固定）
set_target_properties(FE-Mounter PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${FE_MOUNT_BIN_OUT}"
  RUNTIME_OUTPUT_DIRECTORY_DEBUG "${FE_MOUNT_BIN_OUT}"
  RUNTIME_OUTPUT_DIRECTORY_RELEASE "${FE_MOUNT_BIN_OUT}"
  RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${FE_MOUNT_BIN_OUT}"
  RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL "${FE_MOUNT_BIN_OUT}")

if(MSVC)
  target_compile_options(FE-Mounter PRIVATE /guard:cf)
  target_link_options(FE-Mounter PRIVATE /guard:cf)
endif()
if(UNIX)
  target_link_libraries(FE-Mounter PRIVATE ${CMAKE_DL_LIBS})   # dlopen
endif()

# ---- fuse3（Linux 挂载）----
# 未装 libfuse3-dev 时仍可构建：selftest/cat/bench/lifecycle/ipc 全可用，仅缺 mount 子命令
if(UNIX AND NOT APPLE)
  find_package(PkgConfig QUIET)
  if(PKG_CONFIG_FOUND)
    pkg_check_modules(FUSE3 QUIET fuse3>=3.0)
  endif()
  if(FUSE3_FOUND)
    target_compile_definitions(FE-Mounter PRIVATE FE_HAVE_FUSE=1)
    if(FUSE3_INCLUDEDIR)
      target_include_directories(FE-Mounter PRIVATE "${FUSE3_INCLUDEDIR}")
    endif()
    target_link_libraries(FE-Mounter PRIVATE ${FUSE3_LIBRARIES})
    target_link_directories(FE-Mounter PRIVATE ${FUSE3_LIBRARY_DIRS})
    message(STATUS "fuse3: ${FUSE3_VERSION} (${FUSE3_LIBRARIES})")
  else()
    message(STATUS "fuse3: 未找到（装 libfuse3-dev 启用 Linux mount 子命令）")
  endif()
endif()

# ---- WinFSP（Windows 盘符挂载）----
# 未装 SDK 时不定义 FE_HAVE_WINFSP：仍可构建，winmount 会明确报缺挂载能力而非编译失败
if(WIN32)
  set(_winfsp_root "$ENV{FEWIN_FSP_ROOT}")
  if(NOT _winfsp_root)
    foreach(_p "C:/Program Files (x86)/WinFsp" "C:/Program Files/WinFsp")
      if(EXISTS "${_p}/inc/winfsp/winfsp.h")
        set(_winfsp_root "${_p}")
        break()
      endif()
    endforeach()
  endif()
  if(_winfsp_root AND EXISTS "${_winfsp_root}/inc/winfsp/winfsp.h")
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
      set(_winfsp_lib "${_winfsp_root}/lib/winfsp-x64.lib")
    else()
      set(_winfsp_lib "${_winfsp_root}/lib/winfsp-x86.lib")
    endif()
    if(EXISTS "${_winfsp_lib}")
      # winfsp.h 内部 #include <winfsp/fsctl.h>，故 inc 与 inc/winfsp 都要在路径上
      target_include_directories(FE-Mounter PRIVATE "${_winfsp_root}/inc" "${_winfsp_root}/inc/winfsp")
      target_compile_definitions(FE-Mounter PRIVATE FE_HAVE_WINFSP=1)
      target_link_libraries(FE-Mounter PRIVATE "${_winfsp_lib}")
      # usermode 驱动 DLL 必须与 exe 同目录：静态导入 winfsp-x64.dll，
      # 缺失则进程加载即 0xC0000135（SDK 装在 Program Files 不在默认搜索路径）。
      # launcher-x64.exe 是 WinFSP 服务启动器（服务未运行时由 winfsp-x64.dll 拉起），
      # 同样随包分发，否则目标机没预装 WinFSP 时挂载直接失败。
      add_custom_command(TARGET FE-Mounter POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${_winfsp_root}/bin/winfsp-x64.dll" "$<TARGET_FILE_DIR:FE-Mounter>/")
      foreach(_extra launcher-x64.exe fsptool-x64.exe)
        if(EXISTS "${_winfsp_root}/bin/${_extra}")
          add_custom_command(TARGET FE-Mounter POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "${_winfsp_root}/bin/${_extra}" "$<TARGET_FILE_DIR:FE-Mounter>/")
        endif()
      endforeach()
      message(STATUS "WinFSP: ${_winfsp_root} (${_winfsp_lib})")
    else()
      message(WARNING "找到 WinFSP 头但缺 ${_winfsp_lib}；FE-Mounter 不含挂载能力。")
    endif()
  else()
    message(STATUS "WinFSP: 未找到 SDK（设 FEWIN_FSP_ROOT 指向安装目录以启用 Windows 挂载）")
  endif()
endif()
