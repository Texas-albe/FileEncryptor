cmake_minimum_required(VERSION 3.15)

# 必须在 project() 之前钉住链接器：project() 内部会搜 CMAKE_LINKER，若 PATH 里
# 混着 MinGW/Strawberry 的 ld.exe，CMake 会拿 MSVC 的 /nologo 去问 GNU ld，直接 configure 失败。
if(WIN32)
  find_program(FE_CL_EXECUTABLE NAMES cl.exe
               HINTS "$ENV{VCToolsInstallDir}/bin/Hostx64/x64"
                     "$ENV{VCToolsInstallDir}/bin/Hostx86/x64")
  if(FE_CL_EXECUTABLE)
    get_filename_component(FE_CL_DIR "${FE_CL_EXECUTABLE}" DIRECTORY)
    set(CMAKE_LINKER "${FE_CL_DIR}/link.exe" CACHE FILEPATH "MSVC 链接器" FORCE)
  endif()
endif()

project(FileEncryptorCLI VERSION 3.0.0 LANGUAGES CXX)

# FileEncryptor CLI - 命令行加密工具（独立项目），产出 FileEncryptorCLI(.exe)，GUI 经 QProcess 调用。
# 静态链接 libsodium + yaml-cpp，二进制零外部依赖，可直接打包 DEB/RPM。

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 全程序优化（LTO）：Release 构建启用 /GL + /LTCG，提升跨 TU 热点（KDF 调用、AEAD 循环）性能。
# 仅作用于 Release 配置，不影响 Debug。
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)

# 源码含 UTF-8 中文注释（无 BOM），MSVC 默认按系统代码页解析会触发 C4819 并吞掉代码，
# 故强制以 UTF-8 读取源文件。
if(MSVC)
  add_compile_options(/utf-8)
endif()

# ---------- Android 适配 ----------
# 源码层已用 __ANDROID__ 分支处理平台差异（无交互终端、无 dmi/MAC、无 HOME）；
# 这里只做构建侧裁剪与前提校验。NDK 工具链用法：
#   cmake -G Ninja -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
#         -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-26 -DANDROID_STL=c++_static \
#         -DSODIUM_ROOT=<ndk 交叉编译出的 libsodium 前缀> ...
# std::filesystem 只有 libc++ 提供：gnustl / system 运行时没有该库，必须选 c++_static 或 c++_shared。
if(ANDROID)
  if(NOT ANDROID_STL MATCHES "c\\+\\+_")
    message(FATAL_ERROR "ANDROID_STL 必须是 c++_static 或 c++_shared：本工程使用 std::filesystem，"
                        "gnustl / system 运行时不提供。")
  endif()
  message(STATUS "Android: 挂载（FUSE / WinFSP）与常驻服务在 Android 不可用，已跳过；"
                 "机器标识与配置目录推断也已降级，见 config.cpp / machine_id.cpp。")
  add_compile_definitions(FE_PLATFORM_ANDROID=1)
endif()

# ---------- 工程化开关 ----------
# FE_ENABLE_ASAN：AddressSanitizer 构建（CI Linux 常态化跑往返）。
#   GCC/Clang：-fsanitize=address；MSVC：/fsanitize=address。
#   注意：MSVC 的 ASan 与静态 CRT (/MT) 不兼容，且本工程静态链接 libsodium(/MT)，
#   因此 Windows 侧启用时会 WARNING 提示改用 Debug+动态依赖；CI 的 ASan job 只在 Linux。
option(FE_ENABLE_ASAN "Build with AddressSanitizer" OFF)
if(FE_ENABLE_ASAN)
  if(MSVC)
    message(WARNING "FE_ENABLE_ASAN: MSVC 下需与动态 CRT(/MD) 配合，且 libsodium 静态库为 /MT，"
                    "Windows ASan 构建可能 LNK2038。CI 的 ASan 任务在 Linux 上运行。")
    add_compile_options(/fsanitize=address)
    add_link_options(/fsanitize=address)
  else()
    add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address)
  endif()
endif()

# 让 MSVC_RUNTIME_LIBRARY 目标属性生效（用于 Windows 静态链接时切换 /MT）
if(POLICY CMP0091)
  cmake_policy(SET CMP0091 NEW)
endif()

# 是否静态链接 libsodium：静态链接后生成的可执行文件不依赖任何外部 libsodium，
# 打出的 DEB/RPM 安装包也就无需在安装时再下载 libsodium 等依赖库。
option(SODIUM_STATIC "Statically link libsodium (recommended for self-contained packages)" ON)

# ---------- 查找 libsodium（跨平台） ----------
# 查找优先级：CMake 配置包(vcpkg) > 手动 find_path/find_library（SODIUM_ROOT，/usr/local 优先）
# > pkg-config 兜底（可能指向系统旧版）。
set(SODIUM_TARGET "")
set(SODIUM_FOUND FALSE)

# 1) CMake 配置包（vcpkg: `vcpkg install libsodium` 后启用 toolchain 即可）
find_package(sodium CONFIG QUIET)
if(sodium_FOUND)
  # 不同发行版 / 端口导出的目标名不统一，逐一探测
  foreach(_t sodium libsodium libsodium::libsodium Sodium::sodium)
    if(TARGET ${_t})
      set(SODIUM_TARGET ${_t})
      set(SODIUM_FOUND TRUE)
      break()
    endif()
  endforeach()
endif()

# 2) 手动查找（优先于 pkg-config，避免多版本选错）：Linux 默认 /usr/local 先于 /usr；
#    Windows 预编译包库在 <arch>/<cfg>/<toolset>/<static|dynamic|ltcg> 子目录，按架构自动选取。
if(NOT SODIUM_FOUND AND NOT SODIUM_TARGET)
  # ---- Windows 专用：构造预编译包的候选库目录 ----
  set(_sodium_win_hints "")
  if(WIN32)
    # 预编译包根目录：SODIUM_ROOT > 仓库 third_party/libsodium > $ProgramFiles/libsodium。
    set(_sodium_pkg_root "${SODIUM_ROOT}")
    if(NOT _sodium_pkg_root)
      set(_sodium_pkg_root "${CMAKE_CURRENT_SOURCE_DIR}/../third_party/libsodium")
    endif()
    if(NOT EXISTS "${_sodium_pkg_root}")
      set(_sodium_pkg_root "$ENV{ProgramFiles}/libsodium")
    endif()
    # 架构目录：优先用 VS 生成器给出的平台名，否则按指针宽度推断
    if(DEFINED CMAKE_VS_PLATFORM_NAME AND CMAKE_VS_PLATFORM_NAME)
      set(_sodium_arch "${CMAKE_VS_PLATFORM_NAME}")
    elseif(CMAKE_SIZEOF_VOID_P EQUAL 8)
      set(_sodium_arch "x64")
    else()
      set(_sodium_arch "Win32")
    endif()
    # 选取可用的工具集子目录（v143=VS2022 …），取最新存在的
    set(_sodium_ts "")
    foreach(_ts v143 v142 v141 v140)
      if(EXISTS "${_sodium_pkg_root}/${_sodium_arch}/Release/${_ts}")
        set(_sodium_ts "${_ts}")
        break()
      endif()
    endforeach()
    # 候选库目录链接顺序取决于 SODIUM_STATIC：ON 时 static 优先（配 /MT，Release 排在 Debug 前
    # 避免 CRT 不匹配 LNK2038）；OFF 时 dynamic 优先（需随附 DLL）。覆盖 Release 与 Debug。
    foreach(_cfg Release Debug)
      if(SODIUM_STATIC)
        set(_links static dynamic ltcg)
      else()
        set(_links dynamic static ltcg)
      endif()
      foreach(_link ${_links})
        if(_sodium_ts)
          list(APPEND _sodium_win_hints
            "${_sodium_pkg_root}/${_sodium_arch}/${_cfg}/${_sodium_ts}/${_link}")
        endif()
      endforeach()
    endforeach()
  endif()

  # 清除可能存在的旧缓存，强制重新探测（避免构建目录中残留的过期结果选中 apt 旧版）
  unset(SODIUM_INCLUDE_DIRS CACHE)
  unset(SODIUM_LIBRARIES CACHE)
  # 默认优先 /usr/local（源码安装的新版本），其次 /usr，最后系统默认路径
  find_path(SODIUM_INCLUDE_DIRS
    NAMES sodium.h
    PATH_SUFFIXES include include/sodium
    HINTS ${SODIUM_ROOT} ${LIBSODIUM_ROOT} $ENV{SODIUM_ROOT} $ENV{LIBSODIUM_ROOT} ${_sodium_pkg_root} "$ENV{ProgramFiles}/libsodium" /usr/local /usr ${_sodium_win_hints})
  find_library(SODIUM_LIBRARIES
    NAMES sodium libsodium
    HINTS ${SODIUM_ROOT} ${LIBSODIUM_ROOT} $ENV{SODIUM_ROOT} $ENV{LIBSODIUM_ROOT} ${_sodium_pkg_root} "$ENV{ProgramFiles}/libsodium" /usr/local /usr ${_sodium_win_hints}
    PATH_SUFFIXES lib lib64 bin)
  if(SODIUM_INCLUDE_DIRS AND SODIUM_LIBRARIES)
    set(SODIUM_FOUND TRUE)
  endif()
endif()

# 3) pkg-config（最后回退；可能指向系统中较旧的 libsodium）
if(NOT SODIUM_FOUND AND NOT SODIUM_TARGET)
  find_package(PkgConfig QUIET)
  if(PkgConfig_FOUND)
    pkg_check_modules(SODIUM QUIET libsodium)
  endif()
endif()

# ---------- 校验 libsodium 是否支持 AEGIS-256 ----------
# AEGIS-256 自 1.0.19 起提供。编译期版本校验，链接 1.0.18 及更早直接 FATAL_ERROR。
# 版本来源：sodium_VERSION > version.h 解析 SODIUM_VERSION_STRING > 头文件存在性探测。
set(SODIUM_DETECTED_VERSION "")
if(SODIUM_TARGET AND DEFINED sodium_VERSION AND sodium_VERSION)
  set(SODIUM_DETECTED_VERSION "${sodium_VERSION}")
elseif(SODIUM_FOUND AND SODIUM_INCLUDE_DIRS AND
       EXISTS "${SODIUM_INCLUDE_DIRS}/sodium/version.h")
  file(STRINGS "${SODIUM_INCLUDE_DIRS}/sodium/version.h" _sver_line
       REGEX "^[ \t]*#define[ \t]+SODIUM_VERSION_STRING[ \t]+\"")
  if(_sver_line)
    string(REGEX REPLACE "^[ \t]*#define[ \t]+SODIUM_VERSION_STRING[ \t]+\"([0-9.]+).*$"
           "\\1" SODIUM_DETECTED_VERSION "${_sver_line}")
  endif()
endif()

if(SODIUM_FOUND AND NOT SODIUM_TARGET)
  set(_sodium_ok FALSE)
  if(SODIUM_DETECTED_VERSION AND SODIUM_DETECTED_VERSION VERSION_GREATER_EQUAL "1.0.19")
    set(_sodium_ok TRUE)
    message(STATUS "libsodium 版本 ${SODIUM_DETECTED_VERSION} >= 1.0.19（支持 AEGIS-256）")
  elseif(SODIUM_DETECTED_VERSION)
    message(FATAL_ERROR
      "找到的 libsodium 版本为 ${SODIUM_DETECTED_VERSION}，低于所需的最低版本 1.0.19。\n"
      "AEGIS-256 自 1.0.19 起提供，请升级 libsodium 后重试。")
  elseif(NOT EXISTS "${SODIUM_INCLUDE_DIRS}/sodium/crypto_aead_aegis256.h")
    # 无版本信息可解析时的回退探测
    message(FATAL_ERROR
      "找到的 libsodium 版本缺少 AEGIS-256 支持（需 >= 1.0.19）。\n"
      "这通常是因为系统中同时存在多个 libsodium，CMake 选中了较旧的版本\n"
      "（例如 apt 安装的 libsodium-dev 1.0.18）。请任选其一解决：\n"
      "  1) 显式指定较新的 libsodium 根目录：\n"
      "       cmake -S . -B build -DSODIUM_ROOT=/usr/local ...\n"
      "  2) 卸载旧版本：sudo apt remove libsodium-dev\n"
      "  3) 从源码安装 >= 1.0.19 到 /usr/local（默认会被优先选中）。")
  else()
    set(_sodium_ok TRUE)
    message(STATUS "libsodium 支持 AEGIS-256 (>= 1.0.19，无法解析精确版本号，已回退到头文件探测)")
  endif()
endif()

# ---------- 决定最终链接方式与运行时依赖 ----------
# SODIUM_STATIC(默认 ON) 优先静态库生成自包含可执行文件：Windows hints 已把 static 排前
# （Release 静态库在 Debug 前，任意配置都链接 /MT 版，避免 LNK2038）；Linux 找 .a。
set(SODIUM_LINK_LIBRARY "")
set(SODIUM_IS_STATIC FALSE)
set(SODIUM_DLL "")

if(SODIUM_STATIC AND SODIUM_FOUND AND NOT SODIUM_TARGET)
  if(WIN32)
    # Windows 静态库路径已由上方 hints 解析到 SODIUM_LIBRARIES（static 子目录下）
    if(SODIUM_LIBRARIES)
      set(SODIUM_LINK_LIBRARY ${SODIUM_LIBRARIES})
      set(SODIUM_IS_STATIC TRUE)
      message(STATUS "libsodium: 静态链接 (${SODIUM_LIBRARIES})")
    endif()
  else()
    set(_sfx ${CMAKE_FIND_LIBRARY_SUFFIXES})
    set(CMAKE_FIND_LIBRARY_SUFFIXES .a .lib ${_sfx})
    # 强制重新探测静态库，并显式优先 /usr/local（源码安装的新版本），
    # 避免回退到 apt 的 libsodium-dev 1.0.18（无 AEGIS-256，链接期 undefined reference）
    unset(SODIUM_STATIC_LIBRARY CACHE)
    find_library(SODIUM_STATIC_LIBRARY
      NAMES sodium libsodium
      HINTS ${SODIUM_ROOT} ${LIBSODIUM_ROOT} $ENV{SODIUM_ROOT} $ENV{LIBSODIUM_ROOT} /usr/local /usr
      PATH_SUFFIXES lib lib64)
    set(CMAKE_FIND_LIBRARY_SUFFIXES ${_sfx})
    if(SODIUM_STATIC_LIBRARY AND SODIUM_INCLUDE_DIRS)
      set(SODIUM_LINK_LIBRARY ${SODIUM_STATIC_LIBRARY})
      set(SODIUM_IS_STATIC TRUE)
      message(STATUS "libsodium: 静态链接 (${SODIUM_STATIC_LIBRARY})")
    endif()
  endif()
endif()

# 未找到静态库时回退：Windows 用动态导入库+DLL（复制到 exe 旁）；其它平台用 find_library 结果。
if(NOT SODIUM_IS_STATIC)
  if(WIN32 AND SODIUM_FOUND AND NOT SODIUM_TARGET)
    get_filename_component(_sodium_lib_dir "${SODIUM_LIBRARIES}" DIRECTORY)
    if(EXISTS "${_sodium_lib_dir}/libsodium.dll")
      set(SODIUM_DLL "${_sodium_lib_dir}/libsodium.dll")
    else()
      find_file(SODIUM_DLL
        NAMES libsodium.dll
        HINTS "${_sodium_lib_dir}" "$ENV{ProgramFiles}/libsodium"
        PATH_SUFFIXES bin)
    endif()
    if(SODIUM_DLL)
      message(STATUS "libsodium: 动态链接 (${SODIUM_LIBRARIES})，运行时依赖 ${SODIUM_DLL}")
    else()
      message(STATUS "libsodium: 动态链接 (${SODIUM_LIBRARIES})")
    endif()
  endif()
endif()

if(SODIUM_STATIC AND NOT SODIUM_IS_STATIC)
  message(WARNING
    "未找到 libsodium 静态库，将回退为动态链接；最终可执行文件会依赖 libsodium DLL/SO。\n"
    "  如需完全自包含，请安装静态库：\n"
    "    Windows: 使用含 static 子目录的预编译包（本脚本默认优先选用）；\n"
    "    Linux  : sudo apt install libsodium-dev   (含 libsodium.a)；\n"
    "    Fedora : sudo dnf install libsodium-static")
endif()

# ---------- 校验选中的库确实包含 AEGIS-256 符号（Linux/macOS） ----------
# 防止"头文件来自 /usr/local、链接库却来自 apt 旧版"的头库不一致（链接期 undefined reference）。
# 用 nm 直接检查选中库；SODIUM_TARGET(vcpkg IMPORTED 目标) 无法 nm 检查，跳过。
if(UNIX AND NOT SODIUM_TARGET)
  set(_chosen_sodium_lib "${SODIUM_LINK_LIBRARY}")
  if(NOT _chosen_sodium_lib)
    set(_chosen_sodium_lib "${SODIUM_LIBRARIES}")
  endif()
  if(_chosen_sodium_lib AND EXISTS "${_chosen_sodium_lib}")
    find_program(NM_EXECUTABLE NAMES nm)
    if(NM_EXECUTABLE)
      execute_process(COMMAND ${NM_EXECUTABLE} "${_chosen_sodium_lib}"
        OUTPUT_VARIABLE _sodium_nm_out ERROR_QUIET)
      if(NOT _sodium_nm_out MATCHES "crypto_aead_aegis256_encrypt")
        message(FATAL_ERROR
          "选中的 libsodium 库 (${_chosen_sodium_lib}) 不包含 AEGIS-256 符号，\n"
          "很可能链接到了旧版本（如 apt 的 libsodium-dev 1.0.18）。\n"
          "请任选其一解决：\n"
          "  1) 显式指定较新的 libsodium 根目录：\n"
          "       cmake -S . -B build -DSODIUM_ROOT=/usr/local ...\n"
          "  2) 卸载旧版本：sudo apt remove libsodium-dev\n"
          "  3) 从源码安装 >= 1.0.19 到 /usr/local（默认会被优先选中）。")
      else()
        message(STATUS "libsodium 库确认包含 AEGIS-256 符号")
      endif()
    endif()
  endif()
endif()

if(NOT SODIUM_FOUND AND NOT SODIUM_TARGET)
  message(FATAL_ERROR
    "找不到 libsodium。安装方式：\n"
    "  Linux  (Debian/Ubuntu): sudo apt install libsodium-dev pkg-config\n"
    "  Linux  (Fedora):        sudo dnf install libsodium-devel\n"
    "  macOS  (Homebrew):      brew install libsodium\n"
    "  Windows (vcpkg):        vcpkg install libsodium  (并在配置时启用 vcpkg toolchain)\n"
    "  或解压预编译包后设置环境变量 SODIUM_ROOT 指向其根目录。")
endif()

# ---------- 源文件 ----------
# CLI 独立项目：core/（加密核心）+ cli/（命令行入口），GUI 通过 QProcess 调用本程序。
set(SOURCES
  core/FileEncryptor.cpp
  core/cipher.cpp
  core/ptd_format.cpp
  core/kdf.cpp
  core/source_handling.cpp
  core/config.cpp
  core/keylib.cpp
  core/progress_frame.cpp
  core/asym_crypto.cpp
  core/mapped_file.cpp
  core/password_policy.cpp
  core/machine_id.cpp
  core/watermark.cpp
  core/split_volumes.cpp
  core/archive.cpp
  core/keywrap.cpp
  core/vault_index.cpp
  cli/main.cpp)

# Windows 图标资源（嵌入 exe；Linux/macOS 无 .rc）
if(WIN32)
  enable_language(RC)
  list(APPEND SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/cli/FileEncryptorCLI.rc")
endif()

add_executable(FileEncryptor ${SOURCES})

if(MSVC)
    # CFG：阻断间接调用劫持与 ROP 链。编译与链接两侧都必须给，
    # 缺链接侧则只有编译期位、最终映像 load config 里不会落 CFG 位（B1）
    target_compile_options(FileEncryptor PRIVATE /guard:cf)
    target_link_options(FileEncryptor PRIVATE /guard:cf)
endif()

# ---------- 查找 yaml-cpp（YAML 配置解析，v1.7.2 起依赖） ----------
# 优先 CMake 配置包命中；无配置时按头文件与静态库手动查找（YAMLCPP_ROOT 可显式指定）。
find_package(Threads REQUIRED)
set(YAMLCPP_TARGET "")
set(YAMLCPP_IS_STATIC ON)
# 库来源：优先仓库内 third_party/yaml-cpp（含 /MT 预编译静态库，工具集匹配），
# 其次 find_package/手动查找，避免命中系统工具集或 CRT 不匹配的安装（曾引发 LNK2019/2038）。
set(_yamlcpp_repo_root "${CMAKE_CURRENT_SOURCE_DIR}/../third_party/yaml-cpp")
if(EXISTS "${_yamlcpp_repo_root}/include/yaml-cpp/yaml.h")
  find_path(YAMLCPP_INCLUDE_DIR NAMES yaml-cpp/yaml.h
    HINTS "${_yamlcpp_repo_root}" NO_DEFAULT_PATH
    PATH_SUFFIXES include)
  find_library(YAMLCPP_LIBRARY NAMES yaml-cpp libyaml-cpp
    HINTS "${_yamlcpp_repo_root}" NO_DEFAULT_PATH
    PATH_SUFFIXES lib)
  if(YAMLCPP_INCLUDE_DIR AND YAMLCPP_LIBRARY)
    add_library(yaml-cpp-static STATIC IMPORTED)
    set_target_properties(yaml-cpp-static PROPERTIES
      IMPORTED_LOCATION ${YAMLCPP_LIBRARY}
      INTERFACE_INCLUDE_DIRECTORIES ${YAMLCPP_INCLUDE_DIR})
    set(YAMLCPP_TARGET yaml-cpp-static)
    message(STATUS "yaml-cpp: 仓库内 third_party (${YAMLCPP_LIBRARY})")
  endif()
endif()
if(NOT YAMLCPP_TARGET)
find_package(yaml-cpp QUIET)
if(yaml-cpp_FOUND)
  set(YAMLCPP_TARGET yaml-cpp::yaml-cpp)
  if(YAML_CPP_SHARED_LIBS_BUILT)
    set(YAMLCPP_IS_STATIC OFF)
  endif()
  message(STATUS "yaml-cpp: find_package 成功")
else()
  find_path(YAMLCPP_INCLUDE_DIR NAMES yaml-cpp/yaml.h
    HINTS "$ENV{ProgramFiles}/yaml-cpp" ${YAMLCPP_ROOT} $ENV{YAMLCPP_ROOT}
    PATH_SUFFIXES include)
  find_library(YAMLCPP_LIBRARY NAMES yaml-cpp libyaml-cpp
    HINTS "$ENV{ProgramFiles}/yaml-cpp" ${YAMLCPP_ROOT} $ENV{YAMLCPP_ROOT}
    PATH_SUFFIXES lib lib64 build/Release build/Debug)
  if(YAMLCPP_INCLUDE_DIR AND YAMLCPP_LIBRARY)
    add_library(yaml-cpp-static STATIC IMPORTED)
    set_target_properties(yaml-cpp-static PROPERTIES
      IMPORTED_LOCATION ${YAMLCPP_LIBRARY}
      INTERFACE_INCLUDE_DIRECTORIES ${YAMLCPP_INCLUDE_DIR})
    set(YAMLCPP_TARGET yaml-cpp-static)
    message(STATUS "yaml-cpp: 手动查找 (${YAMLCPP_LIBRARY})")
  endif()
endif()
endif() # NOT YAMLCPP_TARGET（third_party 优先分支收尾）
if(NOT YAMLCPP_TARGET)
  message(FATAL_ERROR
    "找不到 yaml-cpp。安装方式：\n"
    "  仓库内:  确认 third_party/yaml-cpp/ 存在（include/ + lib/yaml-cpp.lib）\n"
    "  Linux  (Debian/Ubuntu): sudo apt install libyaml-cpp-dev\n"
    "  Linux  (Fedora):        sudo dnf install yaml-cpp-devel\n"
    "  Windows:                yaml-cpp 已随仓库放于 ../third_party/yaml-cpp/，\n"
    "                          或设置 YAMLCPP_ROOT 指向其根目录（相对路径亦可）。")
endif()

# ---------- 链接 libsodium ----------
if(SODIUM_TARGET)
  target_link_libraries(FileEncryptor PRIVATE ${SODIUM_TARGET})
else()
  # core/ 加入 include 路径：cli/main.cpp 与 core/*.cpp 都 #include "FileEncryptor.hpp" 等头
  target_include_directories(FileEncryptor PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/core ${CMAKE_CURRENT_SOURCE_DIR}/include ${SODIUM_INCLUDE_DIRS})
  if(SODIUM_LINK_LIBRARY)
    target_link_libraries(FileEncryptor PRIVATE ${SODIUM_LINK_LIBRARY})
  else()
    target_link_libraries(FileEncryptor PRIVATE ${SODIUM_LIBRARIES})
  endif()
  target_compile_options(FileEncryptor PRIVATE ${SODIUM_CFLAGS_OTHER})
  if(SODIUM_IS_STATIC)
    find_package(Threads REQUIRED)
    target_link_libraries(FileEncryptor PRIVATE Threads::Threads)
    if(WIN32)
      # Windows 下静态链接 libsodium 需要这些系统库；
      # shell32.lib 提供 CommandLineToArgvW（main.cpp 用于 UTF-8 参数解析）
      target_link_libraries(FileEncryptor PRIVATE ws2_32 advapi32 bcrypt crypt32 shell32)
      # iphlpapi 提供第一个网卡 MAC（machine_id）；WMI 库提供主板序列号查询（CLSID_WbemLocator）
      target_link_libraries(FileEncryptor PRIVATE iphlpapi)
      find_library(FE_WBEM_LIBRARY NAMES wbemuuid wbemidl)
      if(FE_WBEM_LIBRARY)
        target_link_libraries(FileEncryptor PRIVATE ${FE_WBEM_LIBRARY})
      endif()
    endif()
    # 链接静态 libsodium 必须定义 SODIUM_STATIC，否则 sodium.h 把函数声明为
    # __declspec(dllimport)（产生 __imp_ 前缀），静态库报 LNK2019；定义后函数为普通 extern。
    target_compile_definitions(FileEncryptor PRIVATE SODIUM_STATIC)
    # Windows 静态链接 libsodium 时，必须把本项目运行时库切换为静态 CRT (/MT)，
    # 否则与 libsodium 静态库的 LIBCMT 冲突，报 LNK2038（CRT 不匹配）。
    if(MSVC)
      set_target_properties(FileEncryptor PROPERTIES
        MSVC_RUNTIME_LIBRARY "MultiThreaded")
    endif()
  endif()
endif()

# ---------- 链接 yaml-cpp + Threads ----------
# 静态链接 yaml-cpp 必须定义 YAML_CPP_STATIC_DEFINE（否则符号声明为 dllimport，LNK2019），
# 与 SODIUM_STATIC 同理；动态构建时不能定义。
if(YAMLCPP_IS_STATIC)
  target_compile_definitions(FileEncryptor PRIVATE YAML_CPP_STATIC_DEFINE)
endif()
target_link_libraries(FileEncryptor PRIVATE ${YAMLCPP_TARGET} Threads::Threads)

# ---------- 平台相关的链接善后 ----------
# std::filesystem：GCC 9 之前（Ubuntu 18.04 等）需显式链接 libstdc++fs，否则 undefined reference。
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.0)
  target_link_libraries(FileEncryptor PRIVATE stdc++fs)
endif()

# Linux 静态链接 libsodium / yaml-cpp 时，动态加载器符号（dlopen 等）需显式链接
if(UNIX)
  target_link_libraries(FileEncryptor PRIVATE ${CMAKE_DL_LIBS})
endif()

# ---------- OpenSSL（SM4 分块密码 + X25519/X448 非对称，静态链接保持自包含） ----------
# 优先复用仓库共享的静态 OpenSSL（Updater 已构建到 <repo>/Updater/out/openssl，
# libcrypto.lib + include/openssl）；其次 find_package(OpenSSL) 静态；均不可得则 WARNING
# 并回退为不含 SM4/非对称能力（相关调用返回明确错误，不中断构建）。
option(WITH_OPENSSL "Enable OpenSSL-backed ciphers (SM4) and asymmetric (X25519/X448)" ON)
set(FE_OPENSSL_FOUND FALSE)
if(WITH_OPENSSL)
  set(_ossl_repo_root "${CMAKE_CURRENT_SOURCE_DIR}/../Updater/out/openssl")
  find_path(OPENSSL_INCLUDE_DIR NAMES openssl/ssl.h
    HINTS "${_ossl_repo_root}/include" NO_DEFAULT_PATH)
  find_library(OPENSSL_CRYPTO_LIBRARY NAMES libcrypto crypto
    HINTS "${_ossl_repo_root}/lib" NO_DEFAULT_PATH)
  if(OPENSSL_INCLUDE_DIR AND OPENSSL_CRYPTO_LIBRARY)
    set(FE_OPENSSL_FOUND TRUE)
    target_include_directories(FileEncryptor PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(FileEncryptor PRIVATE ${OPENSSL_CRYPTO_LIBRARY})
    if(WIN32)
      target_link_libraries(FileEncryptor PRIVATE crypt32 ws2_32)
    else()
      target_link_libraries(FileEncryptor PRIVATE ${CMAKE_DL_LIBS})
    endif()
    message(STATUS "OpenSSL: 静态复用仓库构建 (${OPENSSL_CRYPTO_LIBRARY})")
  else()
    # 回退：系统 OpenSSL（Linux 优先静态，Windows 通常动态）
    if(NOT WIN32)
      set(OPENSSL_USE_STATIC_LIBS ON)
    endif()
    find_package(OpenSSL QUIET)
    if(OpenSSL_FOUND AND OPENSSL_CRYPTO_LIBRARY)
      set(FE_OPENSSL_FOUND TRUE)
      target_link_libraries(FileEncryptor PRIVATE OpenSSL::Crypto)
      message(STATUS "OpenSSL: find_package (${OPENSSL_VERSION})")
    else()
      message(WARNING
        "WITH_OPENSSL=ON but OpenSSL not found.\n"
        "  Windows: 需先构建 Updater/out/openssl（libsodium/OpenSSL 静态构建已就绪）。\n"
        "  Linux  : 安装 libssl-dev 或设置 OPENSSL_ROOT_DIR。\n"
        "SM4 / X25519 / X448 将不可用。")
    endif()
  endif()
  if(FE_OPENSSL_FOUND)
    target_compile_definitions(FileEncryptor PRIVATE FE_WITH_OPENSSL)
  endif()

  # 静态 libcrypto.a 的传递依赖（动态版由 .so 自带）：zlib 用于 PEM / ASN.1，
  # jitterentropy 是 jitter 熵源的实现；两者缺失都会在与 libcrypto.a 链接时 undefined reference
  if(NOT WIN32 AND FE_OPENSSL_FOUND AND OPENSSL_CRYPTO_LIBRARY MATCHES "\\.a$")
    set(_saved_suffixes ${CMAKE_FIND_LIBRARY_SUFFIXES})
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
    foreach(_dep z jitterentropy)
      unset(FE_OPENSSL_DEP_${_dep} CACHE)   # 清掉上一轮缓存的 .so，强制按静态后缀重探
      find_library(FE_OPENSSL_DEP_${_dep} NAMES ${_dep})
      if(FE_OPENSSL_DEP_${_dep})
        target_link_libraries(FileEncryptor PRIVATE ${FE_OPENSSL_DEP_${_dep}})
      endif()
    endforeach()
    set(CMAKE_FIND_LIBRARY_SUFFIXES ${_saved_suffixes})
  endif()
endif()

# ---------- zstd 压缩支持 ----------
# 查找顺序按平台分开：Linux/macOS 先找系统静态库（省去编译整棵源码树、也是包管理器的
# 常规安装方式），再回退源码编译；Windows 先源码编译（与 MSVC 工具链 / /MT 一致），
# 再回退 third_party 预编译库。
# 静态链接是默认行为：只找到动态库会让 DEB/RPM 带上 libzstd.so 运行时依赖，
# 与「零声明依赖、完全自包含」的目标冲突。ZSTD_STATIC=OFF 允许动态链接。
option(WITH_ZSTD "Enable zstd compression support" ON)
option(ZSTD_STATIC "Statically link zstd (recommended for self-contained packages)" ON)
set(FE_ZSTD_FOUND FALSE)
set(FE_ZSTD_STATIC FALSE)
if(WITH_ZSTD)
  set(_zstd_root "${CMAKE_CURRENT_SOURCE_DIR}/../third_party/zstd")
  set(_zstd_src "${_zstd_root}/src/lib")
  # 每次配置重新探测：find_library 结果进缓存，沿用旧值会在换平台/换库后指向不匹配的库
  unset(ZSTD_LIBRARY CACHE)
  unset(ZSTD_INCLUDE_DIR CACHE)

  # 命中预编译静态库后的统一处理（只挂依赖、不做查找）
  function(fe_zstd_attach_prebuilt _lib _inc)
    set(FE_ZSTD_FOUND TRUE PARENT_SCOPE)
    set(FE_ZSTD_STATIC TRUE PARENT_SCOPE)
    target_include_directories(FileEncryptor PRIVATE ${_inc})
    target_link_libraries(FileEncryptor PRIVATE ${_lib})
    target_compile_definitions(FileEncryptor PRIVATE FE_WITH_ZSTD)
    if(WIN32)
      target_link_libraries(FileEncryptor PRIVATE ws2_32)
    else()
      target_link_libraries(FileEncryptor PRIVATE pthread)
    endif()
    message(STATUS "zstd: 静态链接预编译库 (${_lib})")
  endfunction()

  # ---- 1) Linux/macOS：系统 / 仓库预编译静态库（libzstd.a）----
  # 后缀锁死为 .a，否则 find_library 会先命中 libzstd.so 把动态依赖带进来。
  if(NOT WIN32 AND ZSTD_STATIC)
    set(_zstd_saved_suffixes ${CMAKE_FIND_LIBRARY_SUFFIXES})
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
    find_library(ZSTD_LIBRARY NAMES zstd libzstd_static
      HINTS $ENV{ZSTD_ROOT} "${_zstd_root}/static/linux"
            "/usr/lib/${CMAKE_LIBRARY_ARCHITECTURE}" /usr/local /usr
      PATH_SUFFIXES lib lib64)
    set(CMAKE_FIND_LIBRARY_SUFFIXES ${_zstd_saved_suffixes})
  endif()
  if(ZSTD_LIBRARY)
    find_path(ZSTD_INCLUDE_DIR NAMES zstd.h
      HINTS $ENV{ZSTD_ROOT} "${_zstd_root}/include" /usr/local/include /usr/include
      PATH_SUFFIXES include)
    if(ZSTD_INCLUDE_DIR)
      fe_zstd_attach_prebuilt(${ZSTD_LIBRARY} ${ZSTD_INCLUDE_DIR})
    endif()
  endif()

  # ---- 2) 回退：从源码编译静态库（与本工程同工具链 / 同 /MT 运行时）----
  # Windows 上这是首选路径；源文件缺失时才落到下一步的预编译库
  if(NOT FE_ZSTD_FOUND AND EXISTS "${_zstd_src}/zstd.h")
    set(FE_ZSTD_FOUND TRUE)
    enable_language(C)   # zstd 为 C 源码，工程默认仅启用 CXX
    file(GLOB _zstd_common     "${_zstd_src}/common/*.c")
    file(GLOB _zstd_compress   "${_zstd_src}/compress/*.c")
    file(GLOB _zstd_decompress "${_zstd_src}/decompress/*.c")
    file(GLOB _zstd_dict       "${_zstd_src}/dictBuilder/*.c")
    add_library(zstd_static STATIC
      ${_zstd_common} ${_zstd_compress} ${_zstd_decompress} ${_zstd_dict})
    target_include_directories(zstd_static PRIVATE
      "${_zstd_src}" "${_zstd_src}/common" "${_zstd_src}/compress"
      "${_zstd_src}/decompress" "${_zstd_src}/dictBuilder"
      "${_zstd_root}/include")
    target_compile_definitions(zstd_static PRIVATE ZSTD_DISABLE_ASM)
    if(MSVC)
      # 与 FileEncryptor 的 /MT 静态 CRT 保持一致，否则链接期 LNK2038
      set_target_properties(zstd_static PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded")
      target_compile_options(zstd_static PRIVATE /w)   # 抑制第三方源码告警
    endif()
    target_include_directories(FileEncryptor PRIVATE "${_zstd_root}/include")
    target_link_libraries(FileEncryptor PRIVATE zstd_static)
    target_compile_definitions(FileEncryptor PRIVATE FE_WITH_ZSTD)
    if(NOT WIN32)
      target_link_libraries(FileEncryptor PRIVATE pthread)
    endif()
    message(STATUS "zstd: 已从源码编译集成 (${_zstd_src})")
  endif()

  # ---- 3) Windows 兜底：third_party 预编译静态库（.lib）----
  # 该库由 MinGW 构建，仅当源码树缺失、且链接器不报错时才可用；MSVC 下若报
  # ___chkstk_ms unresolved 说明工具链不匹配，请保留 third_party/zstd/src/lib。
  if(NOT FE_ZSTD_FOUND AND WIN32 AND ZSTD_STATIC)
    find_path(ZSTD_INCLUDE_DIR NAMES zstd.h
      HINTS "$ENV{ZSTD_ROOT}" "${_zstd_root}/include" NO_DEFAULT_PATH)
    find_library(ZSTD_LIBRARY NAMES libzstd_static
      HINTS "$ENV{ZSTD_ROOT}" "${_zstd_root}/static" NO_DEFAULT_PATH)
    if(ZSTD_INCLUDE_DIR AND ZSTD_LIBRARY)
      fe_zstd_attach_prebuilt(${ZSTD_LIBRARY} ${ZSTD_INCLUDE_DIR})
    endif()
  endif()

  # ---- 4) 都不可用 ----
  if(NOT FE_ZSTD_FOUND)
    if(ZSTD_STATIC)
      # 默认不允许动态链接：只会产出带 libzstd.so 依赖的包，静默通过会掩盖问题
      message(FATAL_ERROR
        "WITH_ZSTD=ON 且 ZSTD_STATIC=ON，但未找到 zstd 静态库（libzstd.a / libzstd_static.lib）。\n"
        "  安装静态库后重试：\n"
        "    Debian/Ubuntu: sudo apt install libzstd-dev\n"
        "    Fedora        : sudo dnf install libzstd-static\n"
        "    macOS         : brew install zstd\n"
        "  或直接沿用仓库内的源码树 third_party/zstd/src/lib 走源码编译。\n"
        "  确需动态链接请用 -DZSTD_STATIC=OFF。")
    else()
      message(WARNING
        "WITH_ZSTD=ON 但未找到 zstd（静态库关闭查找、源码树也不在），将构建为“无压缩”版本。\n"
        "  安装 libzstd-dev（Ubuntu）或从源码放置 third_party/zstd/src/lib。\n"
        "CLI 的 -z / --compression-level 会在运行时被拒绝。")
    endif()
  endif()
endif()
if(NOT FE_ZSTD_FOUND)
  target_compile_definitions(FileEncryptor PRIVATE FE_WITHOUT_ZSTD)
endif()

# ============ libvdisk（加密盘共享库：Windows=vdisk.dll / Linux=libvdisk.so）+ FE-Mounter ============
# 加密盘引擎以共享库产出，对外只暴露设计文档 §5.2 的 C ABI（符号最小化，§5.1#7）；
# FE-Mounter 进程用绝对路径动态加载它并持有挂载（§5.1#3）。
# 依赖（libsodium/zstd/OpenSSL/yaml-cpp）直接复用已装配好的 FileEncryptor 目标：
# 用 get_target_property 转移 include / 定义 / 编译选项 / 链接库，零重复维护、随 exe 同步。
set(VDISK_CORE_SOURCES
  core/FileEncryptor.cpp core/cipher.cpp core/ptd_format.cpp core/kdf.cpp
  core/source_handling.cpp core/config.cpp core/keylib.cpp core/progress_frame.cpp
  core/asym_crypto.cpp core/mapped_file.cpp core/password_policy.cpp
  core/machine_id.cpp core/watermark.cpp core/split_volumes.cpp core/archive.cpp
  core/keywrap.cpp core/vault_index.cpp core/vdisk_abi.cpp)

add_library(vdisk SHARED ${VDISK_CORE_SOURCES})
add_library(FileEncryptor::vdisk ALIAS vdisk)

get_target_property(_fe_incs  FileEncryptor INCLUDE_DIRECTORIES)
get_target_property(_fe_defs  FileEncryptor COMPILE_DEFINITIONS)
get_target_property(_fe_opts  FileEncryptor COMPILE_OPTIONS)
get_target_property(_fe_links FileEncryptor LINK_LIBRARIES)
if(_fe_incs)
  target_include_directories(vdisk PRIVATE ${_fe_incs})
endif()
if(_fe_defs)
  target_compile_definitions(vdisk PRIVATE ${_fe_defs})
endif()
if(_fe_opts)
  target_compile_options(vdisk PRIVATE ${_fe_opts})
endif()
if(_fe_links)
  target_link_libraries(vdisk PRIVATE ${_fe_links})
endif()
# vdisk 是共享库：Linux 发行版的 libz.a/libcrypto.a 常为非 PIC（无 -fPIC 编译），
# 直接链进 .so 会报 "relocation R_X86_64_PC32 ... can not be used when making a
# shared object"。可执行文件不受此限，故只需给共享库换成动态版。
if(UNIX AND NOT APPLE)
  foreach(_dep z crypto ssl)
    # _fe_links 里存的是绝对路径（.../libz.a），故按文件名匹配而非裸名
    foreach(_l IN LISTS _fe_links)
      get_filename_component(_ln "${_l}" NAME_WE)
      string(REGEX REPLACE "^lib" "" _ln "${_ln}")   # libz.a -> z
      if(_ln STREQUAL "${_dep}")
        # 把 .a 换成同名 .so（共享库可链入 .so；发行版静态库常无 -fPIC）
        string(REGEX REPLACE "\\.a$" ".so" _lso "${_l}")
        if(EXISTS "${_lso}")
          # 先移除非 PIC 静态库，再链共享版（顺序无关，链接器取先出现的）
          list(REMOVE_ITEM _fe_links "${_l}")
          list(APPEND _fe_links "${_lso}")
          set(_vdisk_extra_links ${_vdisk_extra_links} "${_lso}")
          message(STATUS "vdisk(${_dep}): 改用共享库 ${_lso}（静态版非 PIC，无法链入 .so）")
        else()
          message(WARNING "vdisk(${_dep}): 只找到非 PIC 静态库 ${_l}，libvdisk.so 链接可能失败。\n"
                          "  Linux 装共享版：apt install zlib1g-dev libssl-dev（通常已含 .so）")
        endif()
        break()
      endif()
    endforeach()
  endforeach()
  if(_vdisk_extra_links)
    set_property(TARGET vdisk PROPERTY LINK_LIBRARIES ${_fe_links})
  endif()
endif()
# 同步 MSVC 运行时库属性（静态 libsodium 需 /MT，否则 vdisk 自身对象默认 /MD 与之冲突 LNK2038）
get_target_property(_fe_msvc_rt FileEncryptor MSVC_RUNTIME_LIBRARY)
if(MSVC AND _fe_msvc_rt)
  set_target_properties(vdisk PROPERTIES MSVC_RUNTIME_LIBRARY "${_fe_msvc_rt}")
endif()
target_compile_definitions(vdisk PRIVATE VDISK_BUILD)   # 打开 vdisk.h 的 dllexport/visibility

# 输出与 exe 同目录（VS 生成器下同为 bin/<Config>/），FE-Mounter 才能同目录绝对路径加载。
set_target_properties(vdisk PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
  LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
  ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
  CXX_VISIBILITY_PRESET hidden          # GCC/Clang：默认隐藏内部符号，仅 VDISK_API 可见
  VISIBILITY_INLINES_HIDDEN ON)
if(MSVC)
  # CFG：编译与链接两侧都要给（与 exe 一致）
  target_compile_options(vdisk PRIVATE /guard:cf)
  target_link_options(vdisk PRIVATE /guard:cf)
endif()

# ---- FE-Mounter：加载 libvdisk 的 holder 进程（不链接核心，运行时 dlopen/LoadLibrary）----
# 独立可执行文件，不属于 CLI 本体：CLI 只做文件加密/解密，加密盘挂载是可选能力
# （GUI MSI 里作为可勾选的 VaultFeature）。默认不随 CLI 构建，需要时：
#   -D FE_BUILD_MOUNT=ON（与 CLI 一起构建）
#   或直接用 FE-Mounter/CMakeLists.txt 单独构建（产出会自动放到 CLI 的 bin 目录）
option(FE_BUILD_MOUNT "Build FE-Mounter (encrypted vault mount holder)" OFF)
if(ANDROID AND FE_BUILD_MOUNT)
  # Android 既无 FUSE 挂载权限也无 WinFSP，holder 进程在此毫无意义
  message(WARNING "Android 不支持挂载：已强制关闭 FE_BUILD_MOUNT。")
  set(FE_BUILD_MOUNT OFF)
endif()
if(FE_BUILD_MOUNT)
# 代码按职责拆分在 FE-Mounter/：main(入口/FUSE) fe_vdisk(加载/工具) fe_ipc(§5.1) fe_service(常驻) fe_winfsp(Windows挂载)
set(FE_MOUNT_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/../FE-Mounter/main.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../FE-Mounter/fe_vdisk.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../FE-Mounter/fe_ipc.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../FE-Mounter/fe_service.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../FE-Mounter/fe_winfsp.cpp)
add_executable(FE-Mounter ${FE_MOUNT_SOURCES})
target_include_directories(FE-Mounter PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
set_target_properties(FE-Mounter PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
if(MSVC)
  target_compile_options(FE-Mounter PRIVATE /guard:cf)
  target_link_options(FE-Mounter PRIVATE /guard:cf)
endif()
if(UNIX)
  target_link_libraries(FE-Mounter PRIVATE ${CMAKE_DL_LIBS})   # dlopen
endif()

# ---- fuse3（Linux 只读挂载，M2）----
# pkg-config 探测；未装 libfuse3-dev 时 FE-Mounter 仍可构建（selftest/cat/bench/
# lifecycle/ipc 全部可用，仅缺 mount 子命令），不硬失败。
if(UNIX AND NOT APPLE)
  find_package(PkgConfig QUIET)
  if(PKG_CONFIG_FOUND)
    pkg_check_modules(FUSE3 QUIET fuse3>=3.0)
  endif()
  if(FUSE3_FOUND)
    target_compile_definitions(FE-Mounter PRIVATE FE_HAVE_FUSE=1)
    # 源码按 <fuse3/fuse.h> 写，故要 includedir（.../include），不是 pkg-config Cflags
    # 里那个已带 /fuse3 的路径，也不是 INCLUDE_DIRS（那是 .../include/fuse3，层级差一层）。
    if(FUSE3_INCLUDEDIR)
      target_include_directories(FE-Mounter PRIVATE "${FUSE3_INCLUDEDIR}")
    endif()
    target_link_libraries(FE-Mounter PRIVATE ${FUSE3_LIBRARIES})
    target_link_directories(FE-Mounter PRIVATE ${FUSE3_LIBRARY_DIRS})
    message(STATUS "fuse3: ${FUSE3_VERSION} (${FUSE3_LIBRARIES}, inc=${FUSE3_INCLUDEDIR})")
  else()
    message(STATUS "fuse3: 未找到（装 libfuse3-dev 启用 Linux mount 子命令）")
  endif()
endif()

# ---- WinFSP（Windows 原生只读挂载，M3）----
# 可选 SDK：环境变量 FEWIN_FSP_ROOT 或默认安装位置；找到才定义 FE_HAVE_WINFSP，
# 未装则 FE-Mounter 仅提供 selftest/cat/bench/lifecycle（挂载能力缺席，不报错）。
if(WIN32)
  set(FE_HAVE_WINFSP OFF)
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
      set(FE_HAVE_WINFSP ON)
      # winfsp.h 内部 #include <winfsp/fsctl.h>，故 inc 与 inc/winfsp 都要在路径上
      target_include_directories(FE-Mounter PRIVATE "${_winfsp_root}/inc" "${_winfsp_root}/inc/winfsp")
      target_compile_definitions(FE-Mounter PRIVATE FE_HAVE_WINFSP=1)
      target_link_libraries(FE-Mounter PRIVATE "${_winfsp_lib}")
      # usermode 驱动 DLL 复制到 exe 同目录：FE-Mounter 静态导入 winfsp-x64.dll，
      # 缺失则进程加载即 0xC0000135（SDK 装在 Program Files 不在搜索路径）
      add_custom_command(TARGET FE-Mounter POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${_winfsp_root}/bin/winfsp-x64.dll" "$<TARGET_FILE_DIR:FE-Mounter>/")
      message(STATUS "WinFSP: ${_winfsp_root} (${_winfsp_lib})")
    else()
      message(WARNING "找到 WinFSP 头但缺 ${_winfsp_lib}；FE-Mounter 不含挂载能力。")
    endif()
  else()
    message(STATUS "WinFSP: 未找到 SDK（设 FEWIN_FSP_ROOT 指向安装目录以启用 Windows 挂载）")
  endif()
endif()   # WIN32（WinFsp 探测）
endif()   # FE_BUILD_MOUNT

# 构建期静态链接校验（Linux/macOS）：确认 zstd 已静态打进可执行文件，而非动态依赖 libzstd.so。
if(UNIX AND NOT APPLE AND FE_ZSTD_STATIC)
  find_program(OBJDUMP_EXECUTABLE NAMES objdump)
  if(OBJDUMP_EXECUTABLE)
    add_custom_command(TARGET FileEncryptor POST_BUILD
      COMMENT "校验 zstd 已静态链接（无动态 NEEDED）"
      COMMAND ${CMAKE_COMMAND} -P
              "${CMAKE_CURRENT_SOURCE_DIR}/cmake/CheckStaticZstd.cmake"
              "$<TARGET_FILE:FileEncryptor>" "${OBJDUMP_EXECUTABLE}"
      VERBATIM)
  endif()
endif()

# Windows 动态链接时，把 libsodium.dll 复制到 exe 所在目录，保证直接运行
if(SODIUM_DLL)
  add_custom_command(TARGET FileEncryptor POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${SODIUM_DLL}"
            "$<TARGET_FILE_DIR:FileEncryptor>/")
endif()

# 构建期静态链接校验（Linux/macOS）：确认 libsodium 已静态打进可执行文件，
# 而非动态依赖 libsodium.so。若仍为动态链接则构建失败，避免产出"假自包含"的包。
if(UNIX AND NOT APPLE AND SODIUM_IS_STATIC)
  find_program(OBJDUMP_EXECUTABLE NAMES objdump)
  if(OBJDUMP_EXECUTABLE)
    add_custom_command(TARGET FileEncryptor POST_BUILD
      COMMENT "校验 libsodium 已静态链接（无动态 NEEDED）"
      COMMAND ${CMAKE_COMMAND} -P
              "${CMAKE_CURRENT_SOURCE_DIR}/cmake/CheckStaticSodium.cmake"
              "$<TARGET_FILE:FileEncryptor>" "${OBJDUMP_EXECUTABLE}"
      VERBATIM)
  endif()
endif()

# 可执行文件统一输出到 build/bin。OUTPUT_NAME FileEncryptorCLI：CMake 目标名仍为 FileEncryptor，
# 产物文件名 FileEncryptorCLI(.exe)，对应 GUI 的 FileEncryptorLocator 查找目标。
set_target_properties(FileEncryptor PROPERTIES
  OUTPUT_NAME FileEncryptorCLI
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
  INSTALL_RPATH_USE_LINK_PATH TRUE)

# ---------- PGO（MSVC 两阶段构建，在 LTO 基础上） ----------
# Phase 1 插桩: cmake -B build -DFE_PGO=INSTRUMENT && cmake --build build，运行训练负载生成 .pgc；
# Phase 2 优化: 同目录重配 -DFE_PGO=OPTIMIZE 再 build（/LTCG:PGOPTIMIZE 合并 .pgc）。非 MSVC 不支持。
set(FE_PGO "" CACHE STRING "MSVC PGO 阶段：INSTRUMENT（插桩）/ OPTIMIZE（优化）；留空=关闭")
if(FE_PGO)
  if(NOT MSVC)
    message(WARNING "FE_PGO 仅支持 MSVC，当前编译器不支持，已忽略。")
  elseif(FE_PGO STREQUAL "INSTRUMENT")
    target_link_options(FileEncryptor PRIVATE /LTCG:PGINSTRUMENT)
    # 插桩 exe 运行时需要 PGO 运行时库 pgort140.dll（否则进程直接起不来、退出码 126/127）。
    # 从编译器同目录取并复制到 exe 旁；仅插桩阶段需要，最终 OPTIMIZE 二进制不依赖它。
    get_filename_component(_fe_pgort_dir "${CMAKE_CXX_COMPILER}" DIRECTORY)
    find_file(FE_PGORT_DLL NAMES pgort140.dll HINTS "${_fe_pgort_dir}")
    if(FE_PGORT_DLL)
      add_custom_command(TARGET FileEncryptor POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different "${FE_PGORT_DLL}"
                "$<TARGET_FILE_DIR:FileEncryptor>/"
        VERBATIM)
      message(STATUS "PGO: 已安排复制 PGO 运行时 ${FE_PGORT_DLL} 到 exe 目录")
    else()
      message(WARNING "PGO: 未找到 pgort140.dll，插桩 exe 可能无法启动（请把它放到 exe 同目录）")
    endif()
    message(STATUS "PGO: 插桩阶段——构建后运行训练负载生成 .pgc，再以 FE_PGO=OPTIMIZE 重配重链")
  elseif(FE_PGO STREQUAL "OPTIMIZE")
    target_link_options(FileEncryptor PRIVATE /LTCG:PGOPTIMIZE /USEPROFILE)
    message(STATUS "PGO: 优化阶段——合并训练 .pgc，产出 PGO 优化二进制")
  else()
    message(FATAL_ERROR "FE_PGO 取值无效：${FE_PGO}（应为 INSTRUMENT 或 OPTIMIZE）")
  endif()
endif()

# ---------- 安装与打包（DEB / RPM） ----------
# 构建即产出规范命名 <名>-<版本>-<平台>（如 FileEncryptorCLI-2.4.2-cmd-Linux），版本取 PROJECT_VERSION。
get_target_property(FE_OUTPUT_NAME_BASE FileEncryptor OUTPUT_NAME)
if(NOT FE_OUTPUT_NAME_BASE)
  set(FE_OUTPUT_NAME_BASE "FileEncryptor")
endif()
if(WIN32)
  set(FE_PLATFORM "Windows")
else()
  set(FE_PLATFORM "Linux")
endif()
# Windows 链接器会自动追加 .exe；OUTPUT_NAME 不再手动加，避免生成 ...Windows.exe.exe。
set(FE_RENAMED_EXE "${FE_OUTPUT_NAME_BASE}-${PROJECT_VERSION}-cmd-${FE_PLATFORM}")

# 构建即按规范命名产出（链接器直接写出规范文件名），无需事后复制/重命名。
set_target_properties(FileEncryptor PROPERTIES OUTPUT_NAME "${FE_RENAMED_EXE}")

# Linux：构建后复制到约定发布目录（文件已规范命名，仅作副本分发）；Windows 不复制。
# 发布目录优先落到 Windows 可见位置：VS+WSL 且 E: 盘以 DrvFS 挂于 /mnt/e 时写 /mnt/e/...，
# 否则回落源码树下同源目录。
if(NOT WIN32)
  get_filename_component(FE_SRC_LEAF "${CMAKE_SOURCE_DIR}" NAME)
  if(EXISTS "/mnt/e/FileEncryptor/${FE_SRC_LEAF}/CMakeLists.txt")
    set(FE_STAGE_BASE "/mnt/e/FileEncryptor/${FE_SRC_LEAF}")
  else()
    set(FE_STAGE_BASE "${CMAKE_SOURCE_DIR}")
  endif()
  set(FE_OUT_DIR "${FE_STAGE_BASE}/out/Ubuntu-26.04/build/linux-release/bin")
  add_custom_command(TARGET FileEncryptor POST_BUILD
    COMMENT "Stage executable -> ${FE_OUT_DIR}/${FE_RENAMED_EXE}"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${FE_OUT_DIR}"
    COMMAND ${CMAKE_COMMAND} -E copy "$<TARGET_FILE:FileEncryptor>"
            "${FE_OUT_DIR}/${FE_RENAMED_EXE}"
    VERBATIM)

  # 构建后自动打包 DEB/RPM：cmake --build 与 IDE target 不执行 cpack，故挂 POST_BUILD；
  # 同 POST_BUILD 命令按序执行，天然保证「复制→打包」先后。包目录在 include(CPack) 前设置。
  set(FE_PKG_DIR "${FE_STAGE_BASE}/out/packages")
  set(CPACK_PACKAGE_DIRECTORY "${FE_PKG_DIR}")
  if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/cmake/package_linux.cmake")
    add_custom_command(TARGET FileEncryptor POST_BUILD
      COMMENT "Packaging DEB/RPM -> ${FE_PKG_DIR}"
      COMMAND ${CMAKE_COMMAND}
              -DFE_PKG_BUILD_DIR=${CMAKE_BINARY_DIR}
              -DFE_PKG_OUT_DIR=${FE_PKG_DIR}
              -P "${CMAKE_CURRENT_LIST_DIR}/cmake/package_linux.cmake"
      VERBATIM)
  endif()
endif()

# 安装 / 打包（DEB/RPM）时放置规范命名的二进制到 /usr/bin（包内文件名即规范命名）。
install(TARGETS FileEncryptor RUNTIME DESTINATION bin
        PERMISSIONS OWNER_EXECUTE OWNER_READ
                    GROUP_EXECUTE GROUP_READ
                    WORLD_EXECUTE WORLD_READ)

# 附带自动更新器：Updater 是独立工程，Linux 产物由它自己的 POST_BUILD 暂存到约定目录；
# 打包时直接取这份已构建好的产物，免得 CLI 包去编译 curl。
set(FE_UPDATER_STAGE "${CMAKE_SOURCE_DIR}/../Updater/out/Ubuntu-26.04/build/linux-release/bin/Updater")
if(EXISTS "${FE_UPDATER_STAGE}")
  install(PROGRAMS "${FE_UPDATER_STAGE}" DESTINATION bin RENAME Updater
          PERMISSIONS OWNER_EXECUTE OWNER_READ
                      GROUP_EXECUTE GROUP_READ
                      WORLD_EXECUTE WORLD_READ)
else()
  message(STATUS "[package] 未找到 Updater（${FE_UPDATER_STAGE}）：DEB/RPM 不含自动更新器。"
                 "先构建 Updater 再打包即可得到它。")
endif()

# ---- Linux：加密盘挂载组件（FE-Mounter + libvdisk.so）----
# 与 Windows MSI 的 VaultFeature 对位：不选/不装也不影响 CLI 本体（文件加密解密照常），
# 只是不能把加密盘挂成目录。FE-Mounter 是独立工程，产物由它自己的构建树产出，
# 这里按若干候选路径取现成二进制（同 Updater 的做法，不在本工程里重编一遍）。
if(NOT WIN32)
  # libvdisk.so 是本工程 vdisk 目标的直接产物，装 /usr/lib（fe-mounter 在 /usr/bin，
  # 两者不同目录：fe_vdisk.cpp 的 default_lib_path() 会按序探测系统库目录）
  install(TARGETS vdisk LIBRARY DESTINATION lib)

  set(_fe_mount_candidates
      "${CMAKE_SOURCE_DIR}/../FE-Mounter/out/bin/FE-Mounter"
      "${CMAKE_SOURCE_DIR}/../FE-Mounter/out/bin/Release/FE-Mounter"
      "${CMAKE_BINARY_DIR}/bin/FE-Mounter")
  set(FE_MOUNT_STAGE "")
  foreach(_c IN LISTS _fe_mount_candidates)
    if(NOT FE_MOUNT_STAGE AND EXISTS "${_c}")
      set(FE_MOUNT_STAGE "${_c}")
    endif()
  endforeach()
  if(FE_MOUNT_STAGE)
    install(PROGRAMS "${FE_MOUNT_STAGE}" DESTINATION bin RENAME fe-mounter
            PERMISSIONS OWNER_EXECUTE OWNER_READ
                        GROUP_EXECUTE GROUP_READ
                        WORLD_EXECUTE WORLD_READ)
    message(STATUS "[package] 加密盘挂载组件: ${FE_MOUNT_STAGE} -> /usr/bin/fe-mounter")
  else()
    message(STATUS "[package] 未找到 FE-Mounter（试过 ${_fe_mount_candidates}）："
                   "DEB/RPM 不含加密盘挂载组件，只装 CLI 本体。"
                   "先构建 FE-Mounter/CMakeLists.txt 再打包即可得到它。")
  endif()
endif()

set(CPACK_PACKAGE_NAME "file-encryptor-cli")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")   # 与 project(VERSION) 同步
set(CPACK_PACKAGE_VENDOR "FileEncryptor")
set(CPACK_PACKAGE_CONTACT "maintainer@example.com")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Cross-platform file encryption CLI (libsodium, AEGIS-256)")
set(CPACK_PACKAGE_DESCRIPTION
    "FileEncryptorCLI encrypts and decrypts files using libsodium (XChaCha20-Poly1305 / AEGIS-256). \
The binary is statically linked against libsodium and yaml-cpp, so the installed package requires \
no external libsodium or other third-party libraries at runtime. \
The companion GUI frontend lives in the FileEncryptorGUI project.")
set(CPACK_PACKAGE_LICENSE "GPLv3")
if(EXISTS "${CMAKE_SOURCE_DIR}/LICENSE")
  set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/LICENSE")
endif()

set(CPACK_GENERATOR "DEB;RPM")
set(CPACK_PACKAGING_INSTALL_PREFIX "/usr")

# —— DEB ——
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "maintainer@example.com")
set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
# 静态链接后无外部 .so 依赖，关闭自动依赖探测，避免把 libsodium 写进 Depends
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS OFF)
# 显式清空依赖声明，确保 DEB 的 Depends 字段为空（零声明依赖、完全自包含）
set(CPACK_DEBIAN_PACKAGE_DEPENDS "")
# 但 fe-mounter 挂载加密盘要 dlopen/链接 libfuse3：放进 Suggests（Recommends 会强装），
# 只在用户真去挂载时才需要，不该让只用法加密的 CLI 用户被拖上 FUSE。
set(CPACK_DEBIAN_PACKAGE_SUGGESTS "libfuse3-3 (>= 3.0)")

# —— RPM ——
set(CPACK_RPM_PACKAGE_LICENSE "GPLv3")
set(CPACK_RPM_PACKAGE_GROUP "Applications/System")
# 关闭自动依赖探测，避免 rpm 把 libsodium 列为必需（静态链接后无需）
set(CPACK_RPM_PACKAGE_AUTOREQ OFF)
# 同时关闭自动 Provides/Requires，确保 RPM 不声明任何依赖
set(CPACK_RPM_PACKAGE_AUTOREQPROV OFF)
# 与 DEB 的 Suggests 对位：libfuse3 只是挂载加密盘时需要
set(CPACK_RPM_PACKAGE_RECOMMENDS "libfuse3")

# ---------- 模糊测试 harness（可选） ----------
# FE_BUILD_FUZZ=ON 构建 FileEncryptorFuzz：驱动 CLI/fuzz/fuzz_ptd_header.cpp。
#   clang：直接加 -fsanitize=fuzzer,address，产出可喂给 libFuzzer 的二进制；
#   其他编译器：编译出"读文件当输入"的独立驱动，可手工喂样本回归。
# 只依赖 ptd_format + libsodium，不牵连 yaml-cpp/zstd/age，保持 harness 轻量。
option(FE_BUILD_FUZZ "Build the fuzz harness (CLI/fuzz)" OFF)
if(FE_BUILD_FUZZ)
  add_executable(FileEncryptorFuzz
    fuzz/fuzz_ptd_header.cpp
    core/ptd_format.cpp)
  target_include_directories(FileEncryptorFuzz PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/core ${SODIUM_INCLUDE_DIRS})
  if(SODIUM_LINK_LIBRARY)
    target_link_libraries(FileEncryptorFuzz PRIVATE ${SODIUM_LINK_LIBRARY})
  else()
    target_link_libraries(FileEncryptorFuzz PRIVATE ${SODIUM_LIBRARIES})
  endif()
  target_compile_definitions(FileEncryptorFuzz PRIVATE SODIUM_STATIC)
  if(MSVC)
    set_target_properties(FileEncryptorFuzz PROPERTIES
      MSVC_RUNTIME_LIBRARY "MultiThreaded")
  endif()
  if(CMAKE_CXX_COMPILER_ID MATCHES "Clang" AND NOT MSVC)
    target_compile_options(FileEncryptorFuzz PRIVATE -fsanitize=fuzzer,address)
    target_link_options(FileEncryptorFuzz PRIVATE -fsanitize=fuzzer,address)
  endif()
endif()

# 打包阶段剥离调试符号，减小包体积（仅作用于打包副本，不影响构建树中的二进制）
set(CPACK_STRIP_FILES ON)
# RPM 发布号（包文件名中的 -1）
set(CPACK_PACKAGE_RELEASE "1")

include(CPack)
