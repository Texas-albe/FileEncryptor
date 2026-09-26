cmake_minimum_required(VERSION 3.15)
project(FileEncryptorCLI VERSION 2.4.2 LANGUAGES CXX)

# FileEncryptor CLI - 命令行加密工具（独立项目）
# 本项目编译产出 FileEncryptorCLI(.exe)；GUI 项目（../GUI）通过 QProcess 调用此程序。
# 静态链接 libsodium + yaml-cpp，最终二进制零外部依赖，可直接打包为 DEB/RPM。

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 全程序优化（LTO）：Release 构建启用 /GL + /LTCG，提升跨 TU 热点（KDF 调用、AEAD 循环）性能。
# 仅作用于 Release 配置，不影响 Debug。
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)

# 源码含 UTF-8 中文注释（无 BOM）。MSVC 默认按系统代码页（如 936/GBK）解析，
# 会触发 C4819，并可能把注释内误解析出的反斜杠当成行拼接、把 struct Config 吞进注释，
# 导致 "Config 未声明" 等离奇编译错误。强制以 UTF-8 读取源文件。
if(MSVC)
  add_compile_options(/utf-8)
endif()

# 让 MSVC_RUNTIME_LIBRARY 目标属性生效（用于 Windows 静态链接时切换 /MT）
if(POLICY CMP0091)
  cmake_policy(SET CMP0091 NEW)
endif()

# 是否静态链接 libsodium：静态链接后生成的可执行文件不依赖任何外部 libsodium，
# 打出的 DEB/RPM 安装包也就无需在安装时再下载 libsodium 等依赖库。
option(SODIUM_STATIC "Statically link libsodium (recommended for self-contained packages)" ON)

# ---------- 查找 libsodium（跨平台） ----------
# 查找优先级（关键：手动查找优先于 pkg-config）：
#   1) CMake 配置包（vcpkg 安装，或系统提供了 libsodium-config.cmake）
#   2) 手动 find_path + find_library（SODIUM_ROOT / LIBSODIUM_ROOT 显式指定优先；
#      且默认搜索 /usr/local 先于 /usr，能自动选中较新版本）
#   3) pkg-config（最后回退，可能指向系统中较旧的 libsodium，例如 apt 的
#      libsodium-dev 1.0.18 与源码安装的 /usr/local 1.0.22 并存时会选错）
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

# 2) 手动查找（默认优先于 pkg-config，避免系统存在多个 libsodium 时选错版本）
#    - Linux/macOS：默认搜索 /usr/local 先于 /usr，能自动选中较新版本；支持 SODIUM_ROOT。
#    - Windows：预编译包（如安装到 "C:\Program Files\libsodium"）的库位于
#      <arch>/<Release|Debug>/<v1xx>/<static|dynamic|ltcg> 子目录（MSVC 风格），
#      默认把 "C:\Program Files\libsodium" 加入搜索，并按架构/工具集自动选取。
if(NOT SODIUM_FOUND AND NOT SODIUM_TARGET)
  # ---- Windows 专用：构造预编译包的候选库目录 ----
  set(_sodium_win_hints "")
  if(WIN32)
    # 预编译包根目录：SODIUM_ROOT 优先（命令行 -DSODIUM_ROOT=...），
    # 其次随仓库分发的 third_party/libsodium（预编译库就地可用，无需系统安装），
    # 最后回退 $ENV{ProgramFiles}/libsodium（正常 Windows 环境有值；Git Bash 等不继承时需传 SODIUM_ROOT）
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
    # 候选库目录：链接顺序取决于 SODIUM_STATIC 选项。
    #   - 静态优先 (SODIUM_STATIC=ON)：static 排在最前，并配合 /MT 运行时库（见下方），
    #     得到完全自包含、无 DLL 依赖的可执行文件；Release 静态库排在 Debug 静态库之前，
    #     以便任意构建配置都链接到 /MT 版静态库，避免 Debug/Release CRT 不匹配 (LNK2038)。
    #   - 动态优先 (SODIUM_STATIC=OFF)：dynamic 排在最前，需随附 libsodium.dll。
    # 覆盖 Release 与 Debug。
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
# AEGIS-256 自 libsodium 1.0.19 起稳定提供（crypto_aead_aegis256_* API）。
# 缺陷2：显式做编译期版本校验，链接到 1.0.18 及更早版本时直接 FATAL_ERROR，
# 避免运行时行为不确定或链接期出现晦涩的 undefined reference。
# 版本来源（按优先级）：CMake 配置包导出的 sodium_VERSION > 从头文件 version.h 解析
# SODIUM_VERSION_STRING（如 "1.0.20"）。两者皆缺时回退到 AEGIS-256 头文件存在性探测。
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
# SODIUM_STATIC（默认 ON）时优先使用静态库，生成完全自包含、无外部依赖的可执行文件：
#   - Windows：上方 hints 已把 static 子目录排在前面，find_library 得到的即为静态 libsodium.lib
#     （且 Release 静态库排在 Debug 之前，任意构建配置都链接 /MT 版）。预编译的静态 libsodium
#     以 /MT 构建，必须与本项目运行时库一致，否则链接期报 LNK2038；下方在目标创建后统一切换为 /MT。
#   - Linux/macOS：查找 .a 静态库。
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

# 未找到静态库时的回退：
#   - Windows：动态导入库 + DLL（并把 DLL 复制到 exe 旁）。
#   - 其它平台：直接使用 find_library 找到的库。
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

# ---------- 校验选中的库确实包含 AEGIS-256 符号（Linux / macOS） ----------
# 防止"头文件来自 /usr/local、链接库却来自 apt 旧版"的头库不一致问题：
# 这种不一致会在链接期报诡异的 undefined reference。这里用 nm 直接检查选中的库文件。
# 注意：SODIUM_TARGET（vcpkg 等 IMPORTED 目标）无法用 nm 检查，跳过。
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
# CLI 独立项目：core/（共享加密核心）+ cli/（命令行入口）
# FileEncryptorCLI(.exe) 链接 core 全部加密逻辑，零外部依赖；GUI 通过 QProcess 调用本程序。
set(SOURCES
  core/FileEncryptor.cpp
  core/ptd_format.cpp
  core/kdf.cpp
  core/source_handling.cpp
  core/config.cpp
  core/keylib.cpp
  core/progress_frame.cpp
  core/asym_crypto.cpp
  cli/main.cpp)

# Windows 图标资源（嵌入 exe；Linux/macOS 无 .rc）
if(WIN32)
  enable_language(RC)
  list(APPEND SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/cli/FileEncryptorCLI.rc")
endif()

add_executable(FileEncryptor ${SOURCES})

# ---------- 查找 yaml-cpp（YAML 配置解析，v1.7.2 起依赖） ----------
# 两端标准安装均提供 CMake 配置包，find_package 可直接命中：
#   Windows: 安装到 "C:\Program Files\yaml-cpp"（include/ + lib/ + lib/cmake/）
#   Linux:   sudo make install 到系统路径（/usr/local），或发行版包 libyaml-cpp-dev
# 若无 CMake 配置（仅头文件 + 库的裸布局），按头文件与静态库手动查找
# （YAMLCPP_ROOT 可显式指定根目录）。
find_package(Threads REQUIRED)
set(YAMLCPP_TARGET "")
set(YAMLCPP_IS_STATIC ON)
# 库来源：优先仓库内 third_party/yaml-cpp（含 /MT 预编译静态库，与本机工具集匹配），
# 其次 find_package（CMake 配置包）/ 系统安装手动查找。避免命中系统里工具集或
# CRT 不匹配的安装（曾引发 LNK2019 / LNK2038）。
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
  target_include_directories(FileEncryptor PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/core ${SODIUM_INCLUDE_DIRS})
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
    endif()
    # 链接静态 libsodium 时必须定义 SODIUM_STATIC，否则 sodium.h 会把所有函数声明为
    # __declspec(dllimport)（产生 __imp_ 前缀符号），只有动态导入库才能满足，静态库会报
    # LNK2019 无法解析的外部符号。定义后函数即为普通 extern，由静态库直接提供。
    target_compile_definitions(FileEncryptor PRIVATE SODIUM_STATIC)
    # Windows 静态链接 libsodium 时，必须把本项目运行时库切换为静态 CRT (/MT)，
    # 否则与 libsodium 静态库的 LIBCMT 冲突，报 LNK2038（CRT 不匹配）。
    if(MSVC)
      set_target_properties(FileEncryptor PROPERTIES
        MSVC_RUNTIME_LIBRARY "MultiThreaded")
    endif()
  endif()
endif()

# ---------- 链接 yaml-cpp + Threads（YAML 配置解析所需） ----------
# 静态链接 yaml-cpp 时必须定义 YAML_CPP_STATIC_DEFINE，否则头文件会把符号声明为
# __declspec(dllimport)（产生 __imp_ 前缀），与静态库导出的普通 extern 符号不符，
# 导致 LNK2019。定义后符号即为普通 extern，由静态库直接提供（与 libsodium 的 SODIUM_STATIC 同理）。
# 动态构建（YAML_CPP_SHARED_LIBS_BUILT）时不能定义；Linux 下 dll.h 为空操作，定义与否无影响。
if(YAMLCPP_IS_STATIC)
  target_compile_definitions(FileEncryptor PRIVATE YAML_CPP_STATIC_DEFINE)
endif()
target_link_libraries(FileEncryptor PRIVATE ${YAMLCPP_TARGET} Threads::Threads)

# ---------- 平台相关的链接善后 ----------
# std::filesystem：GCC 9 之前（Ubuntu 18.04 / GCC 8 等老发行版）需显式链接 libstdc++fs，
# 否则链接期报 undefined reference to std::filesystem::...。GCC 9+ 起已并入 libstdc++。
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.0)
  target_link_libraries(FileEncryptor PRIVATE stdc++fs)
endif()

# Linux 静态链接 libsodium / yaml-cpp 时，动态加载器符号（dlopen 等）需显式链接
if(UNIX)
  target_link_libraries(FileEncryptor PRIVATE ${CMAKE_DL_LIBS})
endif()

# ---------- 非对称（混合）加密：集成 rage/age（C-ABI 静态库 fe_age） ----------
# 需先用 age-ffi/build-win.ps1（Windows / MSVC）或 build-linux.sh（Linux）编译出
# 静态库 fe_age.lib / libfe_age.a，并放在 age-ffi/lib/<platform>/ 下。
# 可用 -DFE_AGE_DIR=<age-ffi 目录> 显式指定位置。
option(WITH_AGE "Enable asymmetric (age/rage) encryption support" ON)
set(FE_AGE_FOUND FALSE)
if(WITH_AGE)
  # 库来源：默认随仓库分发的 third_party/rage/age-ffi（源码 + lib/<platform>/ 预编译静态库），
  # 旧的本机安装路径仅作回退。-DFE_AGE_DIR=<age-ffi 目录> 可显式覆盖。
  set(_age_ffi_root "${CMAKE_CURRENT_SOURCE_DIR}/../third_party/rage/age-ffi")
  if(WIN32)
    # 全部走仓库相对路径：third_party/rage/age-ffi 为唯一默认来源，不再引用任何本机绝对路径
    set(_age_hdr_hints "")
    set(_age_lib_install "")
    set(_age_lib_subdir "lib/windows")
  else()
    set(_age_hdr_hints "/usr/local/include")
    set(_age_lib_install "/usr/local/lib")
    set(_age_lib_subdir "lib/linux")
  endif()
  if(DEFINED FE_AGE_DIR AND FE_AGE_DIR)
    set(_age_ffi_root "${FE_AGE_DIR}")
  endif()
  # header lives in the source tree; lib may sit in <root>/lib/<platform> under third_party/rage/age-ffi
  find_path(FE_AGE_INCLUDE_DIR NAMES fe_age.h
    HINTS "${_age_ffi_root}" "${_age_ffi_root}/include" ${_age_hdr_hints} "${CMAKE_CURRENT_SOURCE_DIR}/../third_party/rage/age-ffi")
  if(WIN32)
    find_library(FE_AGE_LIBRARY NAMES fe_age
      HINTS "${_age_ffi_root}/lib/windows" "${_age_ffi_root}/lib"
            ${_age_lib_install}
            "${CMAKE_CURRENT_SOURCE_DIR}/../third_party/rage/age-ffi/lib/windows")
  else()
    find_library(FE_AGE_LIBRARY NAMES fe_age libfe_age
      HINTS "${_age_ffi_root}/${_age_lib_subdir}" "${_age_ffi_root}/lib"
            ${_age_lib_install}
            "${CMAKE_CURRENT_SOURCE_DIR}/../third_party/rage/age-ffi/${_age_lib_subdir}")
  endif()
  if(FE_AGE_INCLUDE_DIR AND FE_AGE_LIBRARY)
    set(FE_AGE_FOUND TRUE)
    target_include_directories(FileEncryptor PRIVATE ${FE_AGE_INCLUDE_DIR})
    target_link_libraries(FileEncryptor PRIVATE ${FE_AGE_LIBRARY})
    target_compile_definitions(FileEncryptor PRIVATE FE_WITH_AGE)
    if(WIN32)
      # Rust staticlib (MSVC target) 运行所需的系统库
      # ntdll: Rust std on Windows calls NtReadFile/NtWriteFile (LNK2019 __imp_NtReadFile / __imp_NtWriteFile)
      target_link_libraries(FileEncryptor PRIVATE bcrypt advapi32 userenv kernel32 ws2_32 ncrypt crypt32 ntdll)
    else()
      target_link_libraries(FileEncryptor PRIVATE pthread dl m)
    endif()
    message(STATUS "fe_age: 已集成 (${FE_AGE_LIBRARY})")
  else()
    message(WARNING
      "WITH_AGE=ON but fe_age was not found.\n"
      "  header=${FE_AGE_INCLUDE_DIR}\n"
      "  library=${FE_AGE_LIBRARY}\n"
      "  searched root: ${_age_ffi_root}\n"
      "Building WITHOUT asymmetric (rage) encryption. Run age-ffi/build-win.ps1 or build-linux.sh first,\n"
      "or pass -DFE_AGE_DIR=<age-ffi dir>.")
  endif()
endif()

# ---------- zstd 压缩支持（参照 zstd，可自定义压缩级别） ----------
# 优先从源码编译（third_party/zstd/src/lib）：与当前工具链 / CRT 完全一致，
# 规避预编译静态库（由更新版 MSVC 构建，引用 ___chkstk_ms 等本机 CRT 缺失符号）导致的 LNK2001。
# 预编译库（third_party/zstd/static/libzstd_static.lib）作为“源码缺失时的回退”保留，
# 但因其工具链不匹配在 Windows 下通常无法链接，故默认走源码编译。
# 缺失（且既无源码也无预编译库）时构建为“无压缩”版本（CLI 的 -z 会被拒绝并明确提示）。
# 可用 -DWITH_ZSTD=OFF 彻底关闭压缩相关代码。
option(WITH_ZSTD "Enable zstd compression support" ON)
set(FE_ZSTD_FOUND FALSE)
if(WITH_ZSTD)
  set(_zstd_root "${CMAKE_CURRENT_SOURCE_DIR}/../third_party/zstd")
  set(_zstd_src "${_zstd_root}/src/lib")
  if(EXISTS "${_zstd_src}/zstd.h")
    # ---- 从源码构建 zstd 静态库（与本工程同工具链 / 同 /MT 运行时）----
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
  else()
    # ---- 回退：使用预编译静态库（需自行放置，且工具链须兼容）----
    if(WIN32)
      find_path(ZSTD_INCLUDE_DIR NAMES zstd.h
        HINTS "${_zstd_root}/include" NO_DEFAULT_PATH)
      find_library(ZSTD_LIBRARY NAMES zstd libzstd libzstd_static zstd_static
        HINTS "${_zstd_root}/static" NO_DEFAULT_PATH)
    else()
      find_path(ZSTD_INCLUDE_DIR NAMES zstd.h
        HINTS "${_zstd_root}/include" "/usr/local/include" "/usr/include")
      find_library(ZSTD_LIBRARY NAMES zstd libzstd_static
        HINTS "${_zstd_root}/static/linux" "/usr/local/lib" "/usr/lib" "/usr/lib64")
    endif()
    if(ZSTD_INCLUDE_DIR AND ZSTD_LIBRARY)
      set(FE_ZSTD_FOUND TRUE)
      target_include_directories(FileEncryptor PRIVATE ${ZSTD_INCLUDE_DIR})
      target_link_libraries(FileEncryptor PRIVATE ${ZSTD_LIBRARY})
      target_compile_definitions(FileEncryptor PRIVATE FE_WITH_ZSTD)
      if(WIN32)
        target_link_libraries(FileEncryptor PRIVATE ws2_32)
      else()
        target_link_libraries(FileEncryptor PRIVATE pthread)
      endif()
      message(STATUS "zstd: 已集成预编译库 (${ZSTD_LIBRARY})")
    else()
      message(WARNING
        "WITH_ZSTD=ON 但未找到 zstd 源码或预编译库，将构建为“无压缩”版本。\n"
        "  请将 zstd 源码放到 third_party/zstd/src/lib，或放置预编译静态库。\n"
        "CLI 的 -z / --compression-level 会在运行时被拒绝。")
    endif()
  endif()
endif()
if(NOT FE_ZSTD_FOUND)
  target_compile_definitions(FileEncryptor PRIVATE FE_WITHOUT_ZSTD)
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

# 可执行文件统一输出到 build/bin，避免目标名与构建目录中已存在的同名目录冲突。
# OUTPUT_NAME FileEncryptorCLI：CMake 目标名仍为 FileEncryptor（保持 target_* 引用不变），
# 但产物文件名为 FileEncryptorCLI(.exe)，对应 GUI 的 FileEncryptorLocator 查找目标。
set_target_properties(FileEncryptor PROPERTIES
  OUTPUT_NAME FileEncryptorCLI
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
  INSTALL_RPATH_USE_LINK_PATH TRUE)

# ---------- PGO（Profile-Guided Optimization，MSVC 两阶段构建） ----------
# 在既有 LTO（/GL + /LTCG，Release 已默认开启）基础上再做基于训练样本的优化。
# 两阶段（同一构建目录重配即可）：
#   Phase 1（插桩）:
#     cmake -B out/build/pgo-windows -DFE_PGO=INSTRUMENT
#     cmake --build out/build/pgo-windows
#     运行代表训练负载（混合加/解密样本各跑一遍，覆盖常用模式与压缩档）
#     → 输出目录 bin/ 产生 FileEncryptorCLI.pgd 与训练期 *.pgc
#   Phase 2（优化）:
#     cmake -B out/build/pgo-windows -DFE_PGO=OPTIMIZE   （同一目录重配）
#     cmake --build out/build/pgo-windows
#     → 链接期 /LTCG:PGOPTIMIZE + /USEPROFILE 合并 .pgc，产出最终优化二进制
# 注意：.pgd/.pgc 默认落在 bin/（exe 旁），Phase 2 必须复用 Phase 1 的构建目录
# 才能自动发现训练数据；切换回普通构建时把 FE_PGO 置空即可（源码/产物不变）。
# 非 MSVC 编译器不支持（GCC 用 -fprofile-generate/-fprofile-use，另行配置）。
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
# 静态链接后最终二进制不依赖任何外部 libsodium，安装包内无需再下载依赖库。
#
# 规范命名：构建即产出 <原名称>-<版本号>-<平台> 的可执行文件（不保留原名），
# 例：FileEncryptorCLI-2.4.2-Linux / FileEncryptorCLI-2.4.2-Windows.exe。
# 版本号取自构建变量 PROJECT_VERSION（随 project(VERSION) 自动同步），
# 平台取 Linux / Windows，原名称取目标 OUTPUT_NAME（CLI 为 FileEncryptorCLI）。
# GUI 的 FileEncryptorLocator::getExpectedNames() 已按此命名探测 CLI，无需保留原名。
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
set(FE_RENAMED_EXE "${FE_OUTPUT_NAME_BASE}-${PROJECT_VERSION}-${FE_PLATFORM}")

# 构建即按规范命名产出（链接器直接写出规范文件名），无需事后复制/重命名。
set_target_properties(FileEncryptor PROPERTIES OUTPUT_NAME "${FE_RENAMED_EXE}")

# Linux：构建完成后复制到约定发布目录，文件本身已是规范命名，此处仅做副本分发；
# Windows 不做此复制步骤（用户要求）。发布目录优先落到「Windows 可见」位置：
# 经 VS+WSL 构建时 E: 盘以 DrvFS 挂载于 /mnt/e 且含本项目，则直接写入 /mnt/e/...，
# 使产物出现在 E:\FileEncryptor\...\out\Ubuntu-26.04\...；纯 Linux 原生构建（无
# DrvFS）回落到源码树下的同源目录，不破坏原生流程。
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

  # 构建后自动打包 DEB/RPM：VS+WSL、cmake --build 以及 IDE 的 --target <主目标>
  # 都只做 configure + build，永远不会执行 cpack，故挂在 POST_BUILD 上。
  # 同一 POST_BUILD 内命令按序执行，天然保证「复制 → 打包」的先后。
  # 包直接落到 Windows 可见目录（CPACK_PACKAGE_DIRECTORY 需在 include(CPack) 前设置）。
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

# —— RPM ——
set(CPACK_RPM_PACKAGE_LICENSE "GPLv3")
set(CPACK_RPM_PACKAGE_GROUP "Applications/System")
# 关闭自动依赖探测，避免 rpm 把 libsodium 列为必需（静态链接后无需）
set(CPACK_RPM_PACKAGE_AUTOREQ OFF)
# 同时关闭自动 Provides/Requires，确保 RPM 不声明任何依赖
set(CPACK_RPM_PACKAGE_AUTOREQPROV OFF)

# 打包阶段剥离调试符号，减小包体积（仅作用于打包副本，不影响构建树中的二进制）
set(CPACK_STRIP_FILES ON)
# RPM 发布号（包文件名中的 -1）
set(CPACK_PACKAGE_RELEASE "1")

include(CPack)
