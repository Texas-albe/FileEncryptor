# Updater — FileEncryptor 自动更新器（独立命令行工具）
# HTTP 层用 libcurl：Windows/Linux 均从 bundled 源码静态编译；产物名固定 Updater(.exe)。

cmake_minimum_required(VERSION 3.20)

# 必须在 project() 之前钉住链接器（同 CLI，见 CLI/CMakeLists.txt 注释）
if(WIN32)
  find_program(FE_CL_EXECUTABLE NAMES cl.exe
               HINTS "$ENV{VCToolsInstallDir}/bin/Hostx64/x64"
                     "$ENV{VCToolsInstallDir}/bin/Hostx86/x64")
  if(FE_CL_EXECUTABLE)
    get_filename_component(FE_CL_DIR "${FE_CL_EXECUTABLE}" DIRECTORY)
    set(CMAKE_LINKER "${FE_CL_DIR}/link.exe" CACHE FILEPATH "MSVC 链接器" FORCE)
  endif()
endif()

project(Updater VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Release 全程序优化（LTO）
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)

# UTF-8 源文件
if(MSVC)
  add_compile_options(/utf-8)
endif()

if(POLICY CMP0091)
  cmake_policy(SET CMP0091 NEW)
endif()

# 静态 CRT（Windows）
if(MSVC)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>" CACHE STRING "" FORCE)
endif()

# 工程化开关
option(FE_ENABLE_ASAN "Build with AddressSanitizer" OFF)
if(FE_ENABLE_ASAN)
  if(MSVC)
    message(WARNING "FE_ENABLE_ASAN: MSVC 下需与动态 CRT(/MD) 配合；CI 的 ASan 任务在 Linux 上运行。")
    add_compile_options(/fsanitize=address)
    add_link_options(/fsanitize=address)
  else()
    add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address)
  endif()
endif()

# libcurl 为 C 源码，显式启用 C 语言
enable_language(C)

set(HTTP_ONLY ON CACHE BOOL "" FORCE)            # 仅 HTTP/HTTPS
set(BUILD_CURL_EXE OFF CACHE BOOL "" FORCE)      # 不编 curl.exe
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)   # 静态库
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)       # 关闭 curl 测试
set(CURL_USE_LIBPSL OFF CACHE BOOL "" FORCE)     # 关闭可选后端
set(CURL_USE_LIBSSH2 OFF CACHE BOOL "" FORCE)    # 同上
set(USE_NGHTTP2 OFF CACHE BOOL "" FORCE)         # 同上
set(CURL_ZLIB OFF CACHE BOOL "" FORCE)           # 不依赖 zlib
set(CURL_BROTLI OFF CACHE BOOL "" FORCE)         # 不依赖 brotli
set(CURL_ZSTD OFF CACHE BOOL "" FORCE)           # 不依赖 zstd
set(CURL_USE_PKGCONFIG OFF CACHE BOOL "" FORCE)  # 禁 pkg-config 检测
set(BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)      # 不编译 curl 示例程序

if(WIN32)
  # Windows 走 Schannel（系统原生 TLS）：curl 的 OpenSSL 后端在 Windows 上不读系统证书库，
  # 而 Updater 目录里往往没有 ca-bundle.crt，TLS 校验必失败（用户侧表现为「检查不了更新」）。
  # updater.cpp 自带 SHA256，Windows 下 Updater 不再需要 OpenSSL。
  set(CURL_USE_SCHANNEL ON CACHE BOOL "" FORCE)
  set(CURL_USE_OPENSSL OFF CACHE BOOL "" FORCE)
  set(CURL_WINDOWS_SSPI ON CACHE BOOL "" FORCE)  # Schannel 需要 SSPI
else()
  set(CURL_USE_OPENSSL ON CACHE BOOL "" FORCE)   # Linux 用系统 OpenSSL
  set(OPENSSL_USE_STATIC_LIBS ON)                # curl 内部检测也走静态
endif()

# Updater 只要静态库，不要 curl 的安装规则：否则 libcurl 的 curl-config、
# pkgconfig、头文件与 man page 会冒泡进顶层，把 Updater 的 DEB/RPM 撑到 500+ 文件
set(CURL_DISABLE_INSTALL ON CACHE BOOL "" FORCE)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../third_party/curl
                 ${CMAKE_CURRENT_BINARY_DIR}/curl-build)

# curl 目标归入文件夹，免得 VS 目标列表刷屏
set_property(GLOBAL PROPERTY USE_FOLDERS ON)
get_target_property(_fe_curl_real libcurl ALIASED_TARGET)
if(_fe_curl_real)
  set_target_properties(${_fe_curl_real} PROPERTIES FOLDER "third_party/curl")
endif()
foreach(_fe_curl_tgt curl-ca-bundle curl-ca-firefox curl-lint curl_uninstall)
  if(TARGET ${_fe_curl_tgt})
    set_target_properties(${_fe_curl_tgt} PROPERTIES FOLDER "third_party/curl")
  endif()
endforeach()

# 裸名依赖强制按静态解析（须在 target 创建前设置，目录属性按创建时快照）
set(CMAKE_LINK_LIBRARY_USING_FE_STATIC "LINKER:--push-state,--static"
                                        "LINKER:--pop-state")
set(CMAKE_LINK_LIBRARY_OVERRIDE_zstd FE_STATIC)
set(CMAKE_LINK_LIBRARY_OVERRIDE_jitterentropy FE_STATIC)

# ===================== 构建 Updater =====================
add_executable(Updater src/updater.cpp)

# 静态链接需 CURL_STATICLIB，否则符号被声明为 dllimport
target_compile_definitions(Updater PRIVATE CURL_STATICLIB)
target_include_directories(Updater PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../third_party/curl/include)
target_link_libraries(Updater PRIVATE libcurl)

if(NOT WIN32)
  # 静态 libcurl 的 OpenSSL 符号需显式链 OpenSSL：优先静态 .a，否则动态
  find_package(Threads REQUIRED)
  set(OPENSSL_USE_STATIC_LIBS ON)
  find_package(OpenSSL QUIET)
  if(OpenSSL_FOUND)
    set(FE_CURL_OPENSSL_STATIC ON)
  else()
    set(OPENSSL_USE_STATIC_LIBS OFF)
    find_package(OpenSSL REQUIRED)
    set(FE_CURL_OPENSSL_STATIC OFF)
  endif()
  # 静态 libcrypto 自带 zstd/jitter 传递依赖，FindOpenSSL 以裸名挂进
  # INTERFACE 会被链接器解析成动态 so。直接清空其 INTERFACE，
  # 由 Updater 显式按序补链：依赖库须在被引用的 libcrypto 之后
  set_target_properties(OpenSSL::Crypto OpenSSL::SSL PROPERTIES
    INTERFACE_LINK_LIBRARIES "")
  set(_fe_orig_suffixes ${CMAKE_FIND_LIBRARY_SUFFIXES})
  set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
  find_library(FE_DEP_ZSTD_A NAMES zstd)
  find_library(FE_DEP_JITTER_A NAMES jitterentropy)
  set(CMAKE_FIND_LIBRARY_SUFFIXES ${_fe_orig_suffixes})
  if(NOT FE_DEP_ZSTD_A OR NOT FE_DEP_JITTER_A)
    message(FATAL_ERROR "缺少 zstd/jitterentropy 静态库，"
      "请安装 libzstd-dev 与 libjitterentropy3-dev")
  endif()
  target_link_libraries(Updater PRIVATE
      OpenSSL::SSL OpenSSL::Crypto
      ${FE_DEP_ZSTD_A} ${FE_DEP_JITTER_A}
      Threads::Threads ${CMAKE_DL_LIBS})
endif()

if(WIN32)
  # Schannel 链接所需的系统库
  target_link_libraries(Updater PRIVATE
      ws2_32 crypt32 advapi32 user32 bcrypt ncrypt iphlpapi)
endif()

if(MSVC)
  target_compile_options(Updater PRIVATE /W3 /utf-8 /EHsc)
endif()

# 产物名 Updater：GUI 按固定文件名查找，改名会导致找不到
# per-config 固定到 bin：VS 多配置生成器不再追加 Release/Debug 子目录
set_target_properties(Updater PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
  RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/bin
  RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/bin
  RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO ${CMAKE_BINARY_DIR}/bin
  RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL ${CMAKE_BINARY_DIR}/bin)

# ---------- WSL 构建选项（staging 到 Windows 可见位置） ----------
if(NOT WIN32)
  get_filename_component(FE_UPD_SRC_LEAF "${CMAKE_SOURCE_DIR}" NAME)
  if(EXISTS "/mnt/e/FileEncryptor/${FE_UPD_SRC_LEAF}/CMakeLists.txt")
    set(FE_UPD_STAGE_BASE "/mnt/e/FileEncryptor/${FE_UPD_SRC_LEAF}")
  else()
    set(FE_UPD_STAGE_BASE "${CMAKE_SOURCE_DIR}")
  endif()
  set(FE_UPD_OUT_DIR "${FE_UPD_STAGE_BASE}/out/Ubuntu-26.04/build/linux-release/bin")
  add_custom_command(TARGET Updater POST_BUILD
    COMMENT "Stage executable -> ${FE_UPD_OUT_DIR}/$<TARGET_FILE_NAME:Updater>"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${FE_UPD_OUT_DIR}"
    COMMAND ${CMAKE_COMMAND} -E copy "$<TARGET_FILE:Updater>"
            "${FE_UPD_OUT_DIR}/$<TARGET_FILE_NAME:Updater>"
    VERBATIM)

  set(FE_UPD_PKG_DIR "${FE_UPD_STAGE_BASE}/out/packages")
  set(CPACK_PACKAGE_DIRECTORY "${FE_UPD_PKG_DIR}")
  if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/cmake/package_linux.cmake")
    add_custom_command(TARGET Updater POST_BUILD
      COMMENT "Packaging DEB/RPM -> ${FE_UPD_PKG_DIR}"
      COMMAND ${CMAKE_COMMAND}
              -DFE_PKG_BUILD_DIR=${CMAKE_BINARY_DIR}
              -DFE_PKG_OUT_DIR=${FE_UPD_PKG_DIR}
              -P "${CMAKE_CURRENT_LIST_DIR}/cmake/package_linux.cmake"
      VERBATIM)
  endif()
endif()

# ---------- 安装与打包（DEB / RPM） ----------
install(TARGETS Updater RUNTIME DESTINATION bin
        PERMISSIONS OWNER_EXECUTE OWNER_READ
                    GROUP_EXECUTE GROUP_READ
                    WORLD_EXECUTE WORLD_READ)

set(CPACK_PACKAGE_NAME "file-encryptor-updater")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_VENDOR "FileEncryptor")
set(CPACK_PACKAGE_CONTACT "maintainer@example.com")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "FileEncryptor auto-updater (libcurl)")
set(CPACK_PACKAGE_DESCRIPTION
    "Updater checks GitHub releases and downloads/verifies updates.")
set(CPACK_PACKAGE_LICENSE "GPLv3")
if(EXISTS "${CMAKE_SOURCE_DIR}/LICENSE")
  set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/LICENSE")
endif()

set(CPACK_GENERATOR "DEB;RPM")
set(CPACK_PACKAGING_INSTALL_PREFIX "/usr")

# 静态链接后无外部 .so 依赖：零声明依赖、完全自包含
if(WIN32 OR FE_CURL_OPENSSL_STATIC)
  set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS OFF)
  set(CPACK_DEBIAN_PACKAGE_DEPENDS "")
  set(CPACK_RPM_PACKAGE_AUTOREQ OFF)
  set(CPACK_RPM_PACKAGE_AUTOREQPROV OFF)
else()
  # OpenSSL 为动态：自动探测依赖
  set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
  set(CPACK_DEBIAN_PACKAGE_DEPENDS "libssl3")
  set(CPACK_RPM_PACKAGE_AUTOREQ ON)
endif()

set(CPACK_DEBIAN_PACKAGE_MAINTAINER "maintainer@example.com")
set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")

set(CPACK_RPM_PACKAGE_LICENSE "GPLv3")
set(CPACK_RPM_PACKAGE_GROUP "Applications/System")

set(CPACK_STRIP_FILES ON)
set(CPACK_PACKAGE_RELEASE "1")

include(CPack)
