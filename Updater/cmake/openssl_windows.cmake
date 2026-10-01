# Windows 静态 OpenSSL：推导 MSVC/SDK 环境后源码构建
# 幂等：头与静态库齐备则跳过；产物留在构建目录，不污染源码树
# 用法：run_openssl_windows_build(SRC_DIR <third_party/openssl 绝对路径>)

function(run_openssl_windows_build SRC_DIR)

  # ---- 产物与幂等判据 ----
  if(NOT FE_OSSL_PREFIX)
    set(FE_OSSL_PREFIX "${CMAKE_BINARY_DIR}/openssl" CACHE PATH "Windows OpenSSL 静态库前缀")
  endif()
  # 仓库级共享前缀：VS 多配置与多个构建目录复用，省一轮约 30 分钟的源码构建
  if(FE_OSSL_PREFIX STREQUAL "${CMAKE_BINARY_DIR}/openssl"
     AND EXISTS "${CMAKE_SOURCE_DIR}/out/openssl/include/openssl/ssl.h")
    set(FE_OSSL_PREFIX "${CMAKE_SOURCE_DIR}/out/openssl" CACHE PATH "Windows OpenSSL 静态库前缀" FORCE)
    message(STATUS "OpenSSL: 复用共享前缀 ${FE_OSSL_PREFIX}")
  endif()
  set(FE_OSSL_PREFIX "${FE_OSSL_PREFIX}" CACHE PATH "Windows OpenSSL 静态库前缀" FORCE)
  set(FE_OSSL_BUILD "${CMAKE_BINARY_DIR}/openssl-build")
  set(FE_OSSL_SSL "${FE_OSSL_PREFIX}/lib/libssl.lib")
  set(FE_OSSL_CRYPTO "${FE_OSSL_PREFIX}/lib/libcrypto.lib")
  if(EXISTS "${FE_OSSL_PREFIX}/include/openssl/ssl.h"
     AND EXISTS "${FE_OSSL_SSL}" AND EXISTS "${FE_OSSL_CRYPTO}")
    return()
  endif()

  # ---- 工具链：Perl 与 cl 所在目录 ----
  find_package(Perl QUIET)
  if(NOT PERL_EXECUTABLE)
    message(FATAL_ERROR "Windows 静态 OpenSSL 构建需要 Perl：安装 Strawberry Perl，"
      "或传 -DFE_OSSL_PERL=<perl.exe> 指定路径")
  endif()
  get_filename_component(_perl_dir "${PERL_EXECUTABLE}" DIRECTORY)
  get_filename_component(_cl_dir "${CMAKE_C_COMPILER}" DIRECTORY)

  # bin/Hostx64/x64 上溯三级到 MSVC 版本目录
  get_filename_component(_msvc "${_cl_dir}" DIRECTORY)
  get_filename_component(_msvc "${_msvc}" DIRECTORY)
  get_filename_component(_msvc "${_msvc}" DIRECTORY)

  # ---- SDK 版本：从 CMake 记录的库搜索路径认，不写死版本号 ----
  # 项为 <SDK>/Lib/<ver>/<mod>/<arch>，上溯两级到 SDK 根
  set(_sdk_root "")
  set(_sdk_ver "")
  foreach(_p IN LISTS CMAKE_SYSTEM_LIBRARY_PATH)
    get_filename_component(_lib "${_p}" DIRECTORY)
    get_filename_component(_ver "${_lib}" NAME)
    get_filename_component(_lib_root "${_lib}" DIRECTORY)
    get_filename_component(_sdk "${_lib_root}" DIRECTORY)
    if(_sdk MATCHES "Windows Kits")
      set(_sdk_root "${_sdk}")
      set(_sdk_ver "${_ver}")
      break()
    endif()
  endforeach()

  # rc.exe 只在 SDK 的 bin 下；个别 SDK 有 Lib/Include 却没 bin，故按版本扫一遍
  set(_sdk_bin "")
  if(_sdk_root)
    file(GLOB _bins LIST_DIRECTORIES true "${_sdk_root}/bin/*/x64")
    set(_vers "")
    foreach(_b IN LISTS _bins)
      if(EXISTS "${_b}/rc.exe")
        get_filename_component(_bv "${_b}" DIRECTORY)
        get_filename_component(_bv "${_bv}" NAME)
        list(APPEND _vers "${_bv}")
      endif()
    endforeach()
    list(REMOVE_DUPLICATES _vers)
    if(_sdk_ver IN_LIST _vers)          # 优先 CMake 选中的那个版本
      set(_vers "${_sdk_ver};${_vers}")
      list(REMOVE_DUPLICATES _vers)
    endif()
    if(_vers)
      list(GET _vers 0 _sdk_ver)
      set(_sdk_bin "${_sdk_root}/bin/${_sdk_ver}/x64")
    endif()
  endif()

  if(FE_RC_EXECUTABLE)                  # 外置 rc.exe 逃生口
    set(_sdk_bin "${FE_RC_EXECUTABLE}")
  endif()
  if(NOT EXISTS "${_sdk_bin}/rc.exe")
    message(FATAL_ERROR "未找到 Windows SDK 的 rc.exe（已尝试 ${_sdk_bin}）："
      "请安装 Windows SDK（rc.exe 在 SDK 的 bin/<ver>/x64），"
      "或传 -DFE_RC_EXECUTABLE=<rc.exe 绝对路径> 指定")
  endif()

  set(_sdk_inc "${_sdk_root}/Include/${_sdk_ver}")
  set(_sdk_lib "${_sdk_root}/Lib/${_sdk_ver}/ucrt/x64;${_sdk_root}/Lib/${_sdk_ver}/um/x64")

  # ---- nmake 直接调 cl/link/rc，环境必须齐 ----
  set(ENV{PATH} "${_cl_dir};${_sdk_bin};${_perl_dir};$ENV{PATH}")
  set(ENV{INCLUDE} "${_msvc}/include;${_sdk_inc}/shared;${_sdk_inc}/um;${_sdk_inc}/ucrt")
  set(ENV{LIB} "${_msvc}/lib/x64;${_sdk_lib}")

  file(MAKE_DIRECTORY "${FE_OSSL_BUILD}")

  message(STATUS "OpenSSL: 配置 VC-WIN64A 静态库（no-asm/no-tests/no-apps）")
  execute_process(
    COMMAND "${PERL_EXECUTABLE}" "${SRC_DIR}/Configure"
            VC-WIN64A no-shared no-asm no-tests no-apps
            --prefix=${FE_OSSL_PREFIX} --openssldir=${FE_OSSL_PREFIX}/ssl
    WORKING_DIRECTORY "${FE_OSSL_BUILD}"
    RESULT_VARIABLE _res OUTPUT_VARIABLE _out)
  if(NOT _res EQUAL 0)
    message(FATAL_ERROR "OpenSSL Configure 失败：${_out}")
  endif()

  message(STATUS "OpenSSL: 编译静态库（nmake 串行，约数十分钟）")
  execute_process(COMMAND nmake WORKING_DIRECTORY "${FE_OSSL_BUILD}"
    RESULT_VARIABLE _res OUTPUT_VARIABLE _out)
  if(NOT _res EQUAL 0)
    message(FATAL_ERROR "OpenSSL nmake 失败：${_out}")
  endif()

  message(STATUS "OpenSSL: 安装头文件与静态库")
  execute_process(COMMAND nmake install_dev WORKING_DIRECTORY "${FE_OSSL_BUILD}"
    RESULT_VARIABLE _res OUTPUT_VARIABLE _out)
  if(NOT _res EQUAL 0)
    message(FATAL_ERROR "OpenSSL install_dev 失败：${_out}")
  endif()

  message(STATUS "OpenSSL: 静态库就绪 -> ${FE_OSSL_SSL}")
endfunction()
