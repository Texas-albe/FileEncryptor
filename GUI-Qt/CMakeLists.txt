cmake_minimum_required(VERSION 3.16)

project(FileEncryptorGUI VERSION 2.0.0 LANGUAGES CXX)

# FileEncryptor GUI - Qt6 图形界面（Windows + Linux 双平台；Windows 另有 WinUI3 版本）

# Windows MSVC：smelibs 静态 Qt6 用 /MT 构建，全局统一静态 CRT
if(MSVC AND WIN32)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")
endif()

# 输出文件名框架标识
set(FE_GUI_FRAMEWORK "Qt")

# Qt6 来源：Windows 用 ../third_party/smelibs（静态 Qt 随仓库）；Linux/WSL 用 /opt/smelibs，不存在则回退系统 Qt6；其它位置用 -DCMAKE_PREFIX_PATH=... 覆盖。
if(WIN32)
  list(APPEND CMAKE_PREFIX_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../third_party/smelibs")
elseif(EXISTS "/opt/smelibs/lib/cmake/Qt6/Qt6Config.cmake")
  list(APPEND CMAKE_PREFIX_PATH "/opt/smelibs")
endif()

# Concurrent：目录规模统计（递归扫描）放到工作线程，避免大目录扫描卡住界面。
find_package(Qt6 6.2 COMPONENTS Widgets Concurrent Network REQUIRED)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# 源码含 UTF-8 中文注释与字符串：MSVC 默认按系统代码页解析会触发 C4819 并可能吞掉代码，强制 /utf-8（读取与执行字符集均为 UTF-8）；GNU/Clang 同理用 -finput-charset/-fexec-charset。
if(MSVC)
  add_compile_options(/utf-8)
elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  add_compile_options(-finput-charset=UTF-8 -fexec-charset=UTF-8)
endif()

# Windows 下启用 RC 资源编译（图标嵌入 exe 所需）
if(WIN32)
  enable_language(RC)
endif()

# 让 MSVC_RUNTIME_LIBRARY 目标属性生效（用于 Windows 静态链接时切换 /MT）
if(POLICY CMP0091)
  cmake_policy(SET CMP0091 NEW)
endif()

# ---------- 外壳源文件 ----------
set(SHELL_SOURCES
    src/main.cpp
    src/MainWindow.cpp
    src/MsgBox.cpp
    src/PasswordDialog.cpp
    src/ProcessCommandExecutor.cpp
    src/CliArgBuilder.cpp
    src/PasswordStrength.cpp
    src/AboutDialogs.cpp
    src/FileEncryptorLocator.cpp
    src/FontBootstrap.cpp
    src/ThemeManager.cpp
    src/ViewSettingsDialog.cpp
    src/CliNotFoundDialog.cpp
    src/TaskHistory.cpp
    src/EtaEstimator.cpp
    src/BatchProgressPanel.cpp
    src/TaskHistoryDialog.cpp
    src/TaskSummaryDialog.cpp)

set(SHELL_HEADERS
    src/MainWindow.h
    src/MsgBox.h
    src/PasswordDialog.h
    src/ICommandExecutor.h
    src/ProcessCommandExecutor.h
    src/CliArgBuilder.h
    src/PasswordStrength.h
    src/AboutDialogs.h
    src/FileEncryptorLocator.h
    src/FontBootstrap.h
    src/ThemeManager.h
    src/ViewSettingsDialog.h
    src/CliNotFoundDialog.h
    src/TaskHistory.h
    src/EtaEstimator.h
    src/BatchProgressPanel.h
    src/TaskHistoryDialog.h
    src/TaskSummaryDialog.h)

# Windows 图标资源（嵌入 exe；Linux/macOS 无 .rc，图标经窗口图标设置）
set(SHELL_RESOURCES )
if(WIN32)
    list(APPEND SHELL_RESOURCES "${CMAKE_CURRENT_SOURCE_DIR}/FileEncryptorGUI.rc")
endif()
# Qt 资源（图标嵌入 exe，供 setWindowIcon 在三端标题栏统一渲染）
list(APPEND SHELL_RESOURCES "${CMAKE_CURRENT_SOURCE_DIR}/icons.qrc")

# 字体资源（仅非 Windows 嵌入）：Linux/macOS 默认字体常不含 CJK 字形致中文方块，运行时 FontBootstrap 从 :/fonts/ 加载内嵌 Noto Sans SC 兜底；Windows 由系统 YaHei 覆盖，不嵌入以控体积。
if(NOT WIN32)
  list(APPEND SHELL_RESOURCES "${CMAKE_CURRENT_SOURCE_DIR}/fonts.qrc")
endif()

add_executable(FileEncryptorGUI WIN32 ${SHELL_SOURCES} ${SHELL_HEADERS} ${SHELL_RESOURCES})
target_link_libraries(FileEncryptorGUI PRIVATE Qt6::Widgets Qt6::Concurrent Qt6::Network)

# Qt 静态构建：Qt6::Widgets 等目标已通过 INTERFACE_LINK_LIBRARIES 把 Qt6Bundled*（Freetype/Harfuzz/Libjpeg/Libpng/Pcre2 等）依赖传递进来，无需手动 link。
# 平台抽象与图像格式插件经 main.cpp 的 Q_IMPORT_PLUGIN 静态导入，运行时无需 Qt6*.dll 与 platforms/qwindows.dll。

# 命名规范：<原名称>-<版本号>-<框架>-<平台>（如 FileEncryptorGUI-2.0.0-Qt-Linux）；版本号取自 PROJECT_VERSION。
get_target_property(FE_GUI_OUTPUT_NAME_BASE FileEncryptorGUI OUTPUT_NAME)
if(NOT FE_GUI_OUTPUT_NAME_BASE)
  set(FE_GUI_OUTPUT_NAME_BASE "FileEncryptorGUI")
endif()
if(WIN32)
  set(FE_GUI_PLATFORM "Windows")
else()
  set(FE_GUI_PLATFORM "Linux")
endif()
# Windows 链接器自动追加 .exe，OUTPUT_NAME 不手动加（避免 ...Windows.exe.exe）。
set(FE_GUI_RENAMED_EXE "${FE_GUI_OUTPUT_NAME_BASE}-${PROJECT_VERSION}-${FE_GUI_FRAMEWORK}-${FE_GUI_PLATFORM}")

# 构建即按规范命名产出（链接器直接写出规范文件名），无需事后复制/重命名。
set_target_properties(FileEncryptorGUI PROPERTIES OUTPUT_NAME "${FE_GUI_RENAMED_EXE}")

# Linux 构建后复制到约定发布目录做副本分发（Windows 不做此步）。发布目录优先落 Windows 可见位置：
# 经 VS+WSL 构建时若 E: 盘以 DrvFS 挂载于 /mnt/e 且含本项目则写入 /mnt/e/...；纯 Linux 原生构建回落到源码树下同源目录。
if(NOT WIN32)
  get_filename_component(FE_GUI_SRC_LEAF "${CMAKE_SOURCE_DIR}" NAME)
  if(EXISTS "/mnt/e/FileEncryptor/${FE_GUI_SRC_LEAF}/CMakeLists.txt")
    set(FE_GUI_STAGE_BASE "/mnt/e/FileEncryptor/${FE_GUI_SRC_LEAF}")
  else()
    set(FE_GUI_STAGE_BASE "${CMAKE_SOURCE_DIR}")
  endif()
  set(FE_GUI_OUT_DIR "${FE_GUI_STAGE_BASE}/out/Ubuntu-26.04/build/linux-release/bin")
  add_custom_command(TARGET FileEncryptorGUI POST_BUILD
    COMMENT "Stage executable -> ${FE_GUI_OUT_DIR}/${FE_GUI_RENAMED_EXE}"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${FE_GUI_OUT_DIR}"
    COMMAND ${CMAKE_COMMAND} -E copy "$<TARGET_FILE:FileEncryptorGUI>"
            "${FE_GUI_OUT_DIR}/${FE_GUI_RENAMED_EXE}"
    VERBATIM)

  # 构建后自动打包 DEB/RPM：VS+WSL、cmake --build 及 IDE --target 都只做 configure+build 不会执行 cpack，故挂 POST_BUILD；同 POST_BUILD 内命令按序执行天然保证复制→打包。包落到 Windows 可见目录。
  set(FE_GUI_PKG_DIR "${FE_GUI_STAGE_BASE}/out/packages")
  set(CPACK_PACKAGE_DIRECTORY "${FE_GUI_PKG_DIR}")
  if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/cmake/package_linux.cmake")
    add_custom_command(TARGET FileEncryptorGUI POST_BUILD
      COMMENT "Packaging DEB/RPM -> ${FE_GUI_PKG_DIR}"
      COMMAND ${CMAKE_COMMAND}
              -DFE_PKG_BUILD_DIR=${CMAKE_BINARY_DIR}
              -DFE_PKG_OUT_DIR=${FE_GUI_PKG_DIR}
              -P "${CMAKE_CURRENT_LIST_DIR}/cmake/package_linux.cmake"
      VERBATIM)
  endif()
endif()

# ---------- PGO（Profile-Guided Optimization，MSVC 两阶段构建） ----------
set(FE_PGO "" CACHE STRING "MSVC PGO 阶段：INSTRUMENT（插桩）/ OPTIMIZE（优化）；留空=关闭")
if(FE_PGO)
  if(NOT MSVC)
    message(WARNING "FE_PGO 仅支持 MSVC，当前编译器不支持，已忽略。")
  elseif(FE_PGO STREQUAL "INSTRUMENT")
    set_target_properties(FileEncryptorGUI PROPERTIES INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
    target_link_options(FileEncryptorGUI PRIVATE /LTCG:PGINSTRUMENT)
    get_filename_component(_fe_gui_pgort_dir "${CMAKE_CXX_COMPILER}" DIRECTORY)
    find_file(FE_GUI_PGORT_DLL NAMES pgort140.dll HINTS "${_fe_gui_pgort_dir}")
    if(FE_GUI_PGORT_DLL)
      add_custom_command(TARGET FileEncryptorGUI POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different "${FE_GUI_PGORT_DLL}"
                "$<TARGET_FILE_DIR:FileEncryptorGUI>/"
        VERBATIM)
    endif()
  elseif(FE_PGO STREQUAL "OPTIMIZE")
    set_target_properties(FileEncryptorGUI PROPERTIES INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
    target_link_options(FileEncryptorGUI PRIVATE /LTCG:PGOPTIMIZE /USEPROFILE)
  else()
    message(FATAL_ERROR "FE_PGO 取值无效：${FE_PGO}（应为 INSTRUMENT 或 OPTIMIZE）")
  endif()
endif()

# 安装 / 打包（DEB/RPM）时放置规范命名的二进制到 /usr/bin
install(TARGETS FileEncryptorGUI RUNTIME DESTINATION bin
        PERMISSIONS OWNER_EXECUTE OWNER_READ
                    GROUP_EXECUTE GROUP_READ
                    WORLD_EXECUTE WORLD_READ)

# ---------- 安装与打包（DEB / RPM） ----------
set(CPACK_PACKAGE_NAME "file-encryptor-gui-qt")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_VENDOR "FileEncryptor")
set(CPACK_PACKAGE_CONTACT "maintainer@example.com")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Cross-platform file encryption GUI (Qt6, static-linked)")
set(CPACK_PACKAGE_DESCRIPTION
      "FileEncryptorGUI is the Qt6 Widgets frontend for FileEncryptor. It is statically linked \
against Qt6, so the installed package requires no external Qt6 runtime. The GUI drives the companion \
FileEncryptorCLI backend via QProcess for the actual encryption/decryption.")
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
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS OFF)
set(CPACK_DEBIAN_PACKAGE_DEPENDS "")

# —— RPM ——
set(CPACK_RPM_PACKAGE_LICENSE "GPLv3")
set(CPACK_RPM_PACKAGE_GROUP "Applications/System")
set(CPACK_RPM_PACKAGE_AUTOREQ OFF)
set(CPACK_RPM_PACKAGE_AUTOREQPROV OFF)

set(CPACK_STRIP_FILES ON)
set(CPACK_PACKAGE_RELEASE "1")

include(CPack)
