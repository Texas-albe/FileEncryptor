cmake_minimum_required(VERSION 3.16)
project(FileEncryptorGUI VERSION 1.4.1 LANGUAGES CXX)

# FileEncryptor GUI - Qt6 跨平台图形界面（独立项目）

# Qt6 来源：
# - Windows：仓库相对路径 ../third_party/smelibs（静态 Qt 分发随项目走）
# - Linux/WSL：/opt/smelibs（Linux 静态 Qt6），不存在时回退系统 Qt6
# 如使用其他位置的静态 Qt，用 -DCMAKE_PREFIX_PATH=... 覆盖。
if(WIN32)
  list(APPEND CMAKE_PREFIX_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../third_party/smelibs")
elseif(EXISTS "/opt/smelibs/lib/cmake/Qt6/Qt6Config.cmake")
  list(APPEND CMAKE_PREFIX_PATH "/opt/smelibs")
endif()

# Concurrent：目录规模统计（递归扫描）放到工作线程，避免大目录扫描卡住界面。
find_package(Qt6 6.2 COMPONENTS Widgets Concurrent REQUIRED)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# 源码含 UTF-8 中文注释与中文字符串，MSVC 默认按系统代码页（如 936/GBK）解析，
# 会触发 C4819，并可能把注释内误解析出的反斜杠当成行拼接、吞掉代码。强制以 UTF-8
# 读取源文件，并让执行字符集也是 UTF-8（保证 tr("中文") 字面量为 UTF-8 字节）。
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

# Qt6 静态链接时的关键设置
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
    src/TaskHistoryDialog.cpp)

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
    src/TaskHistoryDialog.h)

# Windows 图标资源（嵌入 exe；Linux/macOS 无 .rc，图标经窗口图标设置）
set(SHELL_RESOURCES )
if(WIN32)
    list(APPEND SHELL_RESOURCES "${CMAKE_CURRENT_SOURCE_DIR}/FileEncryptorGUI.rc")
endif()
# Qt 资源（图标嵌入 exe，供 setWindowIcon 在三端标题栏统一渲染）
list(APPEND SHELL_RESOURCES "${CMAKE_CURRENT_SOURCE_DIR}/icons.qrc")

# 字体资源（仅非 Windows 嵌入）：Linux/macOS 默认字体常不含 CJK 字形，
# 界面中文会渲染成方块；运行时经 FontBootstrap::loadBundledFont() 从 :/fonts/
# 加载内嵌的 Noto Sans SC 作为兜底。Windows 由系统 YaHei 覆盖（hasCjkGlyph 为真），
# 不嵌入以控制 exe 体积。
if(NOT WIN32)
  list(APPEND SHELL_RESOURCES "${CMAKE_CURRENT_SOURCE_DIR}/fonts.qrc")
endif()

add_executable(FileEncryptorGUI WIN32 ${SHELL_SOURCES} ${SHELL_HEADERS} ${SHELL_RESOURCES})
target_link_libraries(FileEncryptorGUI PRIVATE Qt6::Widgets Qt6::Concurrent)

# Windows CRT 配置：smelibs 提供的 Qt6 静态库是用 /MT（静态 CRT）构建的，
# 本项目也必须用 /MT 才能链接通过（否则 LNK2038 CRT 不匹配）。
# 注：CLI 项目静态链接 libsodium（也是 /MT）；GUI 项目则用 smelibs 的 Qt6 静态库（同样是 /MT），
# 这是两个独立项目各自的合理选择，由依赖库本身决定。
if(MSVC AND WIN32)
  set_target_properties(FileEncryptorGUI PROPERTIES
    MSVC_RUNTIME_LIBRARY "MultiThreaded")
endif()

# Qt 静态构建时，Qt6::Widgets 等目标已通过 INTERFACE_LINK_LIBRARIES 把 Qt6Bundled*
# 依赖（Qt6BundledFreetype / Qt6BundledHarfbuzz / Qt6BundledLibjpeg / Qt6BundledLibpng /
# Qt6BundledPcre2 等）传递进来；无需手动 link。
#
# 插件（平台抽象、图像格式）通过 src/main.cpp 中的 Q_IMPORT_PLUGIN(QWindowsIntegrationPlugin)
# 等声明静态导入，运行时无需 Qt6Core.dll / Qt6Gui.dll / Qt6Widgets.dll / platforms/qwindows.dll
# 等 DLL。

# 命名规范：<原名称>-<版本号>-<平台>  例：FileEncryptorGUI-1.4.1-Linux / -1.4.1-Windows.exe
# 版本号取自 PROJECT_VERSION（随 project(VERSION) 自动同步）。
# 构建即产出规范命名的可执行文件（链接器 OUTPUT_NAME 直接写出，不保留原名）；
# GUI 的 FileEncryptorLocator::getExpectedNames() 已按此命名探测 CLI，无需保留原名。
# - Linux/WSL：POST_BUILD 再复制到发布目录（out/Ubuntu-26.04/...），cpack 打包 DEB/RPM 内含同名二进制。
# - Windows：不做复制步骤，仅构建产出规范命名文件。
# 全程嵌入 CMake，cmake --build 即自动触发，无需外部脚本。
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
set(FE_GUI_RENAMED_EXE "${FE_GUI_OUTPUT_NAME_BASE}-${PROJECT_VERSION}-${FE_GUI_PLATFORM}")

# 构建即按规范命名产出（链接器直接写出规范文件名），无需事后复制/重命名。
set_target_properties(FileEncryptorGUI PROPERTIES OUTPUT_NAME "${FE_GUI_RENAMED_EXE}")

# Linux：构建完成后复制到约定发布目录，文件本身已是规范命名，此处仅做副本分发；
# Windows 不做此复制步骤（用户要求）。发布目录优先落到「Windows 可见」位置：
# 经 VS+WSL 构建时 E: 盘以 DrvFS 挂载于 /mnt/e 且含本项目，则直接写入 /mnt/e/...，
# 使产物出现在 E:\FileEncryptor\...\out\Ubuntu-26.04\...；纯 Linux 原生构建（无
# DrvFS）回落到源码树下的同源目录，不破坏原生流程。
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

  # 构建后自动打包 DEB/RPM：VS+WSL、cmake --build 以及 IDE 的 --target <主目标>
  # 都只做 configure + build，永远不会执行 cpack，故挂在 POST_BUILD 上。
  # 同一 POST_BUILD 内命令按序执行，天然保证「复制 → 打包」的先后。
  # 包直接落到 Windows 可见目录（CPACK_PACKAGE_DIRECTORY 需在 include(CPack) 前设置）。
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
# 与 CLI 同构：在 LTO（/GL + /LTCG）基础上再做基于训练样本的优化。
#   Phase 1（插桩）:
#     cmake -B out/build/pgo-windows -DFE_PGO=INSTRUMENT && cmake --build
#     运行训练负载（pgo/train_gui.ps1）并用 pgosweep 采集 .pgc
#   Phase 2（优化）:
#     cmake -B out/build/pgo-windows -DFE_PGO=OPTIMIZE （同一目录重配）+ 重链
#
# 注意 1：PGO 插桩要求目标以 /GL 编译。GUI 日常 Release 构建不开 IPO（静态 Qt + /GL
#   会让链接时间成倍增加），因此仅在 FE_PGO 打开时才为该目标启用 Release IPO。
# 注意 2：本机的 MSVC PGO 运行时在进程退出时不会自动落盘 .pgc，训练必须用 pgosweep
#   从运行中的进程抓取（详见 pgo/train_gui.ps1 头部说明）。
# 非 MSVC 编译器不支持（GCC 用 -fprofile-generate/-fprofile-use，另行配置）。
set(FE_PGO "" CACHE STRING "MSVC PGO 阶段：INSTRUMENT（插桩）/ OPTIMIZE（优化）；留空=关闭")
if(FE_PGO)
  if(NOT MSVC)
    message(WARNING "FE_PGO 仅支持 MSVC，当前编译器不支持，已忽略。")
  elseif(FE_PGO STREQUAL "INSTRUMENT")
    set_target_properties(FileEncryptorGUI PROPERTIES INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
    target_link_options(FileEncryptorGUI PRIVATE /LTCG:PGINSTRUMENT)
    # 插桩 exe 运行时需要 PGO 运行时库 pgort140.dll，否则进程直接起不来。
    # 从编译器同目录取并复制到 exe 旁；仅插桩阶段需要，OPTIMIZE 后的二进制不依赖。
    get_filename_component(_fe_gui_pgort_dir "${CMAKE_CXX_COMPILER}" DIRECTORY)
    find_file(FE_GUI_PGORT_DLL NAMES pgort140.dll HINTS "${_fe_gui_pgort_dir}")
    if(FE_GUI_PGORT_DLL)
      add_custom_command(TARGET FileEncryptorGUI POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different "${FE_GUI_PGORT_DLL}"
                "$<TARGET_FILE_DIR:FileEncryptorGUI>/"
        VERBATIM)
      message(STATUS "PGO: 已安排复制 PGO 运行时 ${FE_GUI_PGORT_DLL} 到 exe 目录")
    else()
      message(WARNING "PGO: 未找到 pgort140.dll，插桩 exe 可能无法启动")
    endif()
    message(STATUS "PGO: 插桩阶段——构建后运行训练负载并用 pgosweep 采集 .pgc，再以 FE_PGO=OPTIMIZE 重配重链")
  elseif(FE_PGO STREQUAL "OPTIMIZE")
    set_target_properties(FileEncryptorGUI PROPERTIES INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
    target_link_options(FileEncryptorGUI PRIVATE /LTCG:PGOPTIMIZE /USEPROFILE)
    message(STATUS "PGO: 优化阶段——合并训练 .pgc，产出 PGO 优化二进制")
  else()
    message(FATAL_ERROR "FE_PGO 取值无效：${FE_PGO}（应为 INSTRUMENT 或 OPTIMIZE）")
  endif()
endif()

# 安装 / 打包（DEB/RPM）时放置规范命名的二进制到 /usr/bin（包内文件名即规范命名）。
install(TARGETS FileEncryptorGUI RUNTIME DESTINATION bin
        PERMISSIONS OWNER_EXECUTE OWNER_READ
                    GROUP_EXECUTE GROUP_READ
                    WORLD_EXECUTE WORLD_READ)

# ---------- 安装与打包（DEB / RPM） ----------
# GUI 经 Qt6 静态链接（Windows smelibs / Linux 静态 Qt 构建）后，exe 内已内联 Qt6 主库、
# Qt6Bundled* 依赖与嵌入字体，运行时不再依赖 Qt6 *.so / 平台插件 DLL。打包 DEB/RPM 时
# 关闭自动依赖探测，确保包不声明任何系统 Qt 运行时依赖（自包含）。
#
# 注意：本 GUI 通过 QProcess 调用 ../CLI/ 的 FileEncryptorCLI 执行实际加解密。打包后的
# GUI 仅含界面外壳，不捆绑 CLI；终端用户需另行安装 FileEncryptorCLI（或把 CLI 放在 GUI
# 同目录 / 经 FILEENCRYPTOR_EXE 指定）。
set(CPACK_PACKAGE_NAME "file-encryptor-gui")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")   # 与 project(VERSION) 同步
set(CPACK_PACKAGE_VENDOR "FileEncryptor")
set(CPACK_PACKAGE_CONTACT "maintainer@example.com")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Cross-platform file encryption GUI (Qt6, static-linked)")
set(CPACK_PACKAGE_DESCRIPTION
      "FileEncryptorGUI is the Qt6 Widgets frontend for FileEncryptor. It is statically linked \
against Qt6 (main libraries, Qt6Bundled* dependencies and embedded Noto Sans SC font are inlined), \
so the installed package requires no external Qt6 runtime. The GUI drives the companion \
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
# GUI 静态链接 Qt6，无外部 .so 运行时依赖；关闭 shlibdeps 避免把 Qt6 / libsodium 写进 Depends
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS OFF)
set(CPACK_DEBIAN_PACKAGE_DEPENDS "")

# —— RPM ——
set(CPACK_RPM_PACKAGE_LICENSE "GPLv3")
set(CPACK_RPM_PACKAGE_GROUP "Applications/System")
set(CPACK_RPM_PACKAGE_AUTOREQ OFF)
set(CPACK_RPM_PACKAGE_AUTOREQPROV OFF)

# 打包阶段剥离调试符号，减小体积（仅作用于打包副本）
set(CPACK_STRIP_FILES ON)
# RPM 发布号（包文件名中的 -1）
set(CPACK_PACKAGE_RELEASE "1")

include(CPack)
