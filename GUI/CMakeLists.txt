cmake_minimum_required(VERSION 3.16)
project(FileEncryptorGUI VERSION 1.2.1 LANGUAGES CXX)

# FileEncryptor GUI - Qt6 跨平台图形界面（独立项目）

if(WIN32 AND EXISTS "C:/Program Files/smelibs")
  list(APPEND CMAKE_PREFIX_PATH "C:/Program Files/smelibs")
endif()

find_package(Qt6 6.2 COMPONENTS Widgets REQUIRED)

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
    src/CliNotFoundDialog.cpp)

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
    src/CliNotFoundDialog.h)

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
target_link_libraries(FileEncryptorGUI PRIVATE Qt6::Widgets)

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

# 安装
install(TARGETS FileEncryptorGUI RUNTIME DESTINATION bin)

# ---------- 安装与打包（DEB / RPM） ----------
# GUI 经 Qt6 静态链接（Windows smelibs / Linux 静态 Qt 构建）后，exe 内已内联 Qt6 主库、
# Qt6Bundled* 依赖与嵌入字体，运行时不再依赖 Qt6 *.so / 平台插件 DLL。打包 DEB/RPM 时
# 关闭自动依赖探测，确保包不声明任何系统 Qt 运行时依赖（自包含）。
#
# 注意：本 GUI 通过 QProcess 调用 ../CLI/ 的 FileEncryptorCLI 执行实际加解密。打包后的
# GUI 仅含界面外壳，不捆绑 CLI；终端用户需另行安装 FileEncryptorCLI（或把 CLI 放在 GUI
# 同目录 / 经 FILEENCRYPTOR_EXE 指定）。
if(UNIX)
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
endif()
