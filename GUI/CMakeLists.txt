cmake_minimum_required(VERSION 3.16)
project(FileEncryptorGUI VERSION 1.0.0 LANGUAGES CXX)

# FileEncryptor GUI - Qt6 跨平台图形界面（独立项目）
# 本项目编译产出 FileEncryptorGUI(.exe)，通过 QProcess 调用 ../CLI/ 项目的 FileEncryptorCLI
# 执行实际加解密；GUI 不链接任何加密代码（Qt6 /MD 与 libsodium /MT 的 CRT 冲突决定的
# 进程级隔离架构）。
#
# 依赖：
#   - Qt 6.x Widgets（**静态链接**，从 CMAKE_PREFIX_PATH 指向的安装目录查找）
#   - 系统库（Windows 平台插件 / 图像格式插件等已在 main.cpp 中通过 Q_IMPORT_PLUGIN 静态导入）
#
# 使用示例（Windows smelibs 静态 Qt）：
#   cmake -S . -B build -G "Visual Studio 18 2026" -A x64 \
#         -DCMAKE_PREFIX_PATH="C:/Program Files/smelibs"
#
# 运行时依赖：FileEncryptorCLI(.exe) 须位于同目录，或通过 FILEENCRYPTOR_EXE 环境变量、
# PATH 提供。

# ---------- Qt 6 ----------
# 跨平台（Windows / Linux / macOS）。需先安装 Qt 6（官方在线安装器或系统包管理器或 vcpkg）。
#   官方安装器：https://www.qt.io/download  选 Qt 6.x + MinGW/MSVC 套件
#   vcpkg:      vcpkg install qtbase
#   Linux:      sudo apt install qt6-base-dev / sudo dnf install qt6-qtbase-devel
#   macOS:      brew install qt
# 配置时让 CMake 能找到 Qt，例如：
#   cmake -S . -B build -DCMAKE_PREFIX_PATH="C:/Program Files/smelibs"
#                      或 "C:/Qt/6.x.x/msvc2022_64"
#                      或 "/usr/lib/qt6"
#                      或 "$(brew --prefix qt)"
# 仅 Windows + 该目录存在时加入静态 Qt 分发（smelibs）的搜索路径。
# Linux 下用系统/发行版 Qt（/usr/lib/x86_64-linux-gnu/cmake/Qt6 等），
# 不加这条 Windows 路径，避免把无关前缀写进 CMAKE_PREFIX_PATH。
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

# Qt6 静态链接时的关键设置：
# Qt6 官方 Windows 预编译包（msvc2022_64 等）默认是 /MD（动态 CRT）构建。
# 但「完全静态链接 Qt」（如本项目要求 exe 零 Qt DLL 依赖）需要使用专门的 Qt 静态构建，
# 其 lib/ 下提供 Qt6Core.lib / Qt6Gui.lib / Qt6Widgets.lib 等静态导入库（STATIC IMPORTED）
# 以及 Qt6Bundled* 捆绑依赖库。本项目的目标是支持这种静态 Qt 构建。
#
# Qt6 静态构建检测：find_package(Qt6) 找到的 Qt6::Core / Qt6::Widgets 应为 STATIC IMPORTED
# 目标（其 Qt6CoreTargets.cmake 中 add_library(Qt6::Core STATIC IMPORTED)），无需额外设置；
# Qt CMake 配置包会自动把 Qt6Bundled* 等静态依赖通过 INTERFACE_LINK_LIBRARIES 传递。
#
# 用户可使用官方 qt-online-installer 安装时勾选「Static Qt Builds」或预编译的 smelibs
# （如 C:/Program Files/smelibs）即可。

# ---------- 外壳源文件 ----------
set(SHELL_SOURCES
    src/main.cpp
    src/MainWindow.cpp
    src/ProcessCommandExecutor.cpp
    src/CliArgBuilder.cpp
    src/PasswordStrength.cpp
    src/AboutDialogs.cpp
    src/FileEncryptorLocator.cpp
    src/FontBootstrap.cpp
    src/ThemeManager.cpp)

set(SHELL_HEADERS
    src/MainWindow.h
    src/ICommandExecutor.h
    src/ProcessCommandExecutor.h
    src/CliArgBuilder.h
    src/PasswordStrength.h
    src/AboutDialogs.h
    src/FileEncryptorLocator.h
    src/FontBootstrap.h
    src/ThemeManager.h)

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
