// FileEncryptorGUI - Qt GUI 外壳入口
// 通过 QProcess 调用 FileEncryptorCLI 命令行程序，不直接链接业务代码。
// 设计目标：跨平台（Win/Linux/macOS），不修改 FileEncryptor 原有代码逻辑。
//
// 静态链接 Qt：本项目要求 GUI exe 零 Qt DLL 依赖。
//   - Qt6 主库（Core/Gui/Widgets）经 find_package(Qt6) 链接到 smelibs 提供的 STATIC IMPORTED 目标；
//   - Qt 平台插件 / 图像格式插件通过下方 Q_IMPORT_PLUGIN 静态导入（编译期链接进 exe）。
//   - 运行时不再需要 Qt6Core.dll / Qt6Gui.dll / Qt6Widgets.dll / platforms/qwindows.dll
//     或 imageformats/qjpeg.dll 等任何 Qt 插件 DLL。
#include "MainWindow.h"
#include "ThemeManager.h"
#include "FontBootstrap.h"
#include <QApplication>
#include <QStyleFactory>
#include <QIcon>

// Qt 插件静态导入（必须在使用任何 Qt 类之前声明，编译期静态初始化时把插件符号链入 exe）。
//
// 仅在「静态 Qt」下导入：Qt 静态构建会定义 QT_STATIC，插件以 .lib/.a 形式提供，
// 可被 Q_IMPORT_PLUGIN 编译期链接；共享 Qt（Linux 发行版默认）下插件是运行时
// 加载的 .so，没有可供引用的插件类，强行导入会编译失败。故用 QT_STATIC 统一守卫，
// 使同一份源码在 Windows 静态 Qt 与 Linux 共享 Qt 下都能构建。
#include <QtPlugin>
#ifdef QT_STATIC
#ifdef Q_OS_WIN
Q_IMPORT_PLUGIN(QWindowsIntegrationPlugin)
#endif
#ifdef Q_OS_LINUX
Q_IMPORT_PLUGIN(QXcbIntegrationPlugin)
#endif
#ifdef Q_OS_MACOS
Q_IMPORT_PLUGIN(QCocoaIntegrationPlugin)
#endif
Q_IMPORT_PLUGIN(QJpegPlugin)
Q_IMPORT_PLUGIN(QGifPlugin)
Q_IMPORT_PLUGIN(QICOPlugin)
#endif // QT_STATIC

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    app.setApplicationName("FileEncryptorGUI");
    app.setApplicationVersion("1.0.0");
    app.setOrganizationName("FileEncryptor");

    // 跨平台观感一致
    QApplication::setStyle(QStyleFactory::create("Fusion"));

    // 字体引导（必须在创建任何窗口之前）：Linux 默认字体常不含中文，会把界面
    // 中文渲染成方块；这里挑一款含中文的字体（必要时用构建期嵌入的 Noto Sans SC）。
    FontBootstrap::initialize();

    // 应用图标：从 Qt 资源（:/icons/app.ico，编译期嵌入 exe）加载，
    // 设置到 QApplication 后所有顶层窗口标题栏/任务栏统一渲染该图标。
    // （Windows 的 .rc 已嵌入同一 ico 作 exe 图标，此处再设可保证 Linux/macOS 也有标题栏图标。）
    app.setWindowIcon(QIcon(QStringLiteral(":/icons/app.ico")));

    // 应用持久化的主题偏好（浅色/深色/跟随系统），必须在创建主窗口前调用，
    // 否则窗口与子控件会以默认浅色调色板构造后再被切换，闪烁且不彻底。
    ThemeManager::initialize(&app);

    MainWindow w;
    w.show();
    return app.exec();
}
