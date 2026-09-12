// FileEncryptorGUI - Qt GUI 外壳入口
// 通过 QProcess 调用 FileEncryptorCLI 命令行程序，不直接链接业务代码。
// 设计目标：跨平台（Win/Linux/macOS），不修改 FileEncryptor 原有代码逻辑。

#include "MainWindow.h"
#include "ThemeManager.h"
#include "FontBootstrap.h"
#include <QApplication>
#include <QStyleFactory>
#include <QIcon>
#include "CliNotFoundDialog.h"
#include <QTimer> 

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
#endif

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    app.setApplicationName("FileEncryptorGUI");
    app.setApplicationVersion("1.2.1");
    app.setOrganizationName("FileEncryptor");

    // 跨平台观感一致
    QApplication::setStyle(QStyleFactory::create("Fusion"));

    // 字体引导
    FontBootstrap::initialize();

    // 应用图标
    app.setWindowIcon(QIcon(QStringLiteral(":/icons/app.ico")));

    // 应用持久化的主题偏好（浅色/深色）
    ThemeManager::initialize(&app);

    MainWindow w;
    w.show();
    return app.exec();
}
