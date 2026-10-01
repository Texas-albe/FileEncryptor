// Qt GUI 外壳入口

#include "MainWindow.h"
#include "ThemeManager.h"
#include "FontBootstrap.h"
#include "FileEncryptorLocator.h"
#include "I18n.h"
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
    app.setApplicationVersion(FileEncryptorLocator::guiVersion());
    app.setOrganizationName("FileEncryptor");

    // 跨平台观感一致
    QApplication::setStyle(QStyleFactory::create("Fusion"));

    // 字体引导
    FontBootstrap::initialize();

    // 应用图标
    app.setWindowIcon(QIcon(QStringLiteral(":/icons/app.ico")));

    // 应用主题偏好
    ThemeManager::initialize(&app);

    // 安装翻译器
    I18n::instance().init();

    MainWindow w;
    w.show();
    return app.exec();
}
