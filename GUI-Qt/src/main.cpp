// Qt GUI 外壳入口

#include "MainWindow.h"
#include "ThemeManager.h"
#include "FontBootstrap.h"
#include "FileEncryptorLocator.h"
#include "I18n.h"
#include <QApplication>
#include <QStringList>
#include <QStyleFactory>
#include <QIcon>
#include "CliNotFoundDialog.h"
#include "OsHarden.h"
#include <QTimer>
#include <QMessageBox>

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
    // 进程加固
    OsHarden::hardenImageLoadPolicy();   // P1-2 禁远程/低 IL 镜像
    OsHarden::hardenProcessDacl();       // P0-1 收紧进程对象 DACL
    OsHarden::disableCrashDump();        // P1-3 排除出 WER

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
    // 文件关联
    const QStringList cli=QApplication::arguments();
    if(cli.size()>1) w.addFilesFromArgs(cli.mid(1));

    // P2 调试检测
    if (OsHarden::isDebuggerAttached()) {
        QTimer::singleShot(800, []() {
            QMessageBox::warning(
                nullptr,
                QApplication::translate("OsHarden", "检测到调试器"),
                QApplication::translate("OsHarden",
                    "检测到有调试器附加到本程序。若非你本人操作，请立即退出并检查系统安全；程序功能不受影响。"));
        });
    }

    return app.exec();
}
