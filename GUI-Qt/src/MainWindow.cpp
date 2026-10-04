
#include "MainWindow.h"
#include "AboutDialogs.h"
#include "FileEncryptorLocator.h"
#include "FontBootstrap.h"
#include "PasswordStrength.h"
#include "ProcessCommandExecutor.h"
#include "ViewSettingsDialog.h"
#include "PreviewDialog.h"
#include "CliNotFoundDialog.h"
#include "MsgBox.h"
#include "PasswordDialog.h"
#include "TaskHistory.h"
#include "TaskSummaryDialog.h"
#include "TaskHistoryDialog.h"
#include "EtaEstimator.h"
#include "I18n.h"
#include <vector>
#include <cstring>

#include "secure_zero.h"

#include <QMenuBar>
#include <QApplication>
#include <QStatusBar>
#include <QMenu>
#include <QAction>
#include <QActionGroup>
#include <QFileDialog>
#include <QListWidget>
#include <QPlainTextEdit>
#include <QTextBlock>
#include <QLineEdit>
#include <QLabel>
#include <QComboBox>
#include <QRadioButton>
#include <QCheckBox>
#include <QSpinBox>
#include <QDoubleSpinBox>
#include <QProcess>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMessageBox>
#include <QProgressDialog>
#include <QFile>
#include <QDir>
#include <QCoreApplication>
#include <QJsonObject>
#include <QPushButton>
#include <QButtonGroup>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QGridLayout>
#include <QSizePolicy>
#include <QSplitter>
#include <QGroupBox>
#include <QMessageBox>
#include <QCloseEvent>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QMimeData>
#include <QDirIterator>
#include <QDateTime>
#include <QUrl>
#include <QSaveFile>
#include <QRegularExpression>
#include <QCoreApplication>
#include <QFileInfo>
#include <QDir>
#include <QStandardPaths>
#include <QSet>
#include <QTextCharFormat>
#include <QTextCursor>
#include <QTextDocument>
#include <QScrollBar>
#include <QFontDatabase>
#include <QFontMetrics>
#include <QColor>
#include <QToolBar>
#include <QPixmap>
#include <QScreen>
#include <QResizeEvent>
#include <QSettings>
#include <QDesktopServices>
#include <QUrl>
#include <QFile>
#include <QTemporaryFile>
#include <QThread>
#include <QTimer>
#include <QtConcurrent/QtConcurrentRun>
#include <QFutureWatcher>
#include <QElapsedTimer>
#include <atomic>
#include <memory>

namespace {
// 中文一行排得下；英/俄文同一行文字长得多，横排会被列宽裁掉，改逐行显示
bool rowStacksVertically() {
    return I18n::instance().currentLanguage() != QStringLiteral("zh");
}
}

MainWindow::MainWindow(QWidget* parent): QMainWindow(parent) {
    setWindowTitle(QStringLiteral("FileEncryptorGUI %1").arg(
        qApp->applicationVersion().isEmpty() ? FileEncryptorLocator::guiVersion()
        : qApp->applicationVersion()));
    // 默认窗口 16:9，宽度定高（kDefaultWindowWidth 可调）
    const int defW=1351;
    resize(defW,qRound(defW*9.0/16.0));

    m_trayIcon=new QSystemTrayIcon(this);
    m_trayIcon->setIcon(QIcon::fromTheme(QStringLiteral("fileencryptor"),
        QApplication::style()->standardIcon(QStyle::SP_ComputerIcon)));
    m_trayIcon->setToolTip(windowTitle());
    m_trayIcon->show();

    setAcceptDrops(true);

    m_executor=new ProcessCommandExecutor(this);

    if(!FileEncryptorLocator::existsWithVersion(&m_fileEncryptorPath)) {
        QTimer::singleShot(500,this,[this]() {
            showCliNotFoundError(tr("启动时检测"));
            });
    }

    buildMenu();

    auto* centralSplitter=new QSplitter(Qt::Horizontal);

    auto* left=buildLeftPanel();
    auto* center=buildCenterPanel();

    centralSplitter->addWidget(left);
    centralSplitter->addWidget(center);
    centralSplitter->setStretchFactor(0,1);
    centralSplitter->setStretchFactor(1,3);
    centralSplitter->setSizes({300, 900});

    auto* bottom=buildBottomPanel();
    auto* outerSplitter=new QSplitter(Qt::Vertical);
    outerSplitter->addWidget(centralSplitter);
    outerSplitter->addWidget(bottom);
    outerSplitter->setStretchFactor(0,6);
    outerSplitter->setStretchFactor(1,1);
    outerSplitter->setSizes({520, 380});

    setCentralWidget(outerSplitter);
    m_outerSplitter=outerSplitter;

    applyPanelTransparency();
    reflowOptionRows();
    QSettings s(QStringLiteral("FileEncryptor"),QStringLiteral("FileEncryptorGUI"));
    m_bgPath=s.value(QStringLiteral("backgroundImage")).toString();
    applyBackground(m_bgPath, false);
    applyFlagRedTheme();
    if(s.contains(QStringLiteral("geometry")))
        restoreGeometry(s.value(QStringLiteral("geometry")).toByteArray());
    m_statusLabel=new QLabel(this);
    statusBar()->addWidget(m_statusLabel,1);
    m_progressLabel=new QLabel(this);
    m_progressLabel->setTextInteractionFlags(Qt::NoTextInteraction);
    statusBar()->addPermanentWidget(m_progressLabel);
    setStatus(m_fileEncryptorPath.isEmpty()
        ? tr("未找到 FileEncryptor 可执行文件 — 请设置环境变量 FILEENCRYPTOR_EXE 或将其置于本程序同目录")
        : tr("就绪 | FileEncryptor: %1").arg(m_fileEncryptorPath));

    m_pendingTimer=new QTimer(this);
    m_pendingTimer->setSingleShot(true);
    m_pendingTimer->setInterval(180);
    connect(m_pendingTimer,&QTimer::timeout,this,&MainWindow::startPendingScan);
    m_scanWatcher=new QFutureWatcher<ScanResult>(this);
    connect(m_scanWatcher,&QFutureWatcher<ScanResult>::finished,
        this,&MainWindow::onPendingScanFinished);
    m_frameTimer=new QTimer(this);
    m_frameTimer->setSingleShot(true);
    m_frameTimer->setInterval(120);
    connect(m_frameTimer,&QTimer::timeout,this,&MainWindow::flushPendingFrame);

    connectSignals();
    probeZstdSupport();
    updateSm4Visibility();
    updateAsymVisibility();
    refreshCommandPreview();
    updateProgressLabel();
    recomputePending();
}

MainWindow::~MainWindow() {
    if(m_pendingTimer) m_pendingTimer->stop();
    if(m_scanCancel) m_scanCancel->store(true,std::memory_order_relaxed);
    if(m_scanWatcher&&m_scanWatcher->isRunning()) m_scanWatcher->waitForFinished();
}

void MainWindow::closeEvent(QCloseEvent* e) {
    if(m_executor&&m_executor->isRunning()) {
        if(!MsgBox::confirm(this,tr("确认退出"),
            tr("有命令正在运行，退出将终止它。确定退出？"))) {
            e->ignore();
            return;
        }
        m_executor->cancel();
    }
    if(!m_recipientTempFile.isEmpty()) {
        QFile::remove(m_recipientTempFile);
        m_recipientTempFile.clear();
    }
    if(!m_rewrapTempKey.isEmpty()) {
        QFile::remove(m_rewrapTempKey);
        m_rewrapTempKey.clear();
    }
    // 水印私钥：中途退出时 finished() 未必跑完，这里同步兜底
    CliArgBuilder::cleanupWatermarkTemp();
    // 统计 JSON 同理（finishTaskRecord 没跑到就要删）
    if(!m_statsFile.isEmpty()) {
        QFile::remove(m_statsFile);
        m_statsFile.clear();
    }
    QSettings(QStringLiteral("FileEncryptor"),QStringLiteral("FileEncryptorGUI"))
        .setValue(QStringLiteral("geometry"),saveGeometry());
    e->accept();
}

// 顶栏菜单
void MainWindow::buildMenu() {
    m_menuBar=menuBar();


    // 菜单按功能顺序排列
    auto* editMenu=m_menuBar->addMenu(tr("编辑(&E)"));
    auto* actEditConfig=editMenu->addAction(tr("编辑 YAML 配置..."));
    connect(actEditConfig,&QAction::triggered,this,&MainWindow::onEditConfig);

    auto* viewMenu=m_menuBar->addMenu(tr("视图(&V)"));
    auto* actViewSettings=viewMenu->addAction(tr("视图设置..."));
    connect(actViewSettings,&QAction::triggered,this,&MainWindow::onViewSettings);
    viewMenu->addSeparator();

    // 主题：浅色 / 深色 / 跟随系统，与 WinUI 的「视图」菜单一致
    auto* themeMenu=viewMenu->addMenu(tr("主题"));
    m_themeGroup=new QActionGroup(themeMenu);
    m_themeGroup->setExclusive(true);
    const struct { QAction** act; ThemeManager::Theme theme; const char* label; } kThemeItems[] = {
        {&m_actThemeLight,   ThemeManager::Theme::Light, QT_TR_NOOP("浅色")},
        {&m_actThemeDark,    ThemeManager::Theme::Dark,  QT_TR_NOOP("深色")},
        {&m_actThemeSystem,  ThemeManager::Theme::System, QT_TR_NOOP("跟随系统")},
    };
    for(const auto& it : kThemeItems) {
        auto* a=themeMenu->addAction(tr(it.label));
        a->setCheckable(true);
        a->setData(static_cast<int>(it.theme));
        a->setChecked(ThemeManager::chosenTheme()==it.theme);
        m_themeGroup->addAction(a);
        connect(a,&QAction::triggered,this,&MainWindow::onThemeActionTriggered);
        *it.act=a;
    }

    auto* toolsMenu=m_menuBar->addMenu(tr("工具(&T)"));
    auto* actTaskHistory=toolsMenu->addAction(tr("任务历史..."));
    connect(actTaskHistory,&QAction::triggered,this,&MainWindow::onOpenTaskHistory);
    auto* actRetryCli=toolsMenu->addAction(tr("重新检测 CLI 程序"));
    connect(actRetryCli,&QAction::triggered,this,&MainWindow::onRetryCliDetection);
    toolsMenu->addSeparator();

    auto* langMenu=toolsMenu->addMenu(tr("语言(&L)"));
    auto* langGroup=new QActionGroup(langMenu);
    auto addLang=[&](const QString& label,const QString& id) {
        auto* a=langMenu->addAction(label);
        a->setCheckable(true);
        a->setChecked(I18n::instance().currentLanguage()==id);
        langGroup->addAction(a);
        connect(a,&QAction::triggered,this,[this,id] {
            I18n::instance().changeLanguage(id,this);
            // 祝福语是运行时拼的（tr() 不含年龄占位），语言切换后要重刷
            applyBirthdayStyle();
            // 文案长度变了，横排/竖排的判断要跟着重算
            reflowOptionRows();
        });
    };
    addLang(QStringLiteral("简体中文"),QStringLiteral("zh"));
    addLang(QStringLiteral("English"),QStringLiteral("en"));
    addLang(QStringLiteral("Русский"),QStringLiteral("ru"));

    auto* aboutMenu=m_menuBar->addMenu(tr("关于(&A)"));

    auto* actCheckUpdate=aboutMenu->addAction(tr("检查更新..."));
    connect(actCheckUpdate,&QAction::triggered,this,&MainWindow::onCheckForUpdate);

    auto* actCredits=aboutMenu->addAction(tr("鸣谢..."));
    connect(actCredits,&QAction::triggered,this,[this]{
        CreditsDialog dlg(this);
        dlg.exec();
        });

    auto* actReadme=aboutMenu->addAction(tr("README 摘要..."));
    connect(actReadme,&QAction::triggered,this,[this]{
        ReadmeDialog dlg(this);
        dlg.exec();
        });

    aboutMenu->addSeparator();
    auto* actAboutQt=aboutMenu->addAction(tr("关于 Qt..."));
    connect(actAboutQt,&QAction::triggered,qApp,&QApplication::aboutQt);
}

// 自动更新
QString MainWindow::locateUpdater() const {
    const QString dir = QCoreApplication::applicationDirPath();
    const QStringList cands = {
        dir + QStringLiteral("/updater/Updater.exe"),
        dir + QStringLiteral("/Updater.exe"),
    };
    for (const QString& c : cands)
        if (QFile::exists(c)) return c;
    const QStringList paths = qEnvironmentVariable("PATH").split(QDir::listSeparator(), Qt::SkipEmptyParts);
    for (const QString& p : paths) {
        const QString c = QDir(p).filePath(QStringLiteral("Updater.exe"));
        if (QFile::exists(c)) return c;
    }
    return {};
}

// 更新器报回的 error 码 → 中文说明（与 Updater/src/updater.cpp 的 error 字段对应）。
// 文案直接以字面量写进 translate，便于 lupdate 收录译文。
static QString updaterErrorText(const QString& code) {
    auto t = [](const char* s) { return QCoreApplication::translate("MainWindow", s); };
    if (code == QStringLiteral("network_unreachable")) return QCoreApplication::translate("MainWindow", "网络连接不可用，请检查网络后重试。");
    if (code == QStringLiteral("dns_failed")) return QCoreApplication::translate("MainWindow", "无法解析服务器地址，请检查网络后重试。");
    if (code == QStringLiteral("timeout")) return QCoreApplication::translate("MainWindow", "检查更新超时，请稍后再试。");
    if (code == QStringLiteral("tls_verify_failed")) return QCoreApplication::translate("MainWindow", "安全证书校验失败，可能是网络环境拦截了更新服务。");
    if (code == QStringLiteral("rate_limited")) return QCoreApplication::translate("MainWindow", "检查过于频繁，请稍后再试。");
    if (code == QStringLiteral("release_not_found")) return QCoreApplication::translate("MainWindow", "服务端未找到可更新的版本。");
    if (code == QStringLiteral("host_not_allowed")) return QCoreApplication::translate("MainWindow", "更新服务地址不可达。");
    return code;
}

void MainWindow::onCheckForUpdate() {
    const QString updater = locateUpdater();
    if (updater.isEmpty()) {
        QMessageBox::warning(this, tr("检查更新"),
            tr("未找到更新器 (Updater.exe)。请确认程序安装完整，或手动前往 GitHub 获取新版本。"));
        return;
    }
    auto* dlg = new QProgressDialog(tr("正在检查更新..."), tr("取消"), 0, 0, this);
    dlg->setWindowTitle(tr("检查更新"));
    dlg->setWindowModality(Qt::WindowModal);
    dlg->show();

    auto* proc = new QProcess(this);
    const QString platform = []() {
#ifdef Q_OS_WIN
        return QStringLiteral("windows");
#else
        return QStringLiteral("linux");
#endif
    }();
    const QStringList args = {
        QStringLiteral("--check"),
        QStringLiteral("--current"), FileEncryptorLocator::guiVersion(),
        QStringLiteral("--type"), QStringLiteral("qt"),
        QStringLiteral("--platform"), platform,
    };
    connect(proc, &QProcess::finished, this, [this, dlg, proc, updater](int, QProcess::ExitStatus) {
        dlg->close(); dlg->deleteLater();
        const QByteArray out = proc->readAllStandardOutput();
        proc->deleteLater();
        handleCheckResult(out, updater);
    });
    // 更新器起不来（缺 dll / 被杀软拦）时 finished 不会来，只连 finished 会让进度框一直转
    connect(proc, &QProcess::errorOccurred, this, [this, dlg, proc](QProcess::ProcessError) {
        dlg->close(); dlg->deleteLater();
        proc->deleteLater();
        QMessageBox::warning(this, tr("检查更新"),
            tr("无法启动更新器，请确认程序安装完整。"));
    });
    connect(dlg, &QProgressDialog::canceled, proc, [proc] { proc->kill(); });
    QTimer::singleShot(60000, this, [proc, dlg] {
        if (proc->state() != QProcess::NotRunning) proc->kill();
        dlg->close(); dlg->deleteLater();
    });
    proc->start(updater, args);
}

void MainWindow::handleCheckResult(const QByteArray& out, const QString& updater) {
    QJsonParseError err;
    const QJsonDocument doc = QJsonDocument::fromJson(out, &err);
    if (doc.isNull()) {
        const QString raw = QString::fromUtf8(out).trimmed();
        if (raw.isEmpty())
            QMessageBox::warning(this, tr("检查更新"),
                tr("检查更新未返回结果（可能已超时）。请稍后再试。"));
        else
            QMessageBox::warning(this, tr("检查更新"),
                tr("无法解析更新器输出：%1\n原始输出：%2").arg(err.errorString(), raw));
        return;
    }
    const QJsonObject o = doc.object();
    if (!o.value(QStringLiteral("ok")).toBool()) {
        // 把更新器给的具体原因（网络/超时/证书/限流）显示出来，别只丢一个错误码
        const QString code = o.value(QStringLiteral("error")).toString();
        const QString detail = o.value(QStringLiteral("detail")).toString();
        QMessageBox::warning(this, tr("检查更新"),
            tr("检查失败：%1%2").arg(updaterErrorText(code),
                detail.isEmpty() ? QString() : QStringLiteral("\n") + detail));
        return;
    }
    if (o.value(QStringLiteral("has_update")).toBool(false)) {
        const QString latest = o.value(QStringLiteral("latest_version")).toString();
        const QString notes = o.value(QStringLiteral("notes")).toString();
        QMessageBox box(this);
        box.setWindowTitle(tr("发现新版本"));
        box.setText(tr("发现新版本 %1。").arg(latest));
        box.setInformativeText(notes + QStringLiteral("\n\n") + tr("是否现在下载并安装？"));
        box.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
        box.setDefaultButton(QMessageBox::Yes);
        if (box.exec() == QMessageBox::Yes)
            doUpdaterUpdate(updater,
                o.value(QStringLiteral("download_url")).toString(),
                o.value(QStringLiteral("sha256")).toString(),
                o.value(QStringLiteral("sig_url")).toString(),
                o.value(QStringLiteral("size")).toVariant().toLongLong());
    } else {
        QMessageBox::information(this, tr("检查更新"),
            tr("已是最新版本（%1）。").arg(o.value(QStringLiteral("current_version")).toString()));
    }
}

void MainWindow::doUpdaterUpdate(const QString& updater, const QString& url,
                                 const QString& sha, const QString& sigUrl, long long size) {
    if (url.isEmpty()) {
        QMessageBox::warning(this, tr("更新"),
            tr("未找到适用于本平台的安装包，请前往 GitHub 手动下载。"));
        return;
    }
    const QString staging = QCoreApplication::applicationDirPath()
                            + QStringLiteral("/update_staging");
    QDir().mkpath(staging);

    auto* dlg = new QProgressDialog(tr("正在下载并更新..."), tr("取消"), 0, 100, this);
    dlg->setWindowTitle(tr("更新"));
    dlg->setWindowModality(Qt::WindowModal);
    dlg->show();

    auto* proc = new QProcess(this);
    QStringList args = {
        QStringLiteral("--update"),
        QStringLiteral("--url"), url,
        QStringLiteral("--install-dir"), staging,
    };
    if (!sha.isEmpty()) { args << QStringLiteral("--sha256") << sha; }
    if (!sigUrl.isEmpty()) { args << QStringLiteral("--sig-url") << sigUrl; }
    if (size > 0) { args << QStringLiteral("--size") << QString::number(size); }

    connect(proc, &QProcess::readyReadStandardOutput, this, [dlg, proc] {
        while (proc->canReadLine()) {
            const QJsonDocument d = QJsonDocument::fromJson(proc->readLine().trimmed());
            if (d.isObject()) {
                const int p = d.object().value(QStringLiteral("progress")).toInt(-1);
                if (p >= 0) dlg->setValue(p);
            }
        }
    });
    connect(proc, &QProcess::finished, this, [this, dlg, proc, staging, url] {
        dlg->close(); dlg->deleteLater();
        const QByteArray out = proc->readAllStandardOutput();
        proc->deleteLater();
        if (!out.contains("\"stage\":\"done\"") && out.isEmpty()) {
            QMessageBox::warning(this, tr("更新"), tr("更新器未返回任何结果（可能已超时）。"));
            return;
        }
        const bool done = out.contains("\"stage\":\"done\"");
        if (done) {
            const QString name = url.mid(url.lastIndexOf(QLatin1Char('/')) + 1);
            QMessageBox::information(this, tr("更新"),
                tr("更新包已下载并校验完成，存放于：\n%1\n\n请关闭本程序后以该文件替换当前程序并重新启动。")
                    .arg(staging + QLatin1Char('/') + name));
        } else {
            QMessageBox::warning(this, tr("更新"),
                tr("更新失败（详见输出）。可前往 GitHub 手动下载。"));
        }
    });
    connect(proc, &QProcess::errorOccurred, this, [this, dlg, proc] {
        dlg->close(); dlg->deleteLater();
        proc->deleteLater();
        QMessageBox::warning(this, tr("更新"), tr("无法启动更新器，请确认程序安装完整。"));
    });
    connect(dlg, &QProgressDialog::canceled, proc, [proc] { proc->kill(); });
    QTimer::singleShot(300000, this, [proc, dlg] {
        if (proc->state() != QProcess::NotRunning) proc->kill();
        dlg->close(); dlg->deleteLater();
    });
    proc->start(updater, args);
}

// 主题菜单：勾选态跟随 ThemeManager 当前选择
void MainWindow::onThemeActionTriggered() {
    auto* a=qobject_cast<QAction*>(sender());
    if(!a) return;
    ThemeManager::setTheme(static_cast<ThemeManager::Theme>(a->data().toInt()));
    applyButtonStyles();
    applyPanelTransparency();
    applyFlagRedTheme();
    refreshCommandPreview();
}

void MainWindow::onThemeDarkChanged(bool ) {
    const auto cur=ThemeManager::chosenTheme();
    for(QAction* a : m_themeGroup->actions()) {
        const bool on=a->data().toInt()==static_cast<int>(cur);
        if(a->isChecked()!=on) {
            a->setChecked(on);
            break;  // exclusive group：设一个即取消其余
        }
    }
    applyButtonStyles();
    applyPanelTransparency();
    applyFlagRedTheme();
}

// 底色随配色
void MainWindow::applyFlagRedTheme() {
    const auto& r=ThemeManager::ui();
    // 不能用 setStyleSheet 设窗口底色：Qt 给顶层窗口设样式表会重置整棵子控件树的
    // 调色板，输入框/列表会退回系统默认（浅色主题下就成了黑底配白控件）。
    // 改走 QPalette::Window 这一条正路。
    QPalette p=palette();
    p.setColor(QPalette::Window, QColor(r.window));
    p.setColor(QPalette::WindowText, QColor(r.text));
    p.setColor(QPalette::Highlight, QColor(r.highlight));
    p.setColor(QPalette::HighlightedText, Qt::white);
    setPalette(p);
    applyButtonStyles();
    applyBirthdayStyle();
}

// 祝福语固定国旗红，不随深浅档变化（跟 WinUI 侧一致）
void MainWindow::applyBirthdayStyle() {
    if(!m_birthdayLabel) return;
    const bool active=ThemeManager::isNationalDay();
    m_birthdayLabel->setVisible(active);
    if(!active) return;
    m_birthdayLabel->setText(ThemeManager::birthdayMessage());
    m_birthdayLabel->setStyleSheet(QStringLiteral("QLabel{color:%1;font-weight:600;}")
        .arg(QLatin1String(ThemeManager::chinaRedHex())));
}

// 预览解密：新开窗口显示明文前缀，不写出任何文件
void MainWindow::onPreviewClicked() {
    QListWidgetItem* cur = m_fileList ? m_fileList->currentItem() : nullptr;
    if (!cur) {
        MsgBox::warn(this, tr("未选择文件"),
            tr("请先在列表里选中一个要预览的密文文件。"));
        return;
    }
    openPreviewFor(cur->text());
}

void MainWindow::openPreviewFor(const QString& path) {
    if (path.isEmpty() || !QFileInfo::exists(path)) {
        MsgBox::warn(this, tr("文件不存在"), tr("找不到该文件：\n%1").arg(path));
        return;
    }
    const int act = m_actionGroup->checkedId();
    // 预览是解密行为：加密/密钥动作下没有预览语义
    if (act != static_cast<int>(CryptoAction::Decrypt)
        && act != static_cast<int>(CryptoAction::BatchDecrypt)) {
        MsgBox::warn(this, tr("无法预览"),
            tr("预览只对解密动作有效，请先把动作切到「解密」或「批量解密」。"));
        return;
    }

    QByteArray pw;
    // 与 updateAsymVisibility 同一判据：解密时填了私钥文件即走非对称，不需要口令
    const bool asymDecrypt = (act == static_cast<int>(CryptoAction::Decrypt))
        && m_identityEdit && !m_identityEdit->text().trimmed().isEmpty();
    if (asymDecrypt) {
        // 非对称解密靠私钥文件（CLI 自行识别），不问口令
    } else {
        PasswordDialog dlg(this);
        dlg.setPurpose(tr("解密口令（用于预览）"));
        dlg.setRequireConfirm(false);
        if (dlg.exec() != QDialog::Accepted) return;
        const std::vector<unsigned char> v = dlg.takePassword();
        if (v.empty()) return;
        pw = QByteArray(reinterpret_cast<const char*>(v.data()),
                        static_cast<int>(v.size()));
    }

    if (!m_previewDlg) {
        m_previewDlg = new PreviewDialog(this);
        m_previewDlg->setAttribute(Qt::WA_DeleteOnClose, false);
        connect(m_previewDlg, &PreviewDialog::nextRequested, this, [this] {
            if (!m_fileList) return;
            QListWidgetItem* it = m_fileList->currentItem();
            if (!it) return;
            const int row = m_fileList->row(it);
            if (row + 1 < m_fileList->count())
                m_fileList->setCurrentRow(row + 1);
            if (m_fileList->currentItem())
                openPreviewFor(m_fileList->currentItem()->text());
        });
    }

    PreviewRequest req;
    req.programPath = m_fileEncryptorPath;
    req.filePath = path;
    req.password = pw;
    req.maxBytes = 4096;
    m_previewDlg->setFileName(QFileInfo(path).fileName());
    m_previewDlg->start(req);
    m_previewDlg->show();
    m_previewDlg->raise();
    m_previewDlg->activateWindow();
}

void MainWindow::onViewSettings() {
    ViewSettingsDialog dlg(m_bgPath,this);
    if(dlg.exec()!=QDialog::Accepted) return;

    const QString path=dlg.selectedImagePath();
    if(path.isEmpty()) {
        applyBackground(QString(), false);
        return;
    }
    const QPixmap pm(path);
    if(pm.isNull()) {
        MsgBox::warn(this,tr("背景图无效"),
            tr("无法加载该图片，请选择有效的 PNG/JPG 等图片文件。"));
        return;
    }
    applyBackground(path, true);
}

// 背景图应用
void MainWindow::applyBackground(const QString& path,bool resizeToRatio) {
    if(path.isEmpty()||!QFileInfo(path).isFile()) {
        m_bgPath.clear();
        m_bgSource=QPixmap();
        if(m_bgLabel) m_bgLabel->hide();
        QSettings(QStringLiteral("FileEncryptor"),QStringLiteral("FileEncryptorGUI"))
            .setValue(QStringLiteral("backgroundImage"),QString());
        return;
    }

    const QPixmap pm(path);
    if(pm.isNull()) return;

    m_bgPath=path;
    m_bgSource=pm;

    if(!m_bgLabel) {
        m_bgLabel=new QLabel(this);
        m_bgLabel->setScaledContents(false);
        m_bgLabel->setAttribute(Qt::WA_TransparentForMouseEvents);
        m_bgLabel->lower();
    }
    m_bgLabel->show();
    resizeBgLabel();

    QSettings(QStringLiteral("FileEncryptor"),QStringLiteral("FileEncryptorGUI"))
        .setValue(QStringLiteral("backgroundImage"),path);

    if(resizeToRatio) {
        const qreal ar=static_cast<qreal>(pm.width())/static_cast<qreal>(pm.height());
        QScreen* scr=screen();
        const QRect avail=scr ? scr->availableGeometry() : QRect(0,0,1280,800);
        int h=qBound(480,pm.height(),900);
        int w=qRound(h*ar);
        const int maxW=qRound(avail.width()*0.9);
        const int maxH=qRound(avail.height()*0.9);
        if(w>maxW) { w=maxW; h=qRound(w/ar); }
        if(h>maxH) { h=maxH; w=qRound(h*ar); }
        resize(w,h);
    }
}

void MainWindow::resizeBgLabel() {
    if(!m_bgLabel) return;
    m_bgLabel->setGeometry(rect());
    if(!m_bgSource.isNull()) {
        m_bgLabel->setPixmap(m_bgSource.scaled(
            size(),Qt::KeepAspectRatioByExpanding,Qt::SmoothTransformation));
    }
}

void MainWindow::applyPanelTransparency() {
    const QString transparent=QStringLiteral("background:transparent;");
    const auto& r=ThemeManager::ui();
    const QString chinaRed=QLatin1String(r.highlight);

    // 区块底色随配色
    const QString panelStyle=QStringLiteral("background:%1;border-radius:6px;")
        .arg(QLatin1String(r.panelRgba));
    for(QWidget* p:{m_leftPanel, m_centerPanel, m_bottomPanel}) {
        if(!p) continue;
        p->setAttribute(Qt::WA_TranslucentBackground);
        p->setAutoFillBackground(false);
        p->setStyleSheet(panelStyle);
    }

    const QString fieldBg=QLatin1String(r.field);
    const QString fieldFg=QLatin1String(r.text);
    const QString fieldBor=QLatin1String(r.border);
    const QString fieldSel=chinaRed;
    const QString altBg=QLatin1String(r.alt);
    const QString hoverBg=QLatin1String(r.ctrlHover);
    const QString indBg=QLatin1String(r.indicator);
    const QString indBor=QLatin1String(r.indicatorBorder);
    const QString ctrlBg=QLatin1String(r.ctrl);
    const QString ctrlFg=QLatin1String(r.text);
    const QString ctrlBor=QLatin1String(r.border);
    const QString ctrlHover=QLatin1String(r.ctrlHover);

    if(m_fileList) {
        m_fileList->setStyleSheet(QStringLiteral(
            "QListWidget{background:%1;color:%2;border:1px solid %3;"
            "border-radius:3px;outline:0;}"
            "QListWidget::item{padding:2px 4px;}"
            "QListWidget::item:alternate{background:%4;}"
            "QListWidget::item:selected{background:%5;color:#FFFFFF;}"
            "QListWidget::item:hover{background:%6;}"
            "QListWidget::indicator{width:14px;height:14px;border:1px solid %7;"
            "border-radius:2px;background:%8;}"
            "QListWidget::indicator:checked{background:%5;border:1px solid %7;}"
        ).arg(ctrlBg,ctrlFg,ctrlBor,altBg,fieldSel,hoverBg,indBor,indBg));
    }

    const QString fieldCss=QStringLiteral(
        "background:%1;color:%2;border:1px solid %3;border-radius:3px;padding:2px 4px;"
        "selection-background-color:%4;selection-color:#FFFFFF;")
        .arg(fieldBg,fieldFg,fieldBor,fieldSel);
    // 全部单行输入框共用同一套外观（含后加的水印私钥与密钥包装两处）
    for(QLineEdit* e:{m_outDirEdit, m_keyfileEdit,
                       m_recipientEdit, m_identityEdit,
                       m_wmKeyEdit, m_wrapFileEdit, m_wrapOutEdit}) {
        if(e) e->setStyleSheet(fieldCss);
    }
    if(m_outputView) {
        const QString sbHandle=QLatin1String(r.scrollHandle);
        const QString sbHover=QLatin1String(r.scrollHover);
        m_outputView->setStyleSheet(QStringLiteral(
            "QPlainTextEdit{%1}"
            "QScrollBar:vertical{background:%5;width:12px;margin:0;}"
            "QScrollBar::handle:vertical{background:%6;min-height:24px;"
            "border-radius:5px;}"
            "QScrollBar::handle:vertical:hover{background:%7;}"
            "QScrollBar:horizontal{background:%5;height:12px;margin:0;}"
            "QScrollBar::handle:horizontal{background:%6;min-width:24px;"
            "border-radius:5px;}"
            "QScrollBar::handle:horizontal:hover{background:%7;}"
            "QScrollBar::add-line,QScrollBar::sub-line{width:0;height:0;}"
            "QScrollBar::add-page,QScrollBar::sub-page{background:transparent;}"
        ).arg(fieldCss,altBg,sbHandle,sbHover));
    }

    const QString optionStyle=QStringLiteral(
        "QCheckBox,QRadioButton{background:%1;color:%2;"
        "border:1px solid %3;border-radius:3px;padding:4px 6px;spacing:6px;}"
        "QCheckBox::indicator,QRadioButton::indicator{width:14px;height:14px;"
        "border:1px solid %4;background:%5;}"
        "QCheckBox::indicator{border-radius:2px;}"
        "QRadioButton::indicator{border-radius:7px;}"
        "QCheckBox::indicator:hover,QRadioButton::indicator:hover{border:1px solid %7;}"
        "QCheckBox::indicator:checked{background:%6;border:1px solid %4;}"
        "QRadioButton::indicator:checked{background:%6;border:1px solid %4;}"
    ).arg(fieldBg,fieldFg,fieldBor,indBor,indBg,fieldSel,chinaRed);
    for(QWidget* c:{static_cast<QWidget*>(m_chkForce),
                       static_cast<QWidget*>(m_chkPack),
                       static_cast<QWidget*>(m_chkSha256),
                       static_cast<QWidget*>(m_chkSplit),
                       static_cast<QWidget*>(m_chkCompress),
                       static_cast<QWidget*>(m_chkPqc),
                       static_cast<QWidget*>(m_chkX448),
                       static_cast<QWidget*>(m_chkWatermark),
                       static_cast<QWidget*>(m_rbEncrypt), static_cast<QWidget*>(m_rbDecrypt),
                       static_cast<QWidget*>(m_rbBatchEncrypt), static_cast<QWidget*>(m_rbBatchDecrypt),
                       static_cast<QWidget*>(m_rbKeyGen), static_cast<QWidget*>(m_rbDerive),
                       static_cast<QWidget*>(m_rbPubKey),
                       static_cast<QWidget*>(m_rbWrapKey), static_cast<QWidget*>(m_rbUnwrapKey)}) {
        if(c) c->setStyleSheet(optionStyle);
    }

    const QString comboStyle=QStringLiteral(
        "QComboBox{background:%1;color:%2;border:1px solid %3;border-radius:3px;padding:2px 6px;min-width:60px;}"
        "QComboBox::drop-down{border:none;width:18px;}"
        "QComboBox::down-arrow{image:none;width:0;height:0;border-left:4px solid transparent;"
        "border-right:4px solid transparent;border-top:5px solid %2;}"
        "QComboBox QAbstractItemView{background:%1;color:%2;border:1px solid %3;"
        "selection-background-color:%4;selection-color:#FFFFFF;outline:0;}"
    ).arg(ctrlBg,ctrlFg,ctrlBor,fieldSel);
    for(QComboBox* cb:{m_modeCombo, m_sourceCombo, m_fileCipherCombo, m_splitUnit,
                           m_wrapAlgCombo}) {
        if(cb) cb->setStyleSheet(comboStyle);
    }

    const QString spinStyle=QStringLiteral(
        "QSpinBox{%1}"
        "QSpinBox:disabled{background:%2;color:%4;border:1px solid %3;}"
    ).arg(fieldCss,altBg,fieldBor,QLatin1String(r.placeholder));
    if(m_compressLevel) m_compressLevel->setStyleSheet(spinStyle);
    const QString btnStyle=QStringLiteral(
        "QPushButton{background:%1;color:%2;border:1px solid %3;border-radius:3px;padding:4px 10px;}"
        "QPushButton:hover{background:%4;}"
        "QPushButton:disabled{background:%1;color:%5;}"
    ).arg(ctrlBg,ctrlFg,ctrlBor,ctrlHover,QLatin1String(r.placeholder));
    // 全部普通按钮共用同一套外观（含后加的「密钥轮换」「水印私钥浏览」）
    for(QPushButton* b:{m_btnAddFiles, m_btnAddDir, m_btnClearFiles,
                           m_btnOutDirBrowse, m_btnKeyfileBrowse,
                           m_btnRecipientBrowse, m_btnIdentityBrowse, m_btnPreview,
                           m_btnTaskHistory, m_btnRewrap, m_btnWmKeyBrowse,
                           m_btnWrapFileBrowse, m_btnWrapOutBrowse}) {
        if(b) b->setStyleSheet(btnStyle);
    }

    for(QWidget* s:{m_outerSplitter}) {
        if(!s) continue;
        s->setAttribute(Qt::WA_TranslucentBackground);
        s->setAutoFillBackground(false);
        s->setStyleSheet(transparent);
    }
}

// 英/俄文文案长，但窗口够宽时横排更好看：实测所有项的 widthHint 之和，
// 塞得进当前行宽就保持横排，塞不进才逐行显示（原先只看语言，够宽也是竖排）。
void MainWindow::reflowOptionRows() {
    if(m_optionRows.isEmpty()) return;
    const bool zh=!rowStacksVertically();
    QWidget* host=m_optionRows.first()->parentWidget();
    const int avail=host ? host->width() : 0;
    // 窗口尚未布局时宽度未知（常为 0）：此时不做决定，保持默认横排，
    // 交给 showEvent/resizeEvent 在几何确定后再校准，避免一上来就强制竖排
    if(avail<=0) return;
    for(int r=0;r<m_optionRows.size();++r) {
        QBoxLayout* row=m_optionRows[r];
        int need=0;
        for(int i=0;i<row->count();++i) {
            QLayoutItem* it=row->itemAt(i);
            if(!it) continue;
            // 弹簧/stretch 只是占位，不计入实际需要的宽度
            if(dynamic_cast<QSpacerItem*>(it)) continue;
            need+=it->sizeHint().width()+row->spacing();
        }
        // 中文恒定横排；英/俄文仅当实测总宽塞不进当前行宽时才竖排
        const bool stack=!zh && need>avail;
        row->setDirection(stack ? QBoxLayout::TopToBottom : QBoxLayout::LeftToRight);
    }
}

void MainWindow::showEvent(QShowEvent* e) {
    QMainWindow::showEvent(e);
    // 首帧几何已确定，按真实宽度校准英/俄文选项行方向
    reflowOptionRows();
}

void MainWindow::resizeEvent(QResizeEvent* e) {
    QMainWindow::resizeEvent(e);
    resizeBgLabel();
    // 要在布局重算之后：拉宽窗口时英/俄文选项行才能从竖排回到横排
    reflowOptionRows();
}


// 编辑 YAML 配置

static const char* kDefaultConfigYaml=
"# 运维参数仅由此文件提供，CLI 不可覆盖；删除即恢复默认。\n"
"log_file: \"\"              # 留空 = 仅控制台进度\n"
"log_level: INFO           # ERROR / WARN / INFO / DEBUG\n"
"worker_threads: 0         # 0 = 自动（CPU 核数）\n"
"max_open_files: 256       # 并发线程上限 = 此值 / 3（防句柄耗尽）\n"
"max_memory_bytes: 0       # 0 = 不限（可写 512MB / 1GB 等）\n"
"io_buffer_size: 1MB       # 内部流式缓冲（可写 512KB / 2MB 等）\n"
"max_speed: 0              # 0 = 不限速；可写 10MB/s、1.5GB/s、512KB/s（总吞吐上限）\n"
"max_path_length: 0        # 0 = 不限\n"
"path_whitelist_enabled: false\n"
"# path_whitelist:\n"
"#   - C:/Data/In\n"
"obfuscate_names: true     # 混淆输出文件名\n";

QString MainWindow::locateConfigFile() const {
    const QString name=QStringLiteral("fileencryptor.yaml");
    const QString legacy=QStringLiteral("fileencryptor.yml");
    auto findIn=[&](const QString& dir)->QString{
        if(dir.isEmpty()) return {};
        const QString p=QDir::toNativeSeparators(dir+QLatin1Char('/')+name);
        if(QFileInfo(p).isFile()) return p;
        const QString pl=QDir::toNativeSeparators(dir+QLatin1Char('/')+legacy);
        if(QFileInfo(pl).isFile()) return pl;
        return {};
    };
    const QString env=qEnvironmentVariable("FILEENCRYPTOR_CONFIG");
    if(!env.isEmpty()&&QFileInfo(env).isFile()) return env;
    QString p=findIn(QDir::current().absolutePath());
    if(!p.isEmpty()) return p;
    if(!m_fileEncryptorPath.isEmpty()) {
        p=findIn(QFileInfo(m_fileEncryptorPath).absolutePath());
        if(!p.isEmpty()) return p;
    }
    QString ucd;
#ifdef Q_OS_WIN
    ucd=qEnvironmentVariable("APPDATA");
    if(!ucd.isEmpty()) ucd+=QLatin1String("/FileEncryptor");
#else
    const QString xdg=qEnvironmentVariable("XDG_CONFIG_HOME");
    if(!xdg.isEmpty()) ucd=xdg+QLatin1String("/fileencryptor");
    else {
        const QString home=qEnvironmentVariable("HOME");
        if(!home.isEmpty()) ucd=home+QLatin1String("/.config/fileencryptor");
    }
#endif
    return findIn(ucd);
}

void MainWindow::onEditConfig() {
    QString target=locateConfigFile();
    if(target.isEmpty()) {
        target=QDir::current().absoluteFilePath(QStringLiteral("fileencryptor.yaml"));
        QFile f(target);
        if(!f.exists()) {
            if(!f.open(QIODevice::WriteOnly|QIODevice::Truncate)) {
                MsgBox::warn(this,tr("无法创建配置文件"),
                    tr("无法在以下位置创建默认配置文件：\n%1").arg(target));
                return;
            }
            f.write(kDefaultConfigYaml);
            f.close();
        }
    }
    if(!QDesktopServices::openUrl(QUrl::fromLocalFile(target))) {
        MsgBox::info(this,tr("请手动打开"),
            tr("系统未关联 YAML 文件的默认编辑器，请手动打开：\n%1").arg(target));
    }
}

// CLI 检测
bool MainWindow::checkCliExists(bool showDialog) {
    QString foundPath;
    if(FileEncryptorLocator::existsWithVersion(&foundPath)) {
        m_fileEncryptorPath=foundPath;
        return true;
    }

    if(showDialog) {
        showCliNotFoundError(tr("执行操作时"));
    }
    return false;
}

void MainWindow::showCliNotFoundError(const QString& context) {
    const QStringList expected=FileEncryptorLocator::getExpectedNames();
    QString detail=tr("在 %1 未找到 CLI 程序。\n\n").arg(context);
    detail+=tr("预期文件名：\n");
    for(const QString& name:expected) {
        detail+=QStringLiteral("  - %1\n").arg(name);
    }
    detail+=tr("\n当前程序目录：\n  %1\n").arg(FileEncryptorLocator::selfDir());
    detail+=tr("\n也可设置环境变量 FILEENCRYPTOR_EXE 指向 CLI 程序路径。");

    // 与 WinUI 一致：对话框里直接给「下载 CLI」，下载成功后自动重新探测
    CliNotFoundDialog dlg(detail,this);
    const bool retry=dlg.exec()==QDialog::Accepted && dlg.retryPressed();
    if(!retry && !dlg.downloaded()) return;
    rescanCli();
}

// 重新探测 CLI 并刷新依赖它的界面状态（重试、手动检测、下载完成后共用）
void MainWindow::rescanCli() {
    if(FileEncryptorLocator::existsWithVersion(&m_fileEncryptorPath)) {
        setStatus(tr("就绪 | FileEncryptor: %1").arg(m_fileEncryptorPath));
        MsgBox::info(this,tr("检测成功"),
            tr("已找到 CLI 程序：\n%1").arg(m_fileEncryptorPath));
        probeZstdSupport();
        updateAsymVisibility();
    }
}

// 能力探测
void MainWindow::probeZstdSupport() {
    m_zstdAvailable=false;
    m_aegisAvailable=true;
    if(m_fileEncryptorPath.isEmpty()) return;
    if(!m_probeProcess) {
        m_probeProcess=new QProcess(this);
        connect(m_probeProcess,QOverload<int,QProcess::ExitStatus>::of(&QProcess::finished),
                this,&MainWindow::onProbeFinished);
        // 进程起不来（缺运行库 / 被杀软拦截 / 路径失效）时 finished() 不会发射，
        // onProbeFinished 永不调用，压缩会被永久禁用。这里兜底 fail-open。
        connect(m_probeProcess,&QProcess::errorOccurred,this,[this](QProcess::ProcessError e){
            if(e==QProcess::FailedToStart) {
                m_zstdAvailable=true;
                updateAsymVisibility();
            }
        });
    }
    if(m_probeProcess->state()!=QProcess::NotRunning) m_probeProcess->kill();
    m_probeProcess->start(m_fileEncryptorPath,QStringList{QStringLiteral("--features")});
    if(!m_probeTimer) {
        m_probeTimer=new QTimer(this);
        m_probeTimer->setSingleShot(true);
        connect(m_probeTimer,&QTimer::timeout,this,[this]{
            if(m_probeProcess&&m_probeProcess->state()!=QProcess::NotRunning)
                m_probeProcess->kill();
        });
    }
    m_probeTimer->start(1000);
}

void MainWindow::onProbeFinished(int, QProcess::ExitStatus) {
    if(m_probeTimer) m_probeTimer->stop();
    if(!m_probeProcess) return;
    const QString out=QString::fromUtf8(m_probeProcess->readAllStandardOutput());
    // 仅当 CLI 显式声明 zstd=0 才禁用；其余（含进程异常无输出）一律 fail-open。
    // zstd 是 CLI 核心能力，所有版本都编译了；fail-closed 会让探测进程偶发失败
    // （缺运行库 / 被杀软拦截 / 超时）时压缩永久灰掉，且难以诊断。
    m_zstdAvailable=!out.contains(QStringLiteral("zstd=0"));
    if(out.contains(QStringLiteral("aegis=0"))) m_aegisAvailable=false;
    else if(out.contains(QStringLiteral("aegis=1"))) m_aegisAvailable=true;
    if(out.contains(QStringLiteral("aesgcm=0"))) m_aesGcmAvailable=false;
    else if(out.contains(QStringLiteral("aesgcm=1"))) m_aesGcmAvailable=true;
    if(out.contains(QStringLiteral("sm4=0"))) m_sm4Available=false;
    else if(out.contains(QStringLiteral("sm4=1"))) m_sm4Available=true;
    // 旧 CLI 的 --features 没有 pqc 字段：按「不支持」处理，由勾选状态决定是否下发 --no-pqc。
    // fail-open 会把 --no-pqc 转给不认它的旧 CLI，导致任务直接被拒。
    if(out.contains(QStringLiteral("pqc=1"))) m_pqcAvailable=true;
    else if(out.contains(QStringLiteral("pqc=0"))) m_pqcAvailable=false;
    // --pack 同理：字段缺失即视为不支持，宁可不勾也不给旧 CLI 发 -p
    m_packAvailable=out.contains(QStringLiteral("pack=1"));
    // 包装层要 OpenSSL：字段缺失即视为不支持，否则会下发旧 CLI 不认的 --wrap-key
    m_keywrapAvailable=out.contains(QStringLiteral("keywrap=1"));
    updateSm4Visibility();
    updatePackVisibility();
    updateWrapKeyVisibility();
    updateAsymVisibility();
}

void MainWindow::onRetryCliDetection() {
    if(FileEncryptorLocator::existsWithVersion(&m_fileEncryptorPath)) rescanCli();
    else showCliNotFoundError(tr("手动重试"));
}

void MainWindow::applyButtonStyles() {
    const bool dark=ThemeManager::isDarkActive();
    // 国庆周走红色系
    const bool red=ThemeManager::isNationalDay();
    m_btnRun->setStyleSheet(red
        // 国庆：运行键用国旗红原色，深浅一致；深色下悬停往亮里走才看得出状态变化
        ? QStringLiteral("QPushButton{background:#DE2910;color:#FFFFFF;padding:6px 18px;font-weight:bold;border-radius:4px;}"
                         "QPushButton:hover{background:#F04A30;}"
                         "QPushButton:pressed{background:#A81F0A;}")
        : (dark
           ? QStringLiteral("QPushButton{background:#43A047;color:#FFFFFF;padding:6px 18px;font-weight:bold;border-radius:4px;}"
                            "QPushButton:hover{background:#66BB6A;}")
           : QStringLiteral("QPushButton{background:#4A7C50;color:white;padding:6px 18px;font-weight:bold;border-radius:4px;}"
                            "QPushButton:hover{background:#3D6B4A;}")));
    m_btnCancel->setStyleSheet(red
        // 国庆：取消键同为红但明显加深，与运行键拉开层级
        ? (dark
           ? QStringLiteral("QPushButton{background:#8E2214;color:#FFFFFF;padding:6px 18px;font-weight:bold;border-radius:4px;}"
                            "QPushButton:hover{background:#A82C1B;}"
                            "QPushButton:pressed{background:#6E180E;}"
                            "QPushButton:disabled{background:#242121;color:#6B605E;}")
           : QStringLiteral("QPushButton{background:#9E2A1B;color:#FFFFFF;padding:6px 18px;font-weight:bold;border-radius:4px;}"
                            "QPushButton:hover{background:#B83624;}"
                            "QPushButton:pressed{background:#7C2014;}"
                            "QPushButton:disabled{background:#D8D4D3;color:#8A8180;}"))
        : (dark
           ? QStringLiteral("QPushButton{background:#E53935;color:#FFFFFF;padding:6px 18px;font-weight:bold;border-radius:4px;}"
                            "QPushButton:hover{background:#EF5350;}"
                            "QPushButton:disabled{background:#555;color:#ccc;}")
           : QStringLiteral("QPushButton{background:#C0392B;color:white;padding:6px 18px;font-weight:bold;border-radius:4px;}"
                            "QPushButton:hover{background:#A93226;}"
                            "QPushButton:disabled{background:#999;color:#eee;}")));
}

// 文件选择面板
QWidget* MainWindow::buildLeftPanel() {
    auto* w=new QWidget;
    m_leftPanel=w;
    auto* lay=new QVBoxLayout(w);

    auto* title=new QLabel(tr("<b>文件选择</b>"));
    title->setAlignment(Qt::AlignCenter);
    lay->addWidget(title);

    m_fileList=new QListWidget;
    m_fileList->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_fileList->setAlternatingRowColors(true);
    lay->addWidget(m_fileList,1);

    auto* btnRow1=new QHBoxLayout;
    m_btnAddFiles=new QPushButton(tr("添加文件..."));
    m_btnAddDir=new QPushButton(tr("添加目录..."));
    btnRow1->addWidget(m_btnAddFiles);
    btnRow1->addWidget(m_btnAddDir);
    lay->addLayout(btnRow1);

    auto* btnRow2=new QHBoxLayout;
    m_btnClearFiles=new QPushButton(tr("清空"));
    m_btnPreview=new QPushButton(tr("预览..."));
    m_btnPreview->setToolTip(tr("不解密到文件，先看看密文里的内容"));
    btnRow2->addWidget(m_btnPreview);
    btnRow2->addStretch();
    btnRow2->addWidget(m_btnClearFiles);
    lay->addLayout(btnRow2);

    return w;
}

// 功能区
QWidget* MainWindow::buildCenterPanel() {
    auto* w=new QWidget;
    m_centerPanel=w;
    auto* lay=new QGridLayout(w);
    lay->setColumnStretch(1,1);
    lay->setVerticalSpacing(10);

    int row=0;

    auto* lblAction=new QLabel(tr("<b>操作</b>"));
    lay->addWidget(lblAction,row,0);
    m_rbEncrypt=new QRadioButton(tr("加密"));
    m_rbDecrypt=new QRadioButton(tr("解密"));
    m_rbBatchEncrypt=new QRadioButton(tr("批量加密"));
    m_rbBatchDecrypt=new QRadioButton(tr("批量解密"));
    m_rbKeyGen=new QRadioButton(tr("生成密钥对"));
    m_rbDerive=new QRadioButton(tr("口令派生密钥对"));
    m_rbPubKey=new QRadioButton(tr("导出公钥"));
    m_rbWrapKey=new QRadioButton(tr("包装密钥"));
    m_rbUnwrapKey=new QRadioButton(tr("解开密钥"));
    m_rbWrapKey->setToolTip(tr("把一份 32 字节的数据密钥单独包进 .fekw 文件，用口令或收件人公钥保护"));
    m_rbUnwrapKey->setToolTip(tr("把 .fekw 里的数据密钥还原成 32 字节文件"));
    m_actionGroup=new QButtonGroup(this);
    m_actionGroup->addButton(m_rbEncrypt,static_cast<int>(CryptoAction::Encrypt));
    m_actionGroup->addButton(m_rbDecrypt,static_cast<int>(CryptoAction::Decrypt));
    m_actionGroup->addButton(m_rbBatchEncrypt,static_cast<int>(CryptoAction::BatchEncrypt));
    m_actionGroup->addButton(m_rbBatchDecrypt,static_cast<int>(CryptoAction::BatchDecrypt));
    m_actionGroup->addButton(m_rbKeyGen,static_cast<int>(CryptoAction::KeyGen));
    m_actionGroup->addButton(m_rbDerive,static_cast<int>(CryptoAction::Derive));
    m_actionGroup->addButton(m_rbPubKey,static_cast<int>(CryptoAction::PubKey));
    m_actionGroup->addButton(m_rbWrapKey,static_cast<int>(CryptoAction::WrapKey));
    m_actionGroup->addButton(m_rbUnwrapKey,static_cast<int>(CryptoAction::UnwrapKey));
    m_rbEncrypt->setChecked(true);

    auto* encRow=new QHBoxLayout;
    // 方向由 reflowOptionRows 统一决定（英/俄文按实测宽度排，中文恒定横排）
    encRow->addWidget(m_rbEncrypt);
    encRow->addWidget(m_rbDecrypt);
    encRow->addWidget(m_rbBatchEncrypt);
    encRow->addWidget(m_rbBatchDecrypt);
    encRow->addStretch();
    m_optionRows<<encRow;
    lay->addLayout(encRow,row,1);
    row++;

    auto* lblKeyMgmt=new QLabel(tr("密钥管理"));
    lay->addWidget(lblKeyMgmt,row,0);
    auto* keyMgmtRow=new QHBoxLayout;
    keyMgmtRow->addWidget(m_rbKeyGen);
    keyMgmtRow->addWidget(m_rbDerive);
    keyMgmtRow->addWidget(m_rbPubKey);
    keyMgmtRow->addStretch();
    m_optionRows<<keyMgmtRow;
    lay->addLayout(keyMgmtRow,row,1);
    row++;

    auto* lblWrap=new QLabel(tr("密钥包装"));
    lay->addWidget(lblWrap,row,0);
    auto* wrapRow=new QHBoxLayout;
    wrapRow->addWidget(m_rbWrapKey);
    wrapRow->addWidget(m_rbUnwrapKey);
    wrapRow->addStretch();
    m_optionRows<<wrapRow;
    lay->addLayout(wrapRow,row,1);
    row++;

    // 模式整行收进容器：密钥管理动作下整行一起藏，免得只藏控件留下孤零零的左侧标签
    m_modeRow=new QWidget;
    {
        auto* mr=new QHBoxLayout(m_modeRow);
        mr->setContentsMargins(0,0,0,0);
        // 模式项不带括号说明，算法特性交给悬停提示
        m_modeTitle=new QLabel(tr("加密模式"));
        mr->addWidget(m_modeTitle);
        // 模式与文件算法同排各占一半
        m_modeCombo=new QComboBox;
        m_modeCombo->setSizePolicy(QSizePolicy::Expanding,QSizePolicy::Preferred);
        m_modeCombo->addItem(tr("XChaCha20-Poly1305"),static_cast<int>(CryptoMode::XChaCha20));
        m_modeCombo->addItem(tr("AEGIS-256"),static_cast<int>(CryptoMode::Aegis256));
        m_modeCombo->addItem(tr("AES-256-GCM"),static_cast<int>(CryptoMode::AesGcm));
        m_modeCombo->addItem(tr("SM4-GCM"),static_cast<int>(CryptoMode::Sm4));
        m_modeCombo->addItem(tr("X25519 非对称"),static_cast<int>(CryptoMode::Asymmetric));
        mr->addWidget(m_modeCombo,1);

        // 仅非对称模式显示；非对称只加密此算法生成的密钥
        m_fileCipherLabel=new QLabel(tr("文件算法："));
        mr->addWidget(m_fileCipherLabel);
        m_fileCipherCombo=new QComboBox;
        m_fileCipherCombo->setSizePolicy(QSizePolicy::Expanding,QSizePolicy::Preferred);
        m_fileCipherCombo->addItem(tr("XChaCha20-Poly1305（默认）"),static_cast<int>(CryptoMode::XChaCha20));
        m_fileCipherCombo->addItem(tr("AEGIS-256"),static_cast<int>(CryptoMode::Aegis256));
        m_fileCipherCombo->addItem(tr("AES-256-GCM"),static_cast<int>(CryptoMode::AesGcm));
        m_fileCipherCombo->addItem(tr("SM4-GCM"),static_cast<int>(CryptoMode::Sm4));
        m_fileCipherCombo->setToolTip(tr("非对称模式下的文件载荷加密算法"));
        mr->addWidget(m_fileCipherCombo,1);
    }
    lay->addWidget(m_modeRow,row,0,1,2);
    row++;

    m_compressTitle=new QLabel(tr("压缩"));
    lay->addWidget(m_compressTitle,row,0);
    // 整行收进容器，显隐一次切换
    m_compressRow=new QWidget;
    {
        auto* compRow=new QHBoxLayout(m_compressRow);
        compRow->setContentsMargins(0,0,0,0);
    m_chkCompress=new QCheckBox(tr("压缩数据"));
    m_chkCompress->setToolTip(tr("加密时逐块压缩，对称与非对称均生效"));
    m_compressTipTemplate=m_chkCompress->toolTip();   // 能力探测后要还原默认说明
    m_compressLabel=new QLabel(tr("压缩级别（-5 到 22）："));
    m_compressLevel=new QSpinBox;
    m_compressLevel->setRange(-5,22);
    m_compressLevel->setValue(3);
    m_compressLevel->setToolTip(tr("数值越大压缩比越小，默认 3"));
    m_compressLevel->setButtonSymbols(QAbstractSpinBox::NoButtons);
    m_compressLevel->setAlignment(Qt::AlignRight);
    m_compressLevel->setKeyboardTracking(false);
    m_compressLevel->setFixedWidth(84);
    compRow->addWidget(m_chkCompress);
    compRow->addWidget(m_compressLabel);
    compRow->addWidget(m_compressLevel);
    compRow->addStretch();
    }
    lay->addWidget(m_compressRow,row,1);
    row++;

    m_asymWidget=new QGroupBox(tr("非对称加密"));
    {
        auto* av=new QVBoxLayout(m_asymWidget);
        // 顶部留白刚好放下组标题
        av->setContentsMargins(6,18,6,6);
        av->setSpacing(4);

        m_recipientRow=new QWidget;
        {
            auto* rr=new QHBoxLayout(m_recipientRow);
            rr->setContentsMargins(0,0,0,0);
            rr->addWidget(new QLabel(tr("公钥：")));
            m_recipientEdit=new QLineEdit;
            m_recipientEdit->setPlaceholderText(tr("公钥，或每行一个公钥的文件"));
            rr->addWidget(m_recipientEdit,1);
            m_btnRecipientBrowse=new QPushButton(tr("浏览..."));
            rr->addWidget(m_btnRecipientBrowse);
        }
        av->addWidget(m_recipientRow);
    }
    m_asymWidget->setVisible(false);
    lay->addWidget(m_asymWidget,row,0,1,2);
    row++;

    // 私钥文件行与说明同组：导出公钥时只看到「标题 + 私钥行 + 说明」一块，中间不留空白
    m_keygenWidget=new QGroupBox(tr("非对称密钥管理"));
    {
        auto* kv=new QVBoxLayout(m_keygenWidget);
        kv->setContentsMargins(6,18,6,6);
        kv->setSpacing(4);

        m_identityRow=new QWidget;
        {
            auto* ir=new QHBoxLayout(m_identityRow);
            ir->setContentsMargins(0,0,0,0);
            ir->addWidget(new QLabel(tr("私钥文件：")));
            m_identityEdit=new QLineEdit;
            m_identityEdit->setPlaceholderText(tr("身份私钥文件"));
            ir->addWidget(m_identityEdit,1);
            m_btnIdentityBrowse=new QPushButton(tr("浏览..."));
            ir->addWidget(m_btnIdentityBrowse);
        }
        kv->addWidget(m_identityRow);
        m_keygenIntro=new QLabel;
        m_keygenIntro->setWordWrap(true);
        kv->addWidget(m_keygenIntro);
    }
    m_keygenWidget->setVisible(false);
    lay->addWidget(m_keygenWidget,row,0,1,2);
    row++;

    // 密钥包装：文件选择 + 算法下拉。口令/公钥沿用上面的收件人行与密钥行，不重复造。
    m_wrapWidget=new QGroupBox(tr("密钥包装"));
    {
        auto* wv=new QVBoxLayout(m_wrapWidget);
        wv->setContentsMargins(6,18,6,6);
        wv->setSpacing(4);

        m_wrapFileRow=new QWidget;
        {
            auto* wr=new QHBoxLayout(m_wrapFileRow);
            wr->setContentsMargins(0,0,0,0);
            m_wrapFileLabel=new QLabel(tr("32 字节密钥文件："));
            wr->addWidget(m_wrapFileLabel);
            m_wrapFileEdit=new QLineEdit;
            m_wrapFileEdit->setPlaceholderText(tr("恰好 32 字节的数据密钥（DEK）文件"));
            wr->addWidget(m_wrapFileEdit,1);
            m_btnWrapFileBrowse=new QPushButton(tr("浏览..."));
            wr->addWidget(m_btnWrapFileBrowse);
        }
        wv->addWidget(m_wrapFileRow);

        m_wrapOutRow=new QWidget;
        {
            auto* orow=new QHBoxLayout(m_wrapOutRow);
            orow->setContentsMargins(0,0,0,0);
            m_wrapOutTitle=new QLabel(tr("包装输出："));
            orow->addWidget(m_wrapOutTitle);
            m_wrapOutEdit=new QLineEdit;
            m_wrapOutEdit->setPlaceholderText(tr("留空则用 <密钥文件>.fekw"));
            orow->addWidget(m_wrapOutEdit,1);
            m_btnWrapOutBrowse=new QPushButton(tr("浏览..."));
            orow->addWidget(m_btnWrapOutBrowse);
        }
        wv->addWidget(m_wrapOutRow);

        m_wrapAlgRow=new QWidget;
        {
            auto* ar=new QHBoxLayout(m_wrapAlgRow);
            ar->setContentsMargins(0,0,0,0);
            m_wrapAlgTitle=new QLabel(tr("包装算法："));
            ar->addWidget(m_wrapAlgTitle);
            m_wrapAlgCombo=new QComboBox;
            m_wrapAlgCombo->addItem(tr("AES-256-KWP（推荐，长度不限）"),static_cast<int>(WrapAlg::Kwp));
            m_wrapAlgCombo->addItem(tr("AES-KW（兼容旧工具）"),static_cast<int>(WrapAlg::AesKw));
            m_wrapAlgCombo->addItem(tr("收件人公钥（不需要口令）"),static_cast<int>(WrapAlg::Pubkey));
            m_wrapAlgCombo->setToolTip(tr("包装密钥的算法"));
            ar->addWidget(m_wrapAlgCombo,1);
        }
        wv->addWidget(m_wrapAlgRow);

        m_wrapIntro=new QLabel;
        m_wrapIntro->setWordWrap(true);
        wv->addWidget(m_wrapIntro);
    }
    m_wrapWidget->setVisible(false);
    lay->addWidget(m_wrapWidget,row,0,1,2);
    row++;

    m_outDirLabel=new QLabel(tr("输出目录"));
    lay->addWidget(m_outDirLabel,row,0);
    auto* outRow=new QHBoxLayout;
    m_outDirEdit=new QLineEdit;
    m_outDirEdit->setPlaceholderText(tr("留空 = 输出到源文件目录"));
    m_btnOutDirBrowse=new QPushButton(tr("浏览..."));
    outRow->addWidget(m_outDirEdit);
    outRow->addWidget(m_btnOutDirBrowse);
    lay->addLayout(outRow,row,1);
    row++;

    auto* lblKey=new QLabel(tr("密钥文件"));
    lay->addWidget(lblKey,row,0);
    auto* keyRow=new QHBoxLayout;
    m_keyfileEdit=new QLineEdit;
    m_keyfileEdit->setPlaceholderText(tr("留空 = 运行弹窗输入（经 stdin 注入）"));
    m_btnKeyfileBrowse=new QPushButton(tr("浏览..."));
    keyRow->addWidget(m_keyfileEdit);
    keyRow->addWidget(m_btnKeyfileBrowse);
    lay->addLayout(keyRow,row,1);
    row++;

    auto* lblOpts=new QLabel(tr("选项"));
    lay->addWidget(lblOpts,row,0);
    auto* optsRow=new QHBoxLayout;
    m_sourceCombo=new QComboBox;
    m_sourceCombo->addItem(tr("保留源文件"),0);
    m_sourceCombo->addItem(tr("完成后删除源文件"),1);
    m_sourceCombo->addItem(tr("完成后移入回收站"),3);
    m_sourceCombo->addItem(tr("完成后安全擦除（多次覆写）"),2);
    m_sourceCombo->setToolTip(tr("加密成功后对源文件的处理方式，仅加密动作生效"));
    m_chkForce=new QCheckBox(tr("覆盖已存在文件"));
    m_chkPack=new QCheckBox(tr("打包为单个容器"));
    m_chkPack->setToolTip(tr("把整个目录树或多个文件打成单个 .ptd 容器，不删除源文件"));
    m_chkSha256=new QCheckBox(tr("生成校验单"));
    m_chkSha256->setToolTip(tr("额外生成 .sha256 校验单，便于校验传输完整性"));
    // 与「生成校验单」同排，样式统一
    m_chkPqc=new QCheckBox(tr("后量子 PQC"));
    m_chkPqc->setChecked(true);
    // 提示与 WinUI 一致
    m_chkPqc->setToolTip(tr("非对称收件人用 X25519（或 X448）+ ML-KEM-768 混合密钥，水印签名用 ML-DSA-65"));
    m_chkX448=new QCheckBox(tr("使用 X448"));
    m_chkX448->setToolTip(tr("勾选后非对称封装使用 X448，不勾选则使用 X25519"));
    m_chkWatermark=new QCheckBox(tr("签名水印"));
    m_chkWatermark->setToolTip(tr("在密文尾部追加一条签名水印"));
    optsRow->addWidget(m_sourceCombo);
    optsRow->addWidget(m_chkForce);
    optsRow->addWidget(m_chkPack);
    optsRow->addWidget(m_chkSha256);
    optsRow->addWidget(m_chkPqc);
    optsRow->addWidget(m_chkX448);
    optsRow->addWidget(m_chkWatermark);
    m_chkSplit=new QCheckBox(tr("分卷输出"));
    m_chkSplit->setToolTip(tr("把密文切成多个 .001/.002 分卷；解密时随便挑一卷即可自动合并"));
    optsRow->addWidget(m_chkSplit);
    optsRow->addStretch();
    m_optionRows<<optsRow;
    lay->addLayout(optsRow,row,1);
    row++;

    // 分卷大小：勾选「分卷输出」后才显示，默认 100MB
    m_splitRow=new QWidget;
    {
        auto* sr=new QHBoxLayout(m_splitRow);
        sr->setContentsMargins(0,0,0,0);
        sr->addWidget(new QLabel(tr("分卷大小")));
        m_splitSize=new QDoubleSpinBox;
        m_splitSize->setRange(1.0,1048576.0);
        m_splitSize->setValue(100.0);
        m_splitSize->setDecimals(2);
        m_splitSize->setSingleStep(10.0);
        // 单位由右侧下拉决定，数字框不要再挂固定后缀（否则选 GB 时仍显示 MB）；
        // 宽度留足，避免右侧微调按钮挤占输入区、打字时看不见字符
        m_splitSize->setMinimumWidth(150);
        m_splitUnit=new QComboBox;
        m_splitUnit->addItem(tr("MB"));
        m_splitUnit->addItem(tr("GB"));
        m_splitUnit->addItem(tr("TB"));
        m_splitUnit->setToolTip(tr("分卷大小的单位"));
        sr->addWidget(m_splitSize);
        sr->addWidget(m_splitUnit);
        sr->addStretch();
    }
    m_splitRow->setVisible(false);
    lay->addWidget(m_splitRow,row,1);
    row++;

    // 勾选签名水印后显示，不明文回显
    m_wmKeyRow=new QWidget;
    m_wmKeyRow->setVisible(false);
    {
        auto* wr=new QHBoxLayout(m_wmKeyRow);
        wr->setContentsMargins(0,0,0,0);
        wr->addWidget(new QLabel(tr("水印签名密钥")));
        m_wmKeyEdit=new QLineEdit;
        m_wmKeyEdit->setEchoMode(QLineEdit::Password);
        m_wmKeyEdit->setPlaceholderText(tr("私钥 PEM（密码框输入，不明文回显）"));
        wr->addWidget(m_wmKeyEdit,1);
        m_btnWmKeyBrowse=new QPushButton(tr("浏览..."));
        wr->addWidget(m_btnWmKeyBrowse);
        wr->addWidget(new QLabel(tr("留空 = 只写水印记录不签名")));
    }
    lay->addWidget(m_wmKeyRow,row,0,1,2);
    row++;

    auto* runRow=new QHBoxLayout;
    m_btnRun=new QPushButton(tr("▶ 运行"));
    m_btnCancel=new QPushButton(tr("■ 取消"));
    m_btnRewrap=new QPushButton(tr("密钥轮换"));
    m_btnRewrap->setToolTip(tr("用新口令重新包裹文件密钥，密文不动、零重加密开销"));
    m_btnCancel->setEnabled(false);
    runRow->addWidget(m_btnRewrap);
    runRow->addStretch();
    runRow->addWidget(m_btnRun);
    runRow->addWidget(m_btnCancel);
    lay->addLayout(runRow,row,1);
    row++;
    applyButtonStyles();

    lay->setRowStretch(row,1);

    // 国庆祝福：贴在功能区最下方，跟 WinUI 同位置。
    // 非国庆窗口隐藏，不占布局空间。
    m_birthdayLabel=new QLabel(ThemeManager::birthdayMessage());
    m_birthdayLabel->setAlignment(Qt::AlignCenter);
    m_birthdayLabel->setWordWrap(true);
    m_birthdayLabel->setTextInteractionFlags(Qt::NoTextInteraction);
    m_birthdayLabel->setVisible(ThemeManager::isNationalDay());
    applyBirthdayStyle();
    lay->addWidget(m_birthdayLabel,row,0,1,2);
    row++;

    return w;
}

// 输出区
QWidget* MainWindow::buildBottomPanel() {
    auto* w=new QWidget;
    m_bottomPanel=w;
    auto* lay=new QVBoxLayout(w);
    lay->setContentsMargins(0,0,0,0);

    auto* headerRow=new QHBoxLayout;
    headerRow->setContentsMargins(0,0,0,0);
    headerRow->addWidget(new QLabel(tr("<b>命令浏览与执行输出</b>")));
    headerRow->addStretch();
    m_btnTaskHistory=new QPushButton(tr("任务历史..."));
    m_btnTaskHistory->setToolTip(tr("查看任务历史记录，双击一条可回填参数"));
    headerRow->addWidget(m_btnTaskHistory);
    lay->addLayout(headerRow);

    m_outputView=new QPlainTextEdit;
    m_outputView->setReadOnly(true);
    m_outputView->setLineWrapMode(QPlainTextEdit::NoWrap);
    m_outputView->setMinimumHeight(360);
    m_outputView->setPlaceholderText(tr("此处显示命令预览与执行输出。stdout 默认色，stderr 红色。"));
    m_outputView->setFont(FontBootstrap::monoFont());
    m_outputView->document()->setMaximumBlockCount(5000);
    lay->addWidget(m_outputView);

    return w;
}

// 信号连接
void MainWindow::connectSignals() {
    connect(m_btnAddFiles,&QPushButton::clicked,this,&MainWindow::onAddFiles);
    connect(m_btnAddDir,&QPushButton::clicked,this,&MainWindow::onAddDir);
    connect(m_btnClearFiles,&QPushButton::clicked,this,&MainWindow::onClearFiles);
    connect(m_btnPreview,&QPushButton::clicked,this,&MainWindow::onPreviewClicked);

    connect(m_btnRun,&QPushButton::clicked,this,&MainWindow::onRunClicked);
    if(m_btnRewrap)
        connect(m_btnRewrap,&QPushButton::clicked,this,&MainWindow::onRewrapClicked);
    connect(m_btnCancel,&QPushButton::clicked,this,&MainWindow::onCancelClicked);

    connect(m_executor,&ICommandExecutor::outputLine,this,&MainWindow::onOutputLine);
    connect(m_executor,&ICommandExecutor::finished,this,&MainWindow::onCommandFinished);
    connect(m_executor,&ICommandExecutor::confirmPrompt,this,&MainWindow::onConfirmPrompt);

    auto refresh=[this]{ refreshCommandPreview(); };
    connect(m_actionGroup,&QButtonGroup::idClicked,this,refresh);
    if(m_wrapFileEdit) connect(m_wrapFileEdit,&QLineEdit::textChanged,this,refresh);
    if(m_wrapOutEdit) connect(m_wrapOutEdit,&QLineEdit::textChanged,this,refresh);
    if(m_wrapAlgCombo) {
        connect(m_wrapAlgCombo,QOverload<int>::of(&QComboBox::currentIndexChanged),this,refresh);
        // 算法决定「口令还是私钥」，切换后区块显隐要重算
        connect(m_wrapAlgCombo,QOverload<int>::of(&QComboBox::currentIndexChanged),
            this,[this](int){ updateAsymVisibility(); });
    }
    connect(m_modeCombo,QOverload<int>::of(&QComboBox::currentIndexChanged),this,refresh);
    connect(m_outDirEdit,&QLineEdit::textChanged,this,refresh);
    connect(m_keyfileEdit,&QLineEdit::textChanged,this,refresh);
    connect(m_sourceCombo,QOverload<int>::of(&QComboBox::currentIndexChanged),this,refresh);
    connect(m_chkForce,&QCheckBox::stateChanged,this,refresh);
    connect(m_chkSha256,&QCheckBox::stateChanged,this,refresh);
    connect(m_chkCompress,&QCheckBox::stateChanged,this,refresh);
    connect(m_chkCompress,&QCheckBox::stateChanged,this,[this](int){ updateAsymVisibility(); });
    // 勾选分卷时露出大小行；单位下拉改动也要刷新命令预览
    connect(m_chkSplit,&QCheckBox::stateChanged,this,refresh);
    connect(m_chkSplit,&QCheckBox::stateChanged,this,[this](int){ updateAsymVisibility(); });
    connect(m_splitSize,QOverload<double>::of(&QDoubleSpinBox::valueChanged),this,refresh);
    connect(m_splitUnit,QOverload<int>::of(&QComboBox::currentIndexChanged),this,refresh);
    connect(m_compressLevel,QOverload<int>::of(&QSpinBox::valueChanged),this,refresh);
    connect(m_fileList,&QListWidget::itemChanged,this,refresh);
    connect(m_chkPqc,&QCheckBox::stateChanged,this,refresh);
    connect(m_chkWatermark,&QCheckBox::stateChanged,this,[this](int){ updateAsymVisibility(); });
    connect(m_wmKeyEdit,&QLineEdit::textChanged,this,refresh);
    connect(m_btnWmKeyBrowse,&QPushButton::clicked,this,[this]{
        const QString f=QFileDialog::getOpenFileName(this,tr("选择水印签名私钥"),
            QDir::homePath(),tr("私钥 PEM (*.pem *.key);;所有文件 (*)"));
        if(f.isEmpty()) return;
        // 密钥内容直接进密码框，界面不回显明文
        QFile in(f);
        if(!in.open(QIODevice::ReadOnly|QIODevice::Text)) {
            setStatus(tr("[水印私钥] 读取失败：%1").arg(in.errorString()));
            return;
        }
        const QString pem=QString::fromUtf8(in.readAll());
        in.close();
        m_wmKeyEdit->setText(pem);
        setStatus(tr("[水印私钥] 已载入：%1").arg(QFileInfo(f).fileName()));
        });

    connect(m_btnOutDirBrowse,&QPushButton::clicked,this,[this]{
        QString d=QFileDialog::getExistingDirectory(this,tr("选择输出目录"),
            m_outDirEdit->text().isEmpty() ? QDir::homePath() : m_outDirEdit->text());
        if(!d.isEmpty()) m_outDirEdit->setText(d);
        });
    connect(m_btnKeyfileBrowse,&QPushButton::clicked,this,[this]{
        QString f=QFileDialog::getOpenFileName(this,tr("选择密钥文件"),
            QDir::homePath(),tr("所有文件 (*)"));
        if(!f.isEmpty()) m_keyfileEdit->setText(f);
        });

    connect(m_btnRecipientBrowse,&QPushButton::clicked,this,[this]{
        QString f=QFileDialog::getOpenFileName(this,tr("选择公钥文件"),
            QDir::homePath(),tr("公钥文件 (*.txt *.agepub *);;所有文件 (*)"));
        if(!f.isEmpty()) m_recipientEdit->setText(f);
        });
    connect(m_btnIdentityBrowse,&QPushButton::clicked,this,[this]{
        QString f=QFileDialog::getOpenFileName(this,tr("选择私钥文件"),
            QDir::homePath(),tr("私钥文件 (*.txt *.agekey *);;所有文件 (*)"));
        if(!f.isEmpty()) m_identityEdit->setText(f);
        });
    connect(m_btnTaskHistory,&QPushButton::clicked,this,&MainWindow::onOpenTaskHistory);

    connect(m_btnWrapFileBrowse,&QPushButton::clicked,this,[this]{
        const bool wrap=m_actionGroup->checkedId()==static_cast<int>(CryptoAction::WrapKey);
        const QString f=QFileDialog::getOpenFileName(this,
            wrap ? tr("选择要包装的 32 字节数据密钥") : tr("选择要解开的包装文件"),
            QString(), wrap ? tr("所有文件 (*)") : tr("包装文件 (*.fekw);;所有文件 (*)"));
        if(!f.isEmpty()) m_wrapFileEdit->setText(f);
        });
    connect(m_btnWrapOutBrowse,&QPushButton::clicked,this,[this]{
        const bool wrap=m_actionGroup->checkedId()==static_cast<int>(CryptoAction::WrapKey);
        const QString f=QFileDialog::getSaveFileName(this,
            wrap ? tr("包装产物保存为") : tr("解出的数据密钥保存为"),
            QString(), wrap ? tr("包装文件 (*.fekw)") : tr("数据密钥 (*.dek)"));
        if(!f.isEmpty()) m_wrapOutEdit->setText(f);
        });

    connect(m_fileList,&QListWidget::itemChanged,this,[this]{ recomputePending(); });
    connect(m_modeCombo,QOverload<int>::of(&QComboBox::currentIndexChanged),
        this,&MainWindow::updateAsymVisibility);
    if(m_fileCipherCombo) {
        connect(m_fileCipherCombo,QOverload<int>::of(&QComboBox::currentIndexChanged),
            this,&MainWindow::updateAsymVisibility);
    }
    connect(m_actionGroup,&QButtonGroup::idClicked,
        this,[this](int){ updateAsymVisibility(); });
    if(m_chkX448) {
        connect(m_chkX448,&QCheckBox::toggled,this,[this](bool){ updateAsymVisibility(); });
    }
}

// 打包开关依赖 CLI 的 --pack（2.8.0+）：不支持时整个勾选框隐藏并清掉勾选，
// 否则下发的 -p 会被旧 CLI 当未知参数直接拒绝。
// 不与分卷互斥：归档在明文域打成字节流，分卷再作用于容器，两者叠加语义明确。
void MainWindow::updatePackVisibility() {
    if(!m_chkPack) return;
    if(!m_packAvailable && m_chkPack->isChecked()) m_chkPack->setChecked(false);
}

// 密钥包装动作（--wrap-key / --unwrap-key）同样是 2.9.0 才有：
// CLI 没编 OpenSSL 时报 keywrap=0，此时禁用两个单选并把停用原因写进提示。
// 勾选中的那个要主动切走，否则界面停用却仍能点运行。
void MainWindow::updateWrapKeyVisibility() {
    if(!m_rbWrapKey || !m_rbUnwrapKey) return;
    const QString tip=m_keywrapAvailable ? QString()
        : tr("配套的命令行程序没有密钥包装能力，请更换带 OpenSSL 的 CLI");
    for(QRadioButton* rb:{m_rbWrapKey, m_rbUnwrapKey}) {
        rb->setEnabled(m_keywrapAvailable);
        rb->setToolTip(tip);
    }
    if(!m_keywrapAvailable && m_rbWrapKey->isChecked()) m_rbEncrypt->setChecked(true);
}

// 某些模式依赖硬件或编译选项：--features 报不可用时禁用对应项，避免选中后 CLI 直接报错
void MainWindow::updateSm4Visibility() {
    struct Item{ CryptoMode mode; bool avail; };
    const QList<Item> items{
        {CryptoMode::AesGcm, m_aesGcmAvailable},
        {CryptoMode::Sm4,    m_sm4Available},
    };
    for(QComboBox* cb:{m_modeCombo, m_fileCipherCombo}) {
        if(!cb) continue;
        for(const Item& it : items) {
            for(int i=0;i<cb->count();++i) {
                if(cb->itemData(i).toInt()!=static_cast<int>(it.mode)) continue;
                // Qt 约定：UserRole-1 置 false 即禁用该项
                cb->setItemData(i, !it.avail ? QVariant(false) : QVariant(),
                                Qt::UserRole-1);
                if(!it.avail && cb->currentIndex()==i) cb->setCurrentIndex(0);
                break;
            }
        }
    }
}

// 动作/模式切换
void MainWindow::updateAsymVisibility() {
    const int act=m_actionGroup->checkedId();
    const bool keygen=(act==static_cast<int>(CryptoAction::KeyGen));
    const bool derive=(act==static_cast<int>(CryptoAction::Derive));
    const bool pubkey=(act==static_cast<int>(CryptoAction::PubKey));
    const bool wrap=(act==static_cast<int>(CryptoAction::WrapKey));
    const bool unwrap=(act==static_cast<int>(CryptoAction::UnwrapKey));
    const bool isWrapAction=(wrap||unwrap);
    const bool isKeyAction=(keygen||derive||pubkey);
    const bool isEnc=(act==static_cast<int>(CryptoAction::Encrypt)||
                      act==static_cast<int>(CryptoAction::BatchEncrypt));
    const bool asymDecrypt=(act==static_cast<int>(CryptoAction::Decrypt)||
                            act==static_cast<int>(CryptoAction::BatchDecrypt));
    const bool asym=(!isKeyAction)&&(!isWrapAction)&&
        (m_modeCombo->currentData().toInt()==static_cast<int>(CryptoMode::Asymmetric));

    // 解密不看模式：模式下拉若停在非对称，下一次对称解密会被判成非对称而不弹口令框
    if(asymDecrypt&&asym) {
        for(int i=0;i<m_modeCombo->count();++i) {
            if(m_modeCombo->itemData(i).toInt()==static_cast<int>(CryptoMode::XChaCha20)) {
                m_modeCombo->setCurrentIndex(i);
                break;
            }
        }
    }

    // 公钥行只服务加密；解密靠下面密钥管理组里的「私钥文件」行。
    // 包装动作的公钥收件人也复用这一行：--wrap-to 与 -r 同为收件人输入。
    const bool wrapPubkey=isWrapAction && currentWrapAlg()==WrapAlg::Pubkey;
    m_asymWidget->setVisible((asym&&isEnc)||(wrap&&wrapPubkey));
    m_recipientRow->setVisible((asym&&isEnc)||(wrap&&wrapPubkey));
    // 同一个组在包装动作下装的是收件人公钥，标题得跟着改，否则写着「非对称加密」误导
    if(m_asymTitle.isEmpty()) m_asymTitle=m_asymWidget->title();
    m_asymWidget->setTitle(wrap ? tr("收件人公钥") : m_asymTitle);
    // 「私钥文件」行与说明同时服务密钥管理三项、解密动作与公钥解包
    const bool identityShown=isKeyAction||asymDecrypt||(unwrap&&wrapPubkey);
    m_identityRow->setVisible(identityShown);
    m_keygenWidget->setVisible(identityShown);
    // 曲线开关：非对称模式下控制封装曲线，生成密钥对时控制 -x448（CLI 只认这条）；
    // 派生(-G)/导出公钥(-Y)固定走 X25519，对称加密也无需曲线，故一律隐藏。
    if(m_chkX448) m_chkX448->setVisible((asym&&isEnc)||keygen);
    // 模式整行：只有加密动作才用得上（解密不带 -m，非对称解密走「私钥文件」入口）
    m_modeRow->setVisible(isEnc&&!isKeyAction&&!isWrapAction);
    // 加密专属字段：解密与密钥管理动作下一律不出现（这些参数 CLI 只对加密动作生效，
    // 留在界面上只是点不动的死控件）
    const bool encFields=isEnc&&!isKeyAction;
    // 文件算法仍在容器里，单独按非对称模式控制显隐
    if(m_fileCipherLabel) m_fileCipherLabel->setVisible(asym&&isEnc);
    if(m_fileCipherCombo) {
        m_fileCipherCombo->setVisible(asym&&isEnc);
        // 非对称模式禁用 SM4 之外的选择在界面上无意义，降级为非对称时自动回到默认项
        if(asym && m_fileCipherCombo->currentIndex()<0) m_fileCipherCombo->setCurrentIndex(0);
    }
    if(m_sourceCombo) m_sourceCombo->setVisible(encFields);
    if(m_chkPack) m_chkPack->setVisible(encFields && m_packAvailable);
    if(m_chkSplit) m_chkSplit->setVisible(encFields);
    if(!encFields) {
        // 藏起来的开关清掉勾选，CLI 不会收到对当前动作无意义的开关
        if(m_chkSha256&&m_chkSha256->isChecked()) m_chkSha256->setChecked(false);
        if(m_chkWatermark&&m_chkWatermark->isChecked()) m_chkWatermark->setChecked(false);
        if(m_chkPack&&m_chkPack->isChecked()) m_chkPack->setChecked(false);
        if(m_chkSplit&&m_chkSplit->isChecked()) m_chkSplit->setChecked(false);
        if(m_chkPqc&&m_chkPqc->isChecked()) m_chkPqc->setChecked(false);
    }
    // 分卷大小行：仅「加密动作 + 勾选分卷」时露出
    if(m_splitRow)
        m_splitRow->setVisible(encFields && m_chkSplit && m_chkSplit->isChecked());
    if(m_chkSha256) m_chkSha256->setVisible(encFields);
    if(m_chkWatermark) m_chkWatermark->setVisible(encFields);
    // PQC 只影响载荷封装与水印签名，包装路线不经过这两步，同样收起
    if(m_chkPqc) m_chkPqc->setVisible(encFields);

    if(keygen) {
        const QString curve=m_chkX448&&m_chkX448->isChecked()
            ? QStringLiteral("X448") : QStringLiteral("X25519");
        m_keygenWidget->setTitle(tr("随机生成密钥对"));
        m_keygenIntro->setText(tr("在输出目录随机生成一对 %1 密钥：公钥打印到输出面板，私钥写入 rage_private.txt。").arg(curve));
    } else if(derive) {
        m_keygenWidget->setTitle(tr("口令派生密钥对"));
        m_keygenIntro->setText(tr("由口令派生一对 X25519 密钥：公钥打印到输出面板，私钥写入 rage_private.txt，"
                                  "盐写入 rage_derive_salt.txt（复现同一密钥对必需）。"));
    } else if(pubkey) {
        m_keygenWidget->setTitle(tr("由私钥导出公钥"));
        m_keygenIntro->setText(tr("读取私钥文件反推出对应公钥，打印到输出面板。"));
    } else if(asymDecrypt) {
        m_keygenWidget->setTitle(tr("非对称解密"));
        m_keygenIntro->setText(tr("填写身份私钥文件即可解密选中的 .ptd，无需口令。"));
    } else if(unwrap && wrapPubkey) {
        m_keygenWidget->setTitle(tr("公钥解包"));
        m_keygenIntro->setText(tr("该 .fekw 由收件人公钥封装，填写对应身份私钥文件即可取回数据密钥，无需口令。"));
    }

    // 包装区块：文件清单不参与，输出目录也不参与（产物路径由包装/解包输出行决定）
    m_wrapWidget->setVisible(isWrapAction);
    if(m_outDirLabel) m_outDirLabel->setVisible(!isWrapAction);
    if(m_outDirEdit) m_outDirEdit->setVisible(!isWrapAction);
    if(m_btnOutDirBrowse) m_btnOutDirBrowse->setVisible(!isWrapAction);
    if(isWrapAction) {
        m_wrapWidget->setTitle(wrap ? tr("包装密钥") : tr("解开密钥"));
        m_wrapFileLabel->setText(wrap ? tr("32 字节密钥文件：") : tr("包装文件："));
        m_wrapFileEdit->setPlaceholderText(wrap
            ? tr("恰好 32 字节的数据密钥（DEK）文件")
            : tr("要解开的 .fekw 包装文件"));
        m_wrapOutRow->setVisible(true);
        m_wrapOutTitle->setText(wrap ? tr("包装输出：") : tr("解包输出："));
        m_wrapOutEdit->setPlaceholderText(wrap
            ? tr("留空则用 <密钥文件>.fekw")
            : tr("留空则用 <包装文件>.dek"));
        // 解包时算法写在 blob 头里，下拉只决定「口令还是私钥」，标题随之改口
        m_wrapAlgTitle->setText(wrap ? tr("包装算法：") : tr("解密方式："));
        m_wrapAlgCombo->setToolTip(wrap
            ? tr("包装密钥的算法")
            : tr("包装时的算法已记录在 .fekw 里，此处只用于选择解密凭据"));
        if(wrap) {
            m_wrapIntro->setText(wrapPubkey
                ? tr("把 32 字节数据密钥用收件人公钥封装，不需要口令。")
                : tr("用口令派生出的密钥包装 32 字节数据密钥。"));
        } else {
            m_wrapIntro->setText(wrapPubkey
                ? tr("从 .fekw 中取回 32 字节数据密钥，需要当初收件人的身份私钥。")
                : tr("从 .fekw 中取回 32 字节数据密钥，需要包装时使用的口令。"));
        }
    }

    if(isKeyAction) {
        // 密钥管理动作固定落在非对称项，切回加密动作时参数才是预期的 -m
        for(int i=0;i<m_modeCombo->count();++i) {
            if(m_modeCombo->itemData(i).toInt()==static_cast<int>(CryptoMode::Asymmetric)) {
                m_modeCombo->setCurrentIndex(i);
                break;
            }
        }
    }

    // 压缩对非对称同样可用
    const bool compAllowed=isEnc;
    m_compressTitle->setVisible(compAllowed);
    m_compressRow->setVisible(compAllowed);
    // 禁用以免 CliArgBuilder 仍下发 -zstd
    const bool compressUsable=compAllowed && m_zstdAvailable;
    m_chkCompress->setEnabled(compressUsable);
    m_compressLabel->setEnabled(compressUsable);
    m_compressLevel->setEnabled(compressUsable);
    if(!m_zstdAvailable) {
        if(m_chkCompress->isChecked()) m_chkCompress->setChecked(false);
        m_chkCompress->setToolTip(tr("当前 CLI 不支持压缩，请更换带 zstd 的 CLI"));
    } else {
        m_chkCompress->setToolTip(m_compressTipTemplate);
    }

    // 能力开关常驻，仅由勾选状态决定是否下发
    const bool wmOn=m_chkWatermark && m_chkWatermark->isChecked();
    const QString pqcTip=tr("非对称收件人用 X25519（或 X448）+ ML-KEM-768 混合密钥，水印签名用 ML-DSA-65");
    m_chkPqc->setEnabled(m_pqcAvailable && encFields);
    m_chkPqc->setToolTip(m_pqcAvailable
        ? pqcTip
        : tr("当前 CLI 不支持后量子，请更换带 ML-KEM 的 CLI"));
    m_wmKeyRow->setVisible(isEnc && wmOn);

    refreshCommandPreview();
}

void MainWindow::addInputPaths(const QStringList& paths) {
    QSet<QString> existing;
    for(int i=0;i<m_fileList->count();++i) existing.insert(m_fileList->item(i)->text());
    bool added=false;
    for(const QString& p:paths) {
        if(p.isEmpty()||existing.contains(p)) continue;
        existing.insert(p);
        auto* item=new QListWidgetItem(p,m_fileList);
        item->setFlags(item->flags()|Qt::ItemIsUserCheckable);
        item->setCheckState(Qt::Checked);
        added=true;
    }
    if(added) {
        const int act=m_actionGroup->checkedId();
        bool hasDir=false;
        for(const QString& p:paths)
            if(QFileInfo(p).isDir()) { hasDir=true; break; }
        if(hasDir&&(act==static_cast<int>(CryptoAction::Encrypt)||
                    act==static_cast<int>(CryptoAction::Decrypt))) {
            const CryptoAction batch=(act==static_cast<int>(CryptoAction::Encrypt))
                ? CryptoAction::BatchEncrypt : CryptoAction::BatchDecrypt;
            if(QAbstractButton* b=m_actionGroup->button(static_cast<int>(batch)))
                b->setChecked(true);
            updateAsymVisibility();
            setStatus(tr("检测到目录输入，已自动切换为批量动作"));
        }
        refreshCommandPreview();
    }
    resetPendingCache();
    recomputePending();
}

void MainWindow::onAddFiles() {
    const QStringList files=QFileDialog::getOpenFileNames(
        this,tr("选择文件"),QDir::homePath(),tr("所有文件 (*)"));
    addInputPaths(files);
}

void MainWindow::onAddDir() {
    const QString d=QFileDialog::getExistingDirectory(
        this,tr("选择目录"),QDir::homePath());
    if(!d.isEmpty()) addInputPaths(QStringList{d});
}

void MainWindow::onClearFiles() {
    m_fileList->clear();
    refreshCommandPreview();
    resetPendingCache();
    recomputePending();
}

void MainWindow::dragEnterEvent(QDragEnterEvent* e) {
    if(e->mimeData()->hasUrls()) e->acceptProposedAction();
}

void MainWindow::dropEvent(QDropEvent* e) {
    const QList<QUrl> urls=e->mimeData()->urls();
    if(urls.isEmpty()) return;
    QStringList paths;
    for(const QUrl& u:urls) {
        const QString p=u.toLocalFile();
        if(p.isEmpty()) continue;
        paths<<QDir::toNativeSeparators(p);
    }
    if(!paths.isEmpty()) {
        e->acceptProposedAction();
        addInputPaths(paths);
    }
}

WrapAlg MainWindow::currentWrapAlg() const {
    if(!m_wrapAlgCombo) return WrapAlg::Kwp;
    return static_cast<WrapAlg>(m_wrapAlgCombo->currentData().toInt());
}

ShellOptions MainWindow::collectOptions() const {
    ShellOptions o;
    o.action=static_cast<CryptoAction>(m_actionGroup->checkedId());
    o.mode=static_cast<CryptoMode>(m_modeCombo->currentData().toInt());
    if(o.mode==CryptoMode::Asymmetric && m_fileCipherCombo) {
        o.fileMode=static_cast<CryptoMode>(m_fileCipherCombo->currentData().toInt());
    }

    for(int i=0; i<m_fileList->count(); ++i) {
        auto* it=m_fileList->item(i);
        if(it->checkState()==Qt::Checked) o.inputPaths<<it->text();
    }

    o.outputDir=m_outDirEdit->text().trimmed();
    o.sourceDisposition=m_sourceCombo ? m_sourceCombo->currentData().toInt() : 0;
    o.forceOverwrite=m_chkForce->isChecked();
    o.pack=(m_chkPack && m_chkPack->isChecked());
    o.split=(m_chkSplit && m_chkSplit->isChecked());
    if(m_splitSize) o.splitSize=m_splitSize->value();
    if(m_splitUnit) o.splitUnit=m_splitUnit->currentIndex();
    o.writeSha256=m_chkSha256->isChecked();
    o.keyfilePath=m_keyfileEdit->text().trimmed();
    // CLI 无 zstd 时禁用勾选框，这里再兜一层，避免任务记录/预览里出现别人无法执行的指令
    o.compress=m_chkCompress->isChecked() && m_zstdAvailable;
    o.compressionLevel=o.compress ? m_compressLevel->value() : 0;
    o.useX448=(m_chkX448 && m_chkX448->isChecked());
    // CLI 不支持 PQC 时恒为 false：既不请求 PQC，也不下发旧 CLI 不认的 --no-pqc
    o.pqc=(m_chkPqc && m_chkPqc->isChecked() && m_pqcAvailable);
    o.watermark=m_chkWatermark->isChecked();
    o.watermarkKeyPath=m_wmKeyEdit->text().trimmed();

    const QString rawRecip=m_recipientEdit->text().trimmed();
    o.recipientPath=rawRecip;
    o.recipientCount=0;
    for(const QString& seg:rawRecip.split(QRegularExpression(QStringLiteral("[,，;；]")),Qt::SkipEmptyParts)) {
        if(!seg.trimmed().isEmpty()) ++o.recipientCount;
    }
    o.identityPath=m_identityEdit->text().trimmed();
    o.wrapAlg=currentWrapAlg();
    if(m_wrapFileEdit) o.wrapInput=m_wrapFileEdit->text().trimmed();
    if(m_wrapOutEdit) o.wrapOutput=m_wrapOutEdit->text().trimmed();
    {
        const bool asymDecrypt=(o.action==CryptoAction::Decrypt||
                                o.action==CryptoAction::BatchDecrypt);
        if(asymDecrypt) o.keyfilePath=o.identityPath;
        else if(o.action==CryptoAction::PubKey) o.keyfilePath=o.identityPath;
        else if(o.action==CryptoAction::WrapKey) {
            // 公钥路线没有 KEK，密钥文件行对它无意义，留着会被误当成口令来源下发
            o.keyfilePath=(o.wrapAlg==WrapAlg::Pubkey) ? QString() : o.keyfilePath;
        }
        else if(o.mode==CryptoMode::Asymmetric) o.keyfilePath.clear();
    }

    return o;
}

// 多收件人归一化
QString MainWindow::resolveRecipients(const QString& raw) const {
    QStringList parts;
    for(const QString& seg:raw.split(QRegularExpression(QStringLiteral("[,，;；]")),Qt::SkipEmptyParts)) {
        const QString t=seg.trimmed();
        if(!t.isEmpty()) parts<<t;
    }
    if(parts.size()<=1) return raw.trimmed();
    const bool allKeys=std::all_of(parts.cbegin(),parts.cend(),
        [](const QString& s){ return s.startsWith(QLatin1String("age1"))
                                  ||s.startsWith(QLatin1String("MLKEM1-"))
                                  ||s.startsWith(QLatin1String("X448-"))
                                  ||s.startsWith(QLatin1String("publickey:")); });
    if(!allKeys) return raw.trimmed();
    if(!m_recipientTempFile.isEmpty()) { QFile::remove(m_recipientTempFile); m_recipientTempFile.clear(); }
    QTemporaryFile recTmp(QDir::tempPath()+QStringLiteral("/fe_recipients_XXXXXX"));
    recTmp.setAutoRemove(false);
    // 0600：多用户 POSIX 下默认 0644 会让同机其他用户读到收件人公钥列表
    recTmp.setPermissions(QFileDevice::ReadOwner|QFileDevice::WriteOwner);
    // 无参 open() 是 public；带参重载在 QTemporaryFile 里是 protected
    if(!recTmp.open()) return QString();
    QByteArray blob;
    for(const QString& k:parts) blob+=(k+QLatin1Char('\n')).toUtf8();
    if(recTmp.write(blob)!=static_cast<qint64>(blob.size())) {
        recTmp.close();
        QFile::remove(recTmp.fileName());
        return QString();
    }
    recTmp.close();
    m_recipientTempFile=recTmp.fileName();
    return m_recipientTempFile;
}

// 运行
void MainWindow::onRunClicked() {
    if(!checkCliExists(true)) {
        return;
    }

    if(m_fileEncryptorPath.isEmpty()) {
        m_fileEncryptorPath=FileEncryptorLocator::locate();
        if(m_fileEncryptorPath.isEmpty()) {
            showCliNotFoundError(tr("运行前检测"));
            return;
        }
    }

    ShellOptions o=collectOptions();

    // 多收件人写成临时文件失败时不能把含逗号的原文当 -r 值下发
    if(!o.recipientPath.trimmed().isEmpty()) {
        const QString recipFile=resolveRecipients(o.recipientPath);
        if(recipFile.isEmpty()) {
            MsgBox::warn(this, tr("收件人列表写入失败"),
                tr("无法创建收件人列表的临时文件（权限不足或临时目录不可写）。\n任务已取消。"));
            return;
        }
        o.recipientPath=recipFile;
    }

    // 包装动作与 -m 正交：模式下拉此时是隐藏的残留值，不能拿它做可用性判断
    const bool isWrapAct=(o.action==CryptoAction::WrapKey||o.action==CryptoAction::UnwrapKey);
    if(!isWrapAct && o.mode==CryptoMode::Aegis256 && !m_aegisAvailable) {
        MsgBox::error(this, tr("AEGIS-256 不可用"),
            tr("当前 CPU 不支持 AES-NI，AEGIS-256 在此环境下会极慢且抗侧信道能力弱。\n"
               "请改用 XChaCha20-Poly1305（默认模式）。"));
        return;
    }

    if(!isWrapAct && o.mode==CryptoMode::Sm4 && !m_sm4Available) {
        MsgBox::error(this, tr("SM4-GCM 不可用"),
            tr("当前 CLI 未编译 OpenSSL 支持（--features 中 sm4=0），SM4-GCM 无法使用。\n"
               "请改用 XChaCha20-Poly1305（默认模式）。"));
        return;
    }

    if(!isWrapAct && o.mode==CryptoMode::AesGcm && !m_aesGcmAvailable) {
        MsgBox::error(this, tr("AES-256-GCM 不可用"),
            tr("当前 CPU 不支持 AES-NI，AES-256-GCM 无法使用（--features 中 aesgcm=0）。\n"
               "请改用 XChaCha20-Poly1305（默认模式）。"));
        return;
    }

    if(isWrapAct && !m_keywrapAvailable) {
        MsgBox::error(this, tr("密钥包装不可用"),
            tr("配套的命令行程序没有密钥包装能力，无法包装或解开密钥。\n"
               "请更换带 OpenSSL 的 CLI。"));
        return;
    }

    const bool isKeyGen=(o.action==CryptoAction::KeyGen);
    const bool isDerive=(o.action==CryptoAction::Derive);
    const bool isPubKey=(o.action==CryptoAction::PubKey);
    const bool isWrap=(o.action==CryptoAction::WrapKey);
    const bool isUnwrap=(o.action==CryptoAction::UnwrapKey);
    const bool noInputNeeded=(isKeyGen||isDerive||isPubKey);
    // 包装动作的输入走「包装文件」行，文件清单不参与
    if(!noInputNeeded && !isWrap && !isUnwrap && o.inputPaths.isEmpty()) {
        MsgBox::warn(this,tr("缺少输入"),tr("请先添加文件或目录。"));
        return;
    }
    bool isBatch=(o.action==CryptoAction::BatchEncrypt||
        o.action==CryptoAction::BatchDecrypt);
    bool isEnc=(o.action==CryptoAction::Encrypt||o.action==CryptoAction::BatchEncrypt);
    if(isWrapAct) {
        // 包装输入是单个文件，不走文件清单；缺路径或路径不存在都在这里拦下
        if(o.wrapInput.isEmpty()) {
            MsgBox::warn(this, tr("缺少密钥文件"),
                isWrap ? tr("请先选择要包装的 32 字节数据密钥文件。")
                       : tr("请先选择要解开的 .fekw 包装文件。"));
            if(m_wrapFileEdit) m_wrapFileEdit->setFocus();
            return;
        }
        if(!QFileInfo::exists(o.wrapInput)) {
            MsgBox::warn(this, tr("文件不存在"), tr("找不到：%1").arg(o.wrapInput));
            if(m_wrapFileEdit) m_wrapFileEdit->setFocus();
            return;
        }
    }
    if(!isBatch&&!o.pack&&!isWrapAct&&o.inputPaths.size()>1) {
        MsgBox::warn(this,tr("输入过多"),
            tr("单文件模式只接受一个输入路径，请清空后只选一个，勾选「打包为单个容器」，或改用批量模式。"));
        return;
    }
    // 目录 + 删除类源处置：整棵树都会被清掉，动手前必须确认一次。
    // 确认通过后下发 --source-delete-ok，免得 CLI 再问一遍（问第二遍用户会懵）。
    if(isEnc && !o.pack && o.sourceDisposition!=0) {
        QStringList dirs;
        for(const QString& p : o.inputPaths) {
            if(QFileInfo(p).isDir()) dirs<<p;
        }
        if(!dirs.isEmpty()) {
            const int disp=o.sourceDisposition;
            const QString how = disp==2 ? tr("安全擦除（多次覆写）")
                             : disp==3 ? tr("移入回收站")
                             : tr("删除");
            QStringList show=dirs.mid(0,5);
            // 与 CLI 行为对齐：-de 只逐个删除目录树里的文件，空目录壳保留
            QString msg=tr("加密完成后，以下源目录中的文件将被%1（目录本身保留），此操作不可撤销：\n\n%2")
                             .arg(how)
                             .arg(show.join('\n'));
            if(dirs.size()>show.size()) {
                msg+=QStringLiteral("\n\n... ")
                    +tr("另有 %1 个目录").arg(dirs.size()-show.size());
            }
            if(!MsgBox::confirm(this,tr("确认删除源目录"),msg)) {
                return;
            }
            o.sourceDeleteOk=true;
        }
    }
    // 非对称判定对解密同样成立：解密不看模式，只认「私钥文件」入口
    const bool asymDecrypt=(!isEnc)&&!noInputNeeded&&!isWrapAct&&
        (o.action==CryptoAction::Decrypt||o.action==CryptoAction::BatchDecrypt);
    // 包装动作不参与非对称判定：模式下拉此时隐藏，残留值不代表用户的加密意图
    const bool isAsym=(!isWrapAct)&&(((o.mode==CryptoMode::Asymmetric)&&!noInputNeeded)||asymDecrypt);
    if(isKeyGen) {
    } else if(isDerive) {
    } else if(isPubKey) {
        if(o.identityPath.isEmpty()) {
            MsgBox::warn(this,tr("缺少私钥"),
                tr("请先在「私钥文件」中选择包含 AGE-SECRET-KEY-... 的文件。"));
            m_identityEdit->setFocus();
            return;
        }
    } else if(isWrapAct&&o.wrapAlg==WrapAlg::Pubkey) {
        const bool empty=isWrap ? o.recipientPath.isEmpty() : o.identityPath.isEmpty();
        if(empty) {
            MsgBox::warn(this, tr("缺少密钥材料"),
                isWrap ? tr("公钥包装需要收件人公钥：粘贴公钥串或选择一个含公钥的文件。")
                       : tr("公钥解包需要当初收件人的身份私钥文件。"));
            (isWrap ? m_recipientEdit : m_identityEdit)->setFocus();
            return;
        }
    } else if(isAsym) {
        if(isEnc) {
            if(o.recipientPath.isEmpty()) {
                MsgBox::warn(this,tr("缺少公钥"),
                    tr("非对称加密需要公钥：粘贴 age1... 或选择一个含公钥的文件 (-r)。"));
                m_recipientEdit->setFocus();
                return;
            }
        } else {
            if(o.identityPath.isEmpty()) {
                MsgBox::warn(this,tr("缺少私钥"),
                    tr("非对称解密需要身份私钥文件。"));
                m_identityEdit->setFocus();
                return;
            }
        }
    }

    // 口令弹窗
    const bool wrapPassword=isWrapAct && o.wrapAlg!=WrapAlg::Pubkey
        && o.keyfilePath.isEmpty();
    bool symNeedsPassword = wrapPassword || (!isAsym && o.keyfilePath.isEmpty()
        && (o.action==CryptoAction::Encrypt || o.action==CryptoAction::BatchEncrypt
            || o.action==CryptoAction::Decrypt || o.action==CryptoAction::BatchDecrypt
            || o.action==CryptoAction::Derive));
    std::vector<unsigned char> pw;
    if(symNeedsPassword) {
        if(o.action==CryptoAction::BatchDecrypt) {
            o.restoreName = MsgBox::confirm(this, tr("批量解密文件名"),
                tr("批量解密将对每个文件执行昂贵的密钥派生（KDF）以还原完整原始文件名，可能很慢。\n"
                   "是否启用「完整文件名还原」？\n（无论是否启用，输出文件的扩展名都会保留。）"));
        }
        PasswordDialog dlg(this);
        dlg.setPurpose(isDerive ? tr("口令派生")
            : isWrap ? tr("包装口令")
            : isUnwrap ? tr("解包口令")
            : (isEnc ? tr("加密口令") : tr("解密口令")));
        // 解密与解包都只输一次：原文只有确认，无法确认它与本次输入一致
        dlg.setRequireConfirm(o.action==CryptoAction::Encrypt
            || o.action==CryptoAction::BatchEncrypt || o.action==CryptoAction::Derive
            || o.action==CryptoAction::WrapKey);
        if(dlg.exec()!=QDialog::Accepted) return;
        pw = dlg.takePassword();
        if(pw.empty()) return;
    }

    CommandRequest req;
    req.programPath=m_fileEncryptorPath;
    req.arguments=CliArgBuilder::buildArguments(o);
    req.extraEnv=CliArgBuilder::buildEnvironment(o);
    // 签名私钥临时文件落盘失败时 buildArguments 返回空：中止并说明原因，
    // 不要拿空参数去启动 CLI（那只会弹用法，用户看不出真实原因）
    if(req.arguments.isEmpty()) {
        MsgBox::warn(this, tr("水印签名失败"),
            tr("无法创建水印签名私钥的临时文件（权限不足或临时目录不可写）。\n任务已取消，私钥不会被传给命令行。"));
        return;
    }
    {
        QTemporaryFile statsTmp(QDir::tempPath()+QStringLiteral("/fe_stats_XXXXXX"));
        statsTmp.setAutoRemove(false);
        statsTmp.setPermissions(QFileDevice::ReadOwner|QFileDevice::WriteOwner);
        if(statsTmp.open()) {
            m_statsFile=statsTmp.fileName();
            statsTmp.close();
        }
    }
    req.extraEnv.insert(QStringLiteral("FILEENCRYPTOR_STATS_FILE"),m_statsFile);
    // 确认握手：CLI 把 y/n 询问写进这个文件，界面读到后弹窗，再把答案写回去。
    // 走文件是因为 stdin 已被 --key-stdin 读到 EOF，CLI 那边没法再从 stdin 收答案。
    {
        QTemporaryFile confirmTmp(QDir::tempPath()+QStringLiteral("/fe_confirm_XXXXXX"));
        confirmTmp.setAutoRemove(false);
        confirmTmp.setPermissions(QFileDevice::ReadOwner|QFileDevice::WriteOwner);
        if(confirmTmp.open()) {
            m_confirmFile=confirmTmp.fileName();
            confirmTmp.close();
        }
        QFile::remove(m_confirmFile);
    }
    if(!m_confirmFile.isEmpty()) {
        req.confirmFile=m_confirmFile;
        req.extraEnv.insert(QString::fromLatin1(feConfirmFileEnv()),m_confirmFile);
    }
    if(o.action==CryptoAction::BatchEncrypt||o.action==CryptoAction::BatchDecrypt) {
        req.extraEnv.insert(QStringLiteral("FILEENCRYPTOR_PROGRESS_FRAME"),QStringLiteral("1"));
        const QFontMetrics fm(m_outputView->font());
        const int cw=fm.horizontalAdvance(QLatin1Char('M'));
        int cols=cw>0?(m_outputView->viewport()->width()-8)/cw:100;
        cols=qBound(60,cols,200);
        req.extraEnv.insert(QStringLiteral("COLUMNS"),QString::number(cols));
    }

    // 公钥路线没有口令可注入；包装动作的口令同样走 --key-stdin
    if(!(isKeyGen||isPubKey) && !isAsym && o.keyfilePath.isEmpty() && !pw.empty()) {
        req.stdinData=QByteArray(reinterpret_cast<const char*>(pw.data()),(int)pw.size());
    }

    if(!pw.empty()) {
        secure_zero(pw.data(),pw.size());
        pw.clear();
    }

    m_outputView->clear();
    const QString preview=CliArgBuilder::buildPreview(m_fileEncryptorPath,o);
    appendOutput(QStringLiteral(">>> %1\n").arg(preview),false);
    appendOutput(tr("--- 执行开始 ---")+QStringLiteral("\n"),false);

    m_btnRun->setEnabled(false);
    m_btnCancel->setEnabled(true);
    m_runFileStarts=0;
    m_doneFiles=0; m_skipFiles=0; m_failFiles=0; m_totalFiles=0;
    m_currentFile.clear();
    m_frameBlock=QTextBlock();
    m_frameLen=0;
    updateProgressLabel();
    setStatus(tr("运行中..."));

    beginTaskRecord(o);

    m_executor->execute(req);
    if(!req.stdinData.isEmpty()) {
        secure_zero(req.stdinData.data(),(size_t)req.stdinData.size());
        req.stdinData.clear();
    }
}

// CLI 请求确认：同步弹窗，答完立刻写回握手文件让 CLI 继续
void MainWindow::onConfirmPrompt(const QString& text) {
    if(!m_executor) return;
    const bool yes=MsgBox::confirm(this,tr("需要确认"),text);
    m_executor->answerConfirm(yes);
}

// 密钥轮换
void MainWindow::onRewrapClicked() {
    if(!checkCliExists(true)) return;
    if(m_fileEncryptorPath.isEmpty()) {
        m_fileEncryptorPath=FileEncryptorLocator::locate();
        if(m_fileEncryptorPath.isEmpty()) { showCliNotFoundError(tr("密钥轮换")); return; }
    }
    if(m_executor&&m_executor->isRunning()) {
        MsgBox::warn(this,tr("正在运行"),tr("请等待当前任务结束或先取消。"));
        return;
    }

    const QString file=QFileDialog::getOpenFileName(this,
        tr("选择要轮换密钥的加密容器"),QString(),
        tr("加密容器 (*.ptd);;所有文件 (*)"));
    if(file.isEmpty()) return;

    std::vector<unsigned char> oldPw;
    {
        PasswordDialog dlg(this);
        dlg.setPurpose(tr("旧口令（当前容器口令）"));
        dlg.setRequireConfirm(false);
        if(dlg.exec()!=QDialog::Accepted) return;
        oldPw=dlg.takePassword();
        if(oldPw.empty()) return;
    }
    std::vector<unsigned char> newPw;
    {
        PasswordDialog dlg(this);
        dlg.setPurpose(tr("新口令（轮换后）"));
        dlg.setRequireConfirm(true);
        if(dlg.exec()!=QDialog::Accepted) {
            secure_zero(oldPw.data(),oldPw.size()); oldPw.clear();
            return;
        }
        newPw=dlg.takePassword();
        if(newPw.empty()) {
            secure_zero(oldPw.data(),oldPw.size()); oldPw.clear();
            return;
        }
    }

    QTemporaryFile rewTmp(QDir::tempPath()+QStringLiteral("/fileencryptor_rewrap_XXXXXX"));
    rewTmp.setAutoRemove(false);
    if(!rewTmp.open()) {
        MsgBox::error(this,tr("密钥轮换"),tr("无法写入临时新口令文件。"));
        secure_zero(oldPw.data(),oldPw.size()); oldPw.clear();
        secure_zero(newPw.data(),newPw.size()); newPw.clear();
        return;
    }
    rewTmp.setPermissions(QFileDevice::ReadOwner|QFileDevice::WriteOwner);
    rewTmp.write(reinterpret_cast<const char*>(newPw.data()),(qint64)newPw.size());
    rewTmp.flush();
    const bool rewOk=(rewTmp.error()==QFile::NoError);
    const QString tmp=rewTmp.fileName();
    rewTmp.close();
    if(!rewOk) {
        QFile::remove(tmp);
        MsgBox::error(this,tr("密钥轮换"),tr("无法落盘临时新口令文件。"));
        secure_zero(oldPw.data(),oldPw.size()); oldPw.clear();
        secure_zero(newPw.data(),newPw.size()); newPw.clear();
        return;
    }
    secure_zero(newPw.data(),newPw.size()); newPw.clear();

    CommandRequest req;
    req.programPath=m_fileEncryptorPath;
    req.arguments<<QStringLiteral("--rewrap")<<file
                 <<QStringLiteral("--key-stdin")
                 <<QStringLiteral("--new-key-file")<<tmp;
    req.stdinData=QByteArray(reinterpret_cast<const char*>(oldPw.data()),(int)oldPw.size());
    secure_zero(oldPw.data(),oldPw.size()); oldPw.clear();

    m_rewrapTempKey=tmp;
    m_outputView->clear();
    appendOutput(QStringLiteral(">>> %1 --rewrap \"%2\" --key-stdin --new-key-file \"%3\"\n")
        .arg(m_fileEncryptorPath,file,tmp),false);
    appendOutput(tr("--- 密钥轮换（载荷密文不动） ---")+QStringLiteral("\n"),false);

    m_btnRun->setEnabled(false);
    if(m_btnRewrap) m_btnRewrap->setEnabled(false);
    m_btnCancel->setEnabled(true);
    setStatus(tr("密钥轮换中..."));
    m_executor->execute(req);
    if(!req.stdinData.isEmpty()) {
        secure_zero(req.stdinData.data(),(size_t)req.stdinData.size());
        req.stdinData.clear();
    }
}

void MainWindow::onCancelClicked() {
    if(m_executor->isRunning()) {
        appendOutput(tr("\n--- 用户取消，正在终止子进程... ---\n"),true);
        m_executor->cancel();
    }
}

// 执行回显
void MainWindow::onOutputLine(const OutputLine& line) {
    if(line.isFrame) {
        m_pendingFrame=line;
        m_framePending=true;
        if(!m_frameTimer->isActive()) m_frameTimer->start();
        return;
    }
    if(line.isProgress) {
        const unsigned int rgb=line.isError ? ThemeManager::stderrColorRGB()
            : ThemeManager::stdoutColorRGB();
        QTextCharFormat fmt;
        fmt.setForeground(QColor((rgb>>16)&0xFF,(rgb>>8)&0xFF,rgb&0xFF));
        QTextCursor cur=m_outputView->textCursor();
        cur.movePosition(QTextCursor::End);
        if(m_lastProgressLine) {
            cur.movePosition(QTextCursor::StartOfLine);
            cur.movePosition(QTextCursor::EndOfLine,QTextCursor::KeepAnchor);
            cur.insertText(line.text,fmt);
        } else {
            cur.insertText(QStringLiteral("\n")+line.text,fmt);
        }
        m_lastProgressLine=true;
        QScrollBar* bar=m_outputView->verticalScrollBar();
        bar->setValue(bar->maximum());
        return;
    }
    m_lastProgressLine=false;
    if(line.text.startsWith(QLatin1String("Encrypting: "))||
       line.text.startsWith(QLatin1String("Decrypting: "))) {
        ++m_runFileStarts;
        m_currentTask.filesDone=m_runFileStarts;
        const int arrow=line.text.indexOf(QStringLiteral(" -> "));
        m_currentFile=(arrow>0) ? line.text.mid(12,arrow-12).trimmed()
                                : line.text.mid(12).trimmed();
        updateProgressLabel();
    }
    else if(line.text.startsWith(QLatin1String("Skipped: "))) {
        ++m_skipFiles;
        updateProgressLabel();
    }
    else if(line.text.startsWith(QLatin1String("Failed: "))&&
            line.text.contains(QStringLiteral("skipped, continuing"))) {
        ++m_failFiles;
        updateProgressLabel();
    }
    else if(line.text.contains(QStringLiteral("non-.ptd file(s) in batch decrypt"))) {
        static const QRegularExpression re(QStringLiteral("Skipped\\s+(\\d+)\\s+non"));
        const auto m=re.match(line.text);
        if(m.hasMatch()) { m_skipFiles+=m.captured(1).toInt(); updateProgressLabel(); }
    }
    appendOutput(line.text+QStringLiteral("\n"),line.isError);
}

void MainWindow::flushPendingFrame() {
    if(!m_framePending) return;
    m_framePending=false;
    renderFrameLine(m_pendingFrame);
}

void MainWindow::renderFrameLine(const OutputLine& line) {
    QStringList lines=line.text.split(QLatin1Char('\n'));
    while(!lines.isEmpty()&&lines.last().trimmed().isEmpty()) lines.removeLast();
    if(lines.isEmpty()) return;

    static const QRegularExpression reFiles(
        QStringLiteral("FILES\\s+(\\d+)/(\\d+)\\s+SKIP\\s+(\\d+)\\s+FAIL\\s+(\\d+)"));
    QStringList current;
    for(const QString& ln : lines) {
        const auto m=reFiles.match(ln);
        if(m.hasMatch()) {
            m_doneFiles=m.captured(1).toInt();
            m_totalFiles=m.captured(2).toInt();
            m_skipFiles=m.captured(3).toInt();
            m_failFiles=m.captured(4).toInt();
            continue;
        }
        const int sep=ln.indexOf(QStringLiteral(" | "));
        if(sep<=0) continue;
        const QString name=ln.left(sep).trimmed();
        if(!name.isEmpty()&&name!=QLatin1String("-")&&!current.contains(name))
            current.append(name);
    }
    if(!current.isEmpty()) m_currentFile=current.join(QStringLiteral(", "));
    updateProgressLabel();

    const QString block=lines.join(QLatin1Char('\n'))+QLatin1Char('\n');
    const unsigned int rgb=ThemeManager::stdoutColorRGB();
    QTextCharFormat fmt;
    fmt.setForeground(QColor((rgb>>16)&0xFF,(rgb>>8)&0xFF,rgb&0xFF));

    bool replaced=false;
    if(m_frameBlock.isValid()&&m_frameLen>0) {
        const int pos=m_frameBlock.position();
        const int docLen=m_outputView->document()->characterCount();
        if(pos>=0&&pos+m_frameLen<=docLen
           &&m_outputView->document()->characterAt(pos)==QLatin1Char('T')) {
            QTextCursor sel(m_outputView->document());
            sel.setPosition(pos);
            sel.setPosition(pos+m_frameLen,QTextCursor::KeepAnchor);
            sel.insertText(block,fmt);
            replaced=true;
        }
    }
    if(!replaced) {
        QTextCursor cur=m_outputView->textCursor();
        cur.movePosition(QTextCursor::End);
        const int base=cur.position();
        cur.insertText(QStringLiteral("\n")+block,fmt);
        QTextCursor anchor(m_outputView->document());
        anchor.setPosition(base+1);
        m_frameBlock=anchor.block();
    }
    m_frameLen=block.size();
    m_lastProgressLine=false;
    QScrollBar* bar=m_outputView->verticalScrollBar();
    bar->setValue(bar->maximum());
}

void MainWindow::updateProgressLabel() {
    if(!m_progressLabel) return;
    QString full;
    if(m_executor&&m_executor->isRunning()) {
        const QString cur=m_currentFile.isEmpty()?tr("—"):m_currentFile;
        full=tr("当前: %1 | 完成 %2/%3 | 跳过 %4 | 失败 %5")
                .arg(cur).arg(m_doneFiles).arg(m_totalFiles)
                .arg(m_skipFiles).arg(m_failFiles);
    }
    else if(m_pendingFiles>0) {
        full=tr("待处理: %1 个文件 / %2").arg(m_pendingFiles)
                .arg(EtaEstimator::formatBytes(m_pendingBytes));
    }
    else {
        full=tr("就绪");
    }
    QFontMetrics fm(m_progressLabel->font());
    m_progressLabel->setText(fm.elidedText(full,Qt::ElideMiddle,540));
    m_progressLabel->setToolTip(full);
}

void MainWindow::onCommandFinished(const CommandResult& r) {
    m_btnRun->setEnabled(true);
    if(m_btnRewrap) m_btnRewrap->setEnabled(true);
    m_btnCancel->setEnabled(false);
    if(!m_rewrapTempKey.isEmpty()) {
        QFile::remove(m_rewrapTempKey);
        m_rewrapTempKey.clear();
    }
    // 任务结束即清理，避免公钥临时文件与统计 JSON 滞留到关窗口
    if(!m_recipientTempFile.isEmpty()) {
        QFile::remove(m_recipientTempFile);
        m_recipientTempFile.clear();
    }
    if(m_framePending) flushPendingFrame();
    finishTaskRecord(r);   // 内部要读 m_statsFile，故统计文件在其后清理
    if(!m_statsFile.isEmpty()) {
        QFile::remove(m_statsFile);
        m_statsFile.clear();
    }

    QString summary;
    if(r.wasCancelled) {
        const int preserved=qMax(0,m_runFileStarts-1);
        summary=tr("--- 已取消（退出码 %1）：已保留 %2 个已完成文件的输出，"
                   "重跑同一任务将从 .prs 续传未完成部分 ---")
                    .arg(r.exitCode).arg(preserved);
        setStatus(tr("已取消（已保留 %1 个文件）").arg(preserved));
    }
    else if(!r.errorString.isEmpty()) {
        summary=tr("--- 执行失败：%1 ---").arg(r.errorString);
        setStatus(tr("失败：%1").arg(r.errorString));
    }
    else if(r.exitCode==0) {
        summary=tr("--- 执行成功（退出码 0） ---");
        setStatus(tr("完成"));
    }
    else {
        summary=tr("--- 执行结束（退出码 %1） ---").arg(r.exitCode);
        setStatus(tr("结束（退出码 %1）").arg(r.exitCode));
    }
    if(m_failFiles>0||m_skipFiles>0) {
        summary+=tr("\n（完成 %1 / 跳过 %2 / 失败 %3）")
                    .arg(m_doneFiles).arg(m_skipFiles).arg(m_failFiles);
    }
    appendOutput(QStringLiteral("\n%1\n").arg(summary),r.exitCode!=0);
    resetPendingCache();
    recomputePending();
    updateProgressLabel();

    bool showedSummary=false;
    if(!r.wasCancelled && (m_doneFiles>0||m_failFiles>0)) {
        qint64 encSize=0;
        const QString outDir=m_outDirEdit->text().trimmed();
        if(!outDir.isEmpty()&&QFileInfo(outDir).isDir()) {
            QDirIterator it(outDir,QStringList()<<QStringLiteral("*.ptd"),QDir::Files,QDirIterator::Subdirectories);
            while(it.hasNext()) { it.next(); encSize+=it.fileInfo().size(); }
        }
        const qint64 durMs=m_runTimer.isValid()?m_runTimer.elapsed():0;
        const double avgSpeed=(durMs>0&&m_pendingBytes>0)
            ? static_cast<double>(m_pendingBytes)/(static_cast<double>(durMs)/1000.0) : 0.0;
        const QString durStr=durMs>=3600000 ? QStringLiteral("%1h%2m").arg(durMs/3600000).arg((durMs%3600000)/60000)
                      : durMs>=60000 ? QStringLiteral("%1m%2s").arg(durMs/60000).arg((durMs%60000)/1000)
                      : QStringLiteral("%1s").arg(durMs/1000);
        const QString speedStr=avgSpeed>=1073741824?QStringLiteral("%1 GB/s").arg(avgSpeed/1073741824.0,0,'f',2)
                      : avgSpeed>=1048576?QStringLiteral("%1 MB/s").arg(avgSpeed/1048576.0,0,'f',1)
                      : avgSpeed>=1024?QStringLiteral("%1 KB/s").arg(avgSpeed/1024.0,0,'f',0)
                      : QStringLiteral("%1 B/s").arg((qint64)avgSpeed);
        const QString encStr=encSize>=1073741824?QStringLiteral("%1 GB").arg(encSize/1073741824.0,0,'f',2)
                      : encSize>=1048576?QStringLiteral("%1 MB").arg(encSize/1048576.0,0,'f',1)
                      : encSize>=1024?QStringLiteral("%1 KB").arg(encSize/1024.0,0,'f',0)
                      : QStringLiteral("%1 B").arg(encSize);
        TaskSummaryDialog dlg(tr("任务完成"),durStr,speedStr,encStr,
                              m_doneFiles,m_skipFiles,m_failFiles,this);
        dlg.exec();
        showedSummary=true;   // 已弹汇总框，不再重复弹消息框/托盘通知
    }

    // 已弹汇总框时不再重复通知
    if(!showedSummary) {
        const QString notifyTitle = tr("任务完成");
        const QString notifyBody = summary.remove(QStringLiteral("---")).trimmed();
        if (isActiveWindow()) {
            QMessageBox::information(this, notifyTitle, notifyBody);
        } else if (m_trayIcon && QSystemTrayIcon::isSystemTrayAvailable()) {
            m_trayIcon->showMessage(notifyTitle, notifyBody, QSystemTrayIcon::Information, 5000);
        }
    }
}

// 任务历史与进度
QString MainWindow::actionKey(CryptoAction a) {
    switch(a) {
        case CryptoAction::Encrypt:       return QStringLiteral("encrypt");
        case CryptoAction::Decrypt:       return QStringLiteral("decrypt");
        case CryptoAction::BatchEncrypt:  return QStringLiteral("batch-encrypt");
        case CryptoAction::BatchDecrypt:  return QStringLiteral("batch-decrypt");
        case CryptoAction::KeyGen:        return QStringLiteral("keygen");
        case CryptoAction::Derive:        return QStringLiteral("derive");
        case CryptoAction::PubKey:        return QStringLiteral("pubkey");
        case CryptoAction::WrapKey:       return QStringLiteral("wrap");
        case CryptoAction::UnwrapKey:     return QStringLiteral("unwrap");
    }
    return QStringLiteral("encrypt");
}

QString MainWindow::modeKey(CryptoMode m) {
    switch(m) {
        case CryptoMode::XChaCha20:   return QStringLiteral("xchacha20");
        case CryptoMode::Aegis256:    return QStringLiteral("aegis256");
        case CryptoMode::AesGcm:      return QStringLiteral("aes-gcm");
        case CryptoMode::Sm4:         return QStringLiteral("sm4");
        case CryptoMode::Asymmetric:  return QStringLiteral("asymmetric");
    }
    return QStringLiteral("xchacha20");
}

// 包装算法存的是 CLI 的 --wrap-alg 取值，回放时按同名还原下拉
static QString wrapAlgKey(WrapAlg a) {
    switch(a) {
        case WrapAlg::AesKw:  return QStringLiteral("aes-kw");
        case WrapAlg::Pubkey: return QStringLiteral("pubkey");
        case WrapAlg::Kwp:    return QStringLiteral("kwp");
    }
    return QStringLiteral("kwp");
}

static WrapAlg wrapAlgFromKey(const QString& s) {
    if(s==QStringLiteral("aes-kw")) return WrapAlg::AesKw;
    if(s==QStringLiteral("pubkey")) return WrapAlg::Pubkey;
    return WrapAlg::Kwp;
}

static ScanResult scanInputs(const QStringList& paths,
                             std::shared_ptr<const QHash<QString,DirStat>> cache,
                             std::shared_ptr<std::atomic<bool>> cancel) {
    ScanResult r;
    auto cancelled=[&]{ return cancel && cancel->load(std::memory_order_relaxed); };
    for(const QString& p : paths) {
        if(cancelled()) { r.complete=false; return r; }
        auto hit=cache->constFind(p);
        if(hit!=cache->constEnd()) {
            r.bytes+=hit->bytes;
            r.files+=hit->files;
            continue;
        }
        qint64 b=0;
        int f=0;
        const QFileInfo fi(p);
        if(fi.isFile()) {
            b=fi.size();
            f=1;
        }
        else if(fi.isDir()) {
            QDirIterator it(p,QDir::Files,QDirIterator::Subdirectories);
            while(it.hasNext()) {
                if(cancelled()) { r.complete=false; return r; }
                it.next();
                b+=it.fileInfo().size();
                ++f;
            }
        }
        r.bytes+=b;
        r.files+=f;
        r.entries.insert(p,DirStat{b,f});
    }
    return r;
}

void MainWindow::recomputePending() {
    if(!m_pendingTimer) return;
    m_pendingTimer->start();
}

void MainWindow::resetPendingCache() {
    m_dirCache.clear();
}

void MainWindow::startPendingScan() {
    if(m_scanWatcher->isRunning()) {
        if(m_scanCancel) m_scanCancel->store(true,std::memory_order_relaxed);
        m_scanRestartPending=true;
        return;
    }
    m_scanCancel=std::make_shared<std::atomic<bool>>(false);
    auto cancel=m_scanCancel;
    const QStringList paths=collectOptions().inputPaths;
    auto cache=std::make_shared<const QHash<QString,DirStat>>(m_dirCache);
    m_scanWatcher->setFuture(QtConcurrent::run(
        [paths,cache,cancel]{ return scanInputs(paths,cache,cancel); }));
}

void MainWindow::onPendingScanFinished() {
    const ScanResult r=m_scanWatcher->result();
    if(m_scanRestartPending) {
        m_scanRestartPending=false;
        startPendingScan();
        return;
    }
    if(!r.complete) return;
    m_pendingBytes=r.bytes;
    m_pendingFiles=r.files;
    for(auto it=r.entries.constBegin();it!=r.entries.constEnd();++it)
        m_dirCache.insert(it.key(),it.value());
    updateProgressLabel();
}

void MainWindow::beginTaskRecord(const ShellOptions& o) {
    m_currentTask=TaskRecord();
    m_currentTask.id=TaskHistory::newId();
    m_currentTask.startedAt=QDateTime::currentDateTime()
        .toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"));
    m_currentTask.action=actionKey(o.action);
    m_currentTask.actionLabel=TaskHistory::actionLabel(m_currentTask.action);
    m_currentTask.mode=modeKey(o.mode);
    if(o.mode==CryptoMode::Asymmetric) m_currentTask.fileCipher=modeKey(o.fileMode);
    m_currentTask.inputCount=o.inputPaths.size();
    m_currentTask.inputPaths=o.inputPaths;
    m_currentTask.totalBytes=m_pendingBytes;
    m_currentTask.outputDir=o.outputDir;
    m_currentTask.sourceIndex=o.sourceDisposition;
    m_currentTask.force=o.forceOverwrite;
    m_currentTask.sha256=o.writeSha256;
    m_currentTask.compress=o.compress;
    m_currentTask.compressionLevel=o.compressionLevel;
    m_currentTask.pqc=o.pqc;
    m_currentTask.watermark=o.watermark;
    // 明文私钥不写进任务记录，恢复任务时由用户重新输入
    m_currentTask.watermarkKey=CliArgBuilder::isPrivateKeyMaterial(o.watermarkKeyPath)
        ? QStringLiteral("<protected>") : o.watermarkKeyPath;
    m_currentTask.keyfile=o.keyfilePath;
    m_currentTask.recipient=o.recipientPath;
    m_currentTask.identity=o.identityPath;
    m_currentTask.wrapInput=o.wrapInput;
    m_currentTask.wrapOutput=o.wrapOutput;
    m_currentTask.wrapAlg=(o.action==CryptoAction::WrapKey||o.action==CryptoAction::UnwrapKey)
        ? wrapAlgKey(o.wrapAlg) : QString();
    m_currentTask.restoreName=o.restoreName;
    m_runTimer.start();
}

void MainWindow::finishTaskRecord(const CommandResult& r) {
    if(m_currentTask.id.isEmpty()) return;
    m_currentTask.finishedAt=QDateTime::currentDateTime()
        .toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"));
    m_currentTask.durationMs=m_runTimer.isValid() ? m_runTimer.elapsed() : 0;
    if(!m_statsFile.isEmpty()&&QFile::exists(m_statsFile)) {
        QFile sf(m_statsFile);
        if(sf.open(QIODevice::ReadOnly|QIODevice::Text)) {
            const QJsonDocument sd=QJsonDocument::fromJson(sf.readAll());
            if(sd.isObject()) {
                const QJsonObject so=sd.object();
                m_currentTask.filesDone=so.value(QStringLiteral("files_done")).toInt(m_doneFiles);
                m_currentTask.filesSkip=so.value(QStringLiteral("files_skipped")).toInt(m_skipFiles);
                m_currentTask.filesFail=so.value(QStringLiteral("files_failed")).toInt(m_failFiles);
                m_doneFiles=m_currentTask.filesDone;
                m_skipFiles=m_currentTask.filesSkip;
                m_failFiles=m_currentTask.filesFail;
            }
            sf.close();
        }
        QFile::remove(m_statsFile);
    } else {
        m_currentTask.filesDone=(m_doneFiles>0||m_failFiles>0||m_skipFiles>0)
            ? m_doneFiles : m_runFileStarts;
        m_currentTask.filesSkip=m_skipFiles;
        m_currentTask.filesFail=m_failFiles;
    }
    m_currentTask.exitCode=r.exitCode;
    m_currentTask.cancelled=r.wasCancelled;
    m_currentTask.error=r.errorString;
    m_currentTask.status=r.wasCancelled
        ? QStringLiteral("cancelled")
        : ((!r.errorString.isEmpty()||r.exitCode!=0) ? QStringLiteral("failed")
                                                     : QStringLiteral("success"));
    CliArgBuilder::cleanupWatermarkTemp();
    const TaskRecord done=m_currentTask;
    m_currentTask=TaskRecord();
    QString err;
    if(!TaskHistory::append(done,err))
        appendOutput(tr("（警告：任务历史写入失败：%1）\n").arg(err),true);
}

void MainWindow::onOpenTaskHistory() {
    TaskHistoryDialog dlg(this);
    if(dlg.exec()!=QDialog::Accepted) return;
    const TaskRecord rec=dlg.selectedRecord();
    if(rec.id.isEmpty()) return;
    applyTaskRecord(rec);
}

void MainWindow::applyTaskRecord(const TaskRecord& rec) {
    auto setAction=[&](CryptoAction a){
        if(QAbstractButton* b=m_actionGroup->button(static_cast<int>(a))) b->setChecked(true);
    };
    if(rec.action==QStringLiteral("encrypt"))             setAction(CryptoAction::Encrypt);
    else if(rec.action==QStringLiteral("decrypt"))        setAction(CryptoAction::Decrypt);
    else if(rec.action==QStringLiteral("batch-encrypt"))  setAction(CryptoAction::BatchEncrypt);
    else if(rec.action==QStringLiteral("batch-decrypt"))  setAction(CryptoAction::BatchDecrypt);
    else if(rec.action==QStringLiteral("keygen"))         setAction(CryptoAction::KeyGen);
    else if(rec.action==QStringLiteral("derive"))         setAction(CryptoAction::Derive);
    else if(rec.action==QStringLiteral("pubkey"))         setAction(CryptoAction::PubKey);
    else if(rec.action==QStringLiteral("wrap"))           setAction(CryptoAction::WrapKey);
    else if(rec.action==QStringLiteral("unwrap"))         setAction(CryptoAction::UnwrapKey);

    int mode=-1;
    if(rec.mode==QStringLiteral("xchacha20"))      mode=static_cast<int>(CryptoMode::XChaCha20);
    else if(rec.mode==QStringLiteral("aegis256"))  mode=static_cast<int>(CryptoMode::Aegis256);
    else if(rec.mode==QStringLiteral("aes-gcm"))   mode=static_cast<int>(CryptoMode::AesGcm);
    else if(rec.mode==QStringLiteral("sm4"))       mode=static_cast<int>(CryptoMode::Sm4);
    else if(rec.mode==QStringLiteral("asymmetric")) mode=static_cast<int>(CryptoMode::Asymmetric);
    if(mode>=0) {
        const int idx=m_modeCombo->findData(mode);
        if(idx>=0) m_modeCombo->setCurrentIndex(idx);
    }
    // 非对称模式的文件算法一并回填，否则下拉停在默认项却回放出另一套 -m
    if(m_fileCipherCombo && mode==static_cast<int>(CryptoMode::Asymmetric)) {
        int fc=-1;
        if(rec.fileCipher==QStringLiteral("aegis256"))      fc=static_cast<int>(CryptoMode::Aegis256);
        else if(rec.fileCipher==QStringLiteral("aes-gcm"))   fc=static_cast<int>(CryptoMode::AesGcm);
        else if(rec.fileCipher==QStringLiteral("sm4"))      fc=static_cast<int>(CryptoMode::Sm4);
        else if(rec.fileCipher==QStringLiteral("xchacha20")) fc=static_cast<int>(CryptoMode::XChaCha20);
        const int idx=fc>=0 ? m_fileCipherCombo->findData(fc) : 0;
        if(idx>=0) m_fileCipherCombo->setCurrentIndex(idx);
    }
    if(m_chkX448) m_chkX448->setChecked(rec.mode==QStringLiteral("x448"));
    if(!rec.outputDir.isEmpty()) m_outDirEdit->setText(rec.outputDir);

    if(m_sourceCombo) {
        const int idx=m_sourceCombo->findData(rec.sourceIndex);
        if(idx>=0) m_sourceCombo->setCurrentIndex(idx);
    }
    if(m_chkForce) m_chkForce->setChecked(rec.force);
    if(m_chkSha256) m_chkSha256->setChecked(rec.sha256);
    if(m_chkCompress) m_chkCompress->setChecked(rec.compress);
    if(m_compressLevel) m_compressLevel->setValue(rec.compressionLevel);
    if(m_chkPqc) m_chkPqc->setChecked(rec.pqc);
    if(m_chkWatermark) m_chkWatermark->setChecked(rec.watermark);
    // 历史里只有占位符，私钥需重新输入
    if(m_wmKeyEdit) {
        const QString wmKey=rec.watermarkKey.startsWith(QLatin1Char('<'))
            ? QString() : rec.watermarkKey;
        m_wmKeyEdit->setText(wmKey);
    }
    if(m_keyfileEdit) m_keyfileEdit->setText(rec.keyfile);
    if(m_recipientEdit) m_recipientEdit->setText(rec.recipient);
    if(m_identityEdit) m_identityEdit->setText(rec.identity);
    if(!rec.wrapAlg.isEmpty() && m_wrapAlgCombo) {
        const int idx=m_wrapAlgCombo->findData(
            static_cast<int>(wrapAlgFromKey(rec.wrapAlg)));
        if(idx>=0) m_wrapAlgCombo->setCurrentIndex(idx);
    }
    if(m_wrapFileEdit) m_wrapFileEdit->setText(rec.wrapInput);
    if(m_wrapOutEdit) m_wrapOutEdit->setText(rec.wrapOutput);

    if(!rec.inputPaths.isEmpty()) {
        m_fileList->clear();
        addInputPaths(rec.inputPaths);
    }

    updateAsymVisibility();
    refreshCommandPreview();
    recomputePending();
    setStatus(tr("已回填历史任务参数：%1").arg(rec.actionLabel));
}

void MainWindow::appendOutput(const QString& text,bool isError) {
    const unsigned int rgb=isError ? ThemeManager::stderrColorRGB()
        : ThemeManager::stdoutColorRGB();
    QTextCharFormat fmt;
    fmt.setForeground(QColor((rgb>>16)&0xFF,(rgb>>8)&0xFF,rgb&0xFF));
    QTextCursor cur=m_outputView->textCursor();
    cur.movePosition(QTextCursor::End);
    cur.insertText(text,fmt);
    QScrollBar* bar=m_outputView->verticalScrollBar();
    bar->setValue(bar->maximum());
}

// 命令预览刷新
void MainWindow::refreshCommandPreview() {
    if(m_executor&&m_executor->isRunning()) return;
    const ShellOptions o=collectOptions();
    const QString preview=CliArgBuilder::buildPreview(m_fileEncryptorPath,o);
    m_outputView->clear();
    appendOutput(tr(">>> 命令预览: %1").arg(preview)+QStringLiteral("\n"),false);
}

void MainWindow::setStatus(const QString& msg) {
    if(m_statusLabel) {
        if(m_fileEncryptorPath.isEmpty()) {
            m_statusLabel->setText(tr("未找到 CLI 程序 — 请将 FileEncryptorCLI 置于同目录或设置 FILEENCRYPTOR_EXE"));
        }
        else {
            m_statusLabel->setText(msg);
        }
    }
}
