
#include "MainWindow.h"
#include "AboutDialogs.h"
#include "FileEncryptorLocator.h"
#include "FontBootstrap.h"
#include "PasswordStrength.h"
#include "ProcessCommandExecutor.h"
#include "ViewSettingsDialog.h"
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

MainWindow::MainWindow(QWidget* parent): QMainWindow(parent) {
    setWindowTitle(QStringLiteral("FileEncryptorGUI %1").arg(
        qApp->applicationVersion().isEmpty() ? FileEncryptorLocator::guiVersion()
        : qApp->applicationVersion()));
    // 默认窗口 16:9
    resize(1351,760);

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
    buildNavControls();

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
    connect(dlg, &QProgressDialog::canceled, proc, [proc] { proc->kill(); });
    proc->start(updater, args);
}

void MainWindow::handleCheckResult(const QByteArray& out, const QString& updater) {
    QJsonParseError err;
    const QJsonDocument doc = QJsonDocument::fromJson(out, &err);
    if (doc.isNull()) {
        QMessageBox::warning(this, tr("检查更新"),
            tr("无法解析更新器输出：%1\n原始输出：%2").arg(err.errorString(), QString::fromUtf8(out)));
        return;
    }
    const QJsonObject o = doc.object();
    if (!o.value(QStringLiteral("ok")).toBool()) {
        QMessageBox::warning(this, tr("检查更新"),
            tr("检查失败：%1").arg(o.value(QStringLiteral("error")).toString()));
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
                o.value(QStringLiteral("sig_url")).toString());
    } else {
        QMessageBox::information(this, tr("检查更新"),
            tr("已是最新版本（%1）。").arg(o.value(QStringLiteral("current_version")).toString()));
    }
}

void MainWindow::doUpdaterUpdate(const QString& updater, const QString& url,
                                 const QString& sha, const QString& sigUrl) {
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
    connect(dlg, &QProgressDialog::canceled, proc, [proc] { proc->kill(); });
    proc->start(updater, args);
}

// 主题与视图控件
void MainWindow::buildNavControls() {
    m_navWidget=new QWidget(this);
    auto* lay=new QHBoxLayout(m_navWidget);
    lay->setContentsMargins(0,0,0,0);
    lay->setSpacing(6);

    lay->addWidget(new QLabel(tr("主题：")));
    m_themeCombo=new QComboBox;
    m_themeCombo->addItem(tr("浅色"),static_cast<int>(ThemeManager::Theme::Light));
    m_themeCombo->addItem(tr("深色"),static_cast<int>(ThemeManager::Theme::Dark));
    const int idx=m_themeCombo->findData(static_cast<int>(ThemeManager::chosenTheme()));
    m_themeCombo->setCurrentIndex(idx>=0 ? idx : 0);
    connect(m_themeCombo,QOverload<int>::of(&QComboBox::currentIndexChanged),
        this,&MainWindow::onThemeComboChanged);
    lay->addWidget(m_themeCombo);

    m_btnViewSettings=new QPushButton(tr("视图设置"));
    connect(m_btnViewSettings,&QPushButton::clicked,this,&MainWindow::onViewSettings);
    lay->addWidget(m_btnViewSettings);

    m_menuBar->setCornerWidget(m_navWidget,Qt::TopRightCorner);

    connect(&ThemeManager::instance(),&ThemeManager::themeChanged,
        this,&MainWindow::onThemeDarkChanged);
}

void MainWindow::onThemeComboChanged(int idx) {
    const auto t=static_cast<ThemeManager::Theme>(
        m_themeCombo->itemData(idx).toInt());
    ThemeManager::setTheme(t);
    applyButtonStyles();
    applyPanelTransparency();
    refreshCommandPreview();
}

void MainWindow::onThemeDarkChanged(bool ) {
    const int idx=m_themeCombo->findData(static_cast<int>(ThemeManager::chosenTheme()));
    if(idx>=0) {
        m_themeCombo->blockSignals(true);
        m_themeCombo->setCurrentIndex(idx);
        m_themeCombo->blockSignals(false);
    }
    applyButtonStyles();
    applyPanelTransparency();
    applyFlagRedTheme();
}

// 底色随配色
void MainWindow::applyFlagRedTheme() {
    const auto& r=ThemeManager::ui();
    setStyleSheet(QStringLiteral("QMainWindow{background-color:%1;}")
        .arg(QLatin1String(r.window)));
    QPalette p=palette();
    p.setColor(QPalette::Highlight, QColor(r.highlight));
    p.setColor(QPalette::HighlightedText, Qt::white);
    setPalette(p);
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
    for(QLineEdit* e:{m_outDirEdit, m_keyfileEdit,
                       m_recipientEdit, m_identityEdit}) {
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
                       static_cast<QWidget*>(m_chkSha256),
                       static_cast<QWidget*>(m_chkCompress),
                       static_cast<QWidget*>(m_rbEncrypt), static_cast<QWidget*>(m_rbDecrypt),
                       static_cast<QWidget*>(m_rbBatchEncrypt), static_cast<QWidget*>(m_rbBatchDecrypt),
                       static_cast<QWidget*>(m_rbKeyGen), static_cast<QWidget*>(m_rbDerive),
                       static_cast<QWidget*>(m_rbPubKey)}) {
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
    for(QComboBox* cb:{m_themeCombo, m_modeCombo, m_sourceCombo}) {
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
    for(QPushButton* b:{m_btnAddFiles, m_btnAddDir, m_btnClearFiles,
                           m_btnOutDirBrowse, m_btnKeyfileBrowse, m_btnViewSettings,
                           m_btnRecipientBrowse, m_btnIdentityBrowse,
                           m_btnTaskHistory}) {
        if(b) b->setStyleSheet(btnStyle);
    }

    for(QWidget* s:{m_outerSplitter}) {
        if(!s) continue;
        s->setAttribute(Qt::WA_TranslucentBackground);
        s->setAutoFillBackground(false);
        s->setStyleSheet(transparent);
    }
}

void MainWindow::resizeEvent(QResizeEvent* e) {
    QMainWindow::resizeEvent(e);
    resizeBgLabel();
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

    MsgBox::error(this,tr("FileEncryptor CLI 未找到"),detail);
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
    m_zstdAvailable=out.contains(QStringLiteral("zstd=1"));
    if(out.contains(QStringLiteral("aegis=0"))) m_aegisAvailable=false;
    else if(out.contains(QStringLiteral("aegis=1"))) m_aegisAvailable=true;
    updateAsymVisibility();
}

void MainWindow::onRetryCliDetection() {
    if(FileEncryptorLocator::existsWithVersion(&m_fileEncryptorPath)) {
        setStatus(tr("就绪 | FileEncryptor: %1").arg(m_fileEncryptorPath));
        MsgBox::info(this,tr("检测成功"),
            tr("已找到 CLI 程序：\n%1").arg(m_fileEncryptorPath));
        probeZstdSupport();
        updateAsymVisibility();
    }
    else {
        showCliNotFoundError(tr("手动重试"));
    }
}

void MainWindow::applyButtonStyles() {
    const bool dark=ThemeManager::isDarkActive();
    // 国庆周走红色系
    const bool red=ThemeManager::isNationalDay();
    m_btnRun->setStyleSheet(red
        ? (dark
           ? QStringLiteral("QPushButton{background:#DE2910;color:#FFFFFF;padding:6px 18px;font-weight:bold;border-radius:4px;}"
                            "QPushButton:hover{background:#EF4433;}")
           : QStringLiteral("QPushButton{background:#C0392B;color:white;padding:6px 18px;font-weight:bold;border-radius:4px;}"
                            "QPushButton:hover{background:#A93226;}"))
        : (dark
           ? QStringLiteral("QPushButton{background:#43A047;color:#FFFFFF;padding:6px 18px;font-weight:bold;border-radius:4px;}"
                            "QPushButton:hover{background:#66BB6A;}")
           : QStringLiteral("QPushButton{background:#4A7C50;color:white;padding:6px 18px;font-weight:bold;border-radius:4px;}"
                            "QPushButton:hover{background:#3D6B4A;}")));
    m_btnCancel->setStyleSheet(red
        ? (dark
           ? QStringLiteral("QPushButton{background:#7A1A12;color:#F2DAD6;padding:6px 18px;font-weight:bold;border-radius:4px;}"
                            "QPushButton:hover{background:#95231A;}"
                            "QPushButton:disabled{background:#4A1A16;color:#A87F79;}")
           : QStringLiteral("QPushButton{background:#8A1E13;color:white;padding:6px 18px;font-weight:bold;border-radius:4px;}"
                            "QPushButton:hover{background:#6E1810;}"
                            "QPushButton:disabled{background:#D99A92;color:#FFF7F6;}"))
        : (dark
           ? QStringLiteral("QPushButton{background:#E53935;color:#FFFFFF;padding:6px 18px;font-weight:bold;border-radius:4px;}"
                            "QPushButton:hover{background:#EF5350;}"
                            "QPushButton:disabled{background:#555;color:#ccc;}")
           : QStringLiteral("QPushButton{background:#C0392B;color:white;padding:6px 18px;font-weight:bold;border-radius:4px;}"
                            "QPushButton:hover{background:#A93226;}"
                            "QPushButton:disabled{background:#999;color:#eee;}")));
    if(m_btnRewrap) {
        const auto& r=ThemeManager::ui();
        m_btnRewrap->setStyleSheet(QStringLiteral(
            "QPushButton{background:%1;color:%2;border:1px solid %3;"
            "border-radius:3px;padding:4px 10px;}"
            "QPushButton:hover{background:%4;}"
            "QPushButton:disabled{background:%1;color:%5;}")
            .arg(QLatin1String(r.ctrl),QLatin1String(r.text),QLatin1String(r.border),
                 QLatin1String(r.ctrlHover),QLatin1String(r.placeholder)));
    }
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
    m_actionGroup=new QButtonGroup(this);
    m_actionGroup->addButton(m_rbEncrypt,static_cast<int>(CryptoAction::Encrypt));
    m_actionGroup->addButton(m_rbDecrypt,static_cast<int>(CryptoAction::Decrypt));
    m_actionGroup->addButton(m_rbBatchEncrypt,static_cast<int>(CryptoAction::BatchEncrypt));
    m_actionGroup->addButton(m_rbBatchDecrypt,static_cast<int>(CryptoAction::BatchDecrypt));
    m_actionGroup->addButton(m_rbKeyGen,static_cast<int>(CryptoAction::KeyGen));
    m_actionGroup->addButton(m_rbDerive,static_cast<int>(CryptoAction::Derive));
    m_actionGroup->addButton(m_rbPubKey,static_cast<int>(CryptoAction::PubKey));
    m_rbEncrypt->setChecked(true);

    auto* encRow=new QHBoxLayout;
    encRow->addWidget(m_rbEncrypt);
    encRow->addWidget(m_rbDecrypt);
    encRow->addWidget(m_rbBatchEncrypt);
    encRow->addWidget(m_rbBatchDecrypt);
    encRow->addStretch();
    lay->addLayout(encRow,row,1);
    row++;

    auto* lblKeyMgmt=new QLabel(tr("密钥管理"));
    lay->addWidget(lblKeyMgmt,row,0);
    auto* keyMgmtRow=new QHBoxLayout;
    keyMgmtRow->addWidget(m_rbKeyGen);
    keyMgmtRow->addWidget(m_rbDerive);
    keyMgmtRow->addWidget(m_rbPubKey);
    keyMgmtRow->addStretch();
    lay->addLayout(keyMgmtRow,row,1);
    row++;

    auto* lblMode=new QLabel(tr("加密模式"));
    lay->addWidget(lblMode,row,0);
    m_modeCombo=new QComboBox;
    m_modeCombo->addItem(tr("XChaCha20-Poly1305（默认，兼容性最好）"),static_cast<int>(CryptoMode::XChaCha20));
    m_modeCombo->addItem(tr("AEGIS-256（需 AES-NI 指令）"),static_cast<int>(CryptoMode::Aegis256));
    m_modeCombo->addItem(tr("X25519 + ChaCha20-Poly1305（非对称）"),static_cast<int>(CryptoMode::Asymmetric));
    lay->addWidget(m_modeCombo,row,1);
    row++;

    m_compressTitle=new QLabel(tr("压缩"));
    lay->addWidget(m_compressTitle,row,0);
    auto* compRow=new QHBoxLayout;
    m_chkCompress=new QCheckBox(tr("压缩数据"));
    m_chkCompress->setToolTip(tr("加密时逐块 zstd 压缩（磁盘格式 v5，旧版本 CLI 无法读取）。\n"
                                 "仅对称加密有效；输出名混淆下压缩率统计见 CLI 详细输出。"));
    m_compressLabel=new QLabel(tr("压缩级别 (0-22)："));
    m_compressLevel=new QSpinBox;
    m_compressLevel->setRange(-5,22);
    m_compressLevel->setValue(3);
    m_compressLevel->setToolTip(tr("zstd 级别：1..22 常规（越大越慢、压缩率越高），-1..-5 快速档；默认 3\n"
                                   "直接键入数值，回车或移开焦点后生效；也可用键盘 ↑/↓ 微调"));
    m_compressLevel->setButtonSymbols(QAbstractSpinBox::NoButtons);
    m_compressLevel->setAlignment(Qt::AlignRight);
    m_compressLevel->setKeyboardTracking(false);
    m_compressLevel->setFixedWidth(84);
    compRow->addWidget(m_chkCompress);
    compRow->addWidget(m_compressLabel);
    compRow->addWidget(m_compressLevel);
    compRow->addStretch();
    lay->addLayout(compRow,row,1);
    row++;

    m_asymWidget=new QGroupBox(tr("非对称加密"));
    {
        auto* av=new QVBoxLayout(m_asymWidget);
        av->setContentsMargins(8,8,8,8);
        av->setSpacing(6);
        auto* intro=new QLabel(tr("混合加密：随机生成的文件密钥用 X25519 公钥封装（rage/age 格式）。\n"
                                  "加密只需要公钥（可公开），解密才需要私钥。"));
        intro->setWordWrap(true);
        av->addWidget(intro);

        m_recipientRow=new QWidget;
        {
            auto* rr=new QHBoxLayout(m_recipientRow);
            rr->setContentsMargins(0,0,0,0);
            rr->addWidget(new QLabel(tr("公钥：")));
            m_recipientEdit=new QLineEdit;
            m_recipientEdit->setPlaceholderText(tr("age1... 公钥，或每行一个公钥的文件"));
            rr->addWidget(m_recipientEdit,1);
            m_btnRecipientBrowse=new QPushButton(tr("浏览..."));
            rr->addWidget(m_btnRecipientBrowse);
        }
        av->addWidget(m_recipientRow);

        m_identityRow=new QWidget;
        {
            auto* ir=new QHBoxLayout(m_identityRow);
            ir->setContentsMargins(0,0,0,0);
            ir->addWidget(new QLabel(tr("私钥文件：")));
            m_identityEdit=new QLineEdit;
            m_identityEdit->setPlaceholderText(tr("包含 AGE-SECRET-KEY-... 的文件（如 rage_private.txt）"));
            ir->addWidget(m_identityEdit,1);
            m_btnIdentityBrowse=new QPushButton(tr("浏览..."));
            ir->addWidget(m_btnIdentityBrowse);
        }
        av->addWidget(m_identityRow);
    }
    m_asymWidget->setVisible(false);
    lay->addWidget(m_asymWidget,row,0,1,2);
    row++;

    m_keygenWidget=new QGroupBox(tr("rage 密钥管理"));
    {
        auto* kv=new QVBoxLayout(m_keygenWidget);
        kv->setContentsMargins(8,8,8,8);
        kv->setSpacing(6);
        m_keygenIntro=new QLabel;
        m_keygenIntro->setWordWrap(true);
        kv->addWidget(m_keygenIntro);
    }
    m_keygenWidget->setVisible(false);
    lay->addWidget(m_keygenWidget,row,0,1,2);
    row++;

    auto* lblOut=new QLabel(tr("输出目录"));
    lay->addWidget(lblOut,row,0);
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
    m_sourceCombo->setToolTip(tr("加密成功后对源文件的处理方式：\n"
        "· 删除：直接删除（不可恢复）\n"
        "· 回收站：移入系统回收站（可恢复，受控删除）\n"
        "· 安全擦除：0x00 / 0xFF / 随机三次覆写后删除\n"
        "仅加密动作生效。"));
    m_chkForce=new QCheckBox(tr("覆盖已存在文件"));
    m_chkSha256=new QCheckBox(tr("生成校验单"));
    m_chkSha256->setToolTip(tr("加密成功后额外生成 <输出名>.ptd.sha256 校验单（密文 SHA-256 十六进制 + 文件名），\n"
                               "便于与外部备份 / 传输工具链配合校验传输完整性。仅加密动作有效。"));
    optsRow->addWidget(m_sourceCombo);
    optsRow->addWidget(m_chkForce);
    optsRow->addWidget(m_chkSha256);
    optsRow->addStretch();
    lay->addLayout(optsRow,row,1);
    row++;

    auto* runRow=new QHBoxLayout;
    m_btnRun=new QPushButton(tr("▶ 运行"));
    m_btnCancel=new QPushButton(tr("■ 取消"));
    m_btnRewrap=new QPushButton(tr("密钥轮换"));
    m_btnRewrap->setToolTip(tr("对 v6 容器用新口令重裹 DEK（rewrap）：载荷密文不动，零重加密开销。"));
    m_btnCancel->setEnabled(false);
    runRow->addWidget(m_btnRewrap);
    runRow->addStretch();
    runRow->addWidget(m_btnRun);
    runRow->addWidget(m_btnCancel);
    lay->addLayout(runRow,row,1);
    row++;
    applyButtonStyles();

    lay->setRowStretch(row,1);
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
    m_btnTaskHistory->setToolTip(tr("查看任务历史记录，双击一条可回填参数（回放）"));
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

    connect(m_btnRun,&QPushButton::clicked,this,&MainWindow::onRunClicked);
    if(m_btnRewrap)
        connect(m_btnRewrap,&QPushButton::clicked,this,&MainWindow::onRewrapClicked);
    connect(m_btnCancel,&QPushButton::clicked,this,&MainWindow::onCancelClicked);

    connect(m_executor,&ICommandExecutor::outputLine,this,&MainWindow::onOutputLine);
    connect(m_executor,&ICommandExecutor::finished,this,&MainWindow::onCommandFinished);

    auto refresh=[this]{ refreshCommandPreview(); };
    connect(m_actionGroup,&QButtonGroup::idClicked,this,refresh);
    connect(m_modeCombo,QOverload<int>::of(&QComboBox::currentIndexChanged),this,refresh);
    connect(m_outDirEdit,&QLineEdit::textChanged,this,refresh);
    connect(m_keyfileEdit,&QLineEdit::textChanged,this,refresh);
    connect(m_sourceCombo,QOverload<int>::of(&QComboBox::currentIndexChanged),this,refresh);
    connect(m_chkForce,&QCheckBox::stateChanged,this,refresh);
    connect(m_chkSha256,&QCheckBox::stateChanged,this,refresh);
    connect(m_chkCompress,&QCheckBox::stateChanged,this,refresh);
    connect(m_chkCompress,&QCheckBox::stateChanged,this,[this](int){ updateAsymVisibility(); });
    connect(m_compressLevel,QOverload<int>::of(&QSpinBox::valueChanged),this,refresh);
    connect(m_fileList,&QListWidget::itemChanged,this,refresh);

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

    connect(m_fileList,&QListWidget::itemChanged,this,[this]{ recomputePending(); });
    connect(m_modeCombo,QOverload<int>::of(&QComboBox::currentIndexChanged),
        this,&MainWindow::updateAsymVisibility);
    connect(m_actionGroup,&QButtonGroup::idClicked,
        this,[this](int){ updateAsymVisibility(); });
}

// 动作/模式切换
void MainWindow::updateAsymVisibility() {
    const int act=m_actionGroup->checkedId();
    const bool keygen=(act==static_cast<int>(CryptoAction::KeyGen));
    const bool derive=(act==static_cast<int>(CryptoAction::Derive));
    const bool pubkey=(act==static_cast<int>(CryptoAction::PubKey));
    const bool isKeyAction=(keygen||derive||pubkey);
    const bool isEnc=(act==static_cast<int>(CryptoAction::Encrypt)||
                      act==static_cast<int>(CryptoAction::BatchEncrypt));
    const bool asym=(!isKeyAction)&&
        (m_modeCombo->currentData().toInt()==static_cast<int>(CryptoMode::Asymmetric));

    m_asymWidget->setVisible(asym||pubkey);
    m_recipientRow->setVisible(asym&&isEnc);
    m_identityRow->setVisible((asym&&!isEnc)||pubkey);

    m_keygenWidget->setVisible(isKeyAction);
    if(keygen) {
        m_keygenWidget->setTitle(tr("rage 随机生成密钥对"));
        m_keygenIntro->setText(tr("在下方输出目录中随机生成一对 X25519 密钥：\n"
                                  "  公钥             -> 打印到输出面板（age1...，可公开分享）\n"
                                  "  rage_private.txt -> 私钥文件（AGE-SECRET-KEY-...，务必妥善保管）"));
    } else if(derive) {
        m_keygenWidget->setTitle(tr("rage 口令派生密钥对"));
        m_keygenIntro->setText(tr("用右侧「口令」经 Argon2id 确定性派生一对 X25519 密钥：\n"
                                  "  公钥                  -> 打印到输出面板（age1...）\n"
                                  "  rage_private.txt      -> 私钥文件（AGE-SECRET-KEY-...）\n"
                                  "  rage_derive_salt.txt  -> 16 字节随机盐，复现同一密钥对必需\n"
                                  "同一口令 + 同一盐永远得到同一对密钥，因此口令可以代替私钥文件；"
                                  "但盐必须一并保存，否则无法再次派生出来。"));
    } else if(pubkey) {
        m_keygenWidget->setTitle(tr("rage 由私钥导出公钥"));
        m_keygenIntro->setText(tr("读取下方「私钥文件」里的 AGE-SECRET-KEY-...，"
                                  "反推出对应的 age1... 公钥并打印到输出面板。\n"
                                  "用于私钥还在、公钥丢失的情况（等价 rage-keygen -y）。"));
    }

    if(isKeyAction) {
        for(int i=0;i<m_modeCombo->count();++i) {
            if(m_modeCombo->itemData(i).toInt()==static_cast<int>(CryptoMode::Asymmetric)) {
                m_modeCombo->setCurrentIndex(i);
                break;
            }
        }
        m_modeCombo->setDisabled(true);
    } else {
        m_modeCombo->setDisabled(false);
    }

    const bool compAllowed=isEnc && !asym;
    m_compressTitle->setVisible(compAllowed);
    m_chkCompress->setVisible(compAllowed);
    m_compressLabel->setVisible(compAllowed);
    m_compressLevel->setVisible(compAllowed);
    m_chkCompress->setEnabled(compAllowed);
    m_compressLabel->setEnabled(compAllowed);
    m_compressLevel->setEnabled(compAllowed);
    if(compAllowed && !m_zstdAvailable) {
        m_chkCompress->setToolTip(tr("当前 CLI 不支持 zstd（--features zstd=0），压缩参数不会下发。\n"
                                     "请更换带 zstd 库构建的 FileEncryptorCLI。"));
    }

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

ShellOptions MainWindow::collectOptions() const {
    ShellOptions o;
    o.action=static_cast<CryptoAction>(m_actionGroup->checkedId());
    o.mode=static_cast<CryptoMode>(m_modeCombo->currentData().toInt());

    for(int i=0; i<m_fileList->count(); ++i) {
        auto* it=m_fileList->item(i);
        if(it->checkState()==Qt::Checked) o.inputPaths<<it->text();
    }

    o.outputDir=m_outDirEdit->text().trimmed();
    o.sourceDisposition=m_sourceCombo ? m_sourceCombo->currentData().toInt() : 0;
    o.forceOverwrite=m_chkForce->isChecked();
    o.writeSha256=m_chkSha256->isChecked();
    o.keyfilePath=m_keyfileEdit->text().trimmed();
    o.compress=m_chkCompress->isChecked();
    o.compressionLevel=o.compress ? m_compressLevel->value() : 0;

    const QString rawRecip=m_recipientEdit->text().trimmed();
    o.recipientPath=rawRecip;
    o.recipientCount=0;
    for(const QString& seg:rawRecip.split(QRegularExpression(QStringLiteral("[,，;；]")),Qt::SkipEmptyParts)) {
        if(!seg.trimmed().isEmpty()) ++o.recipientCount;
    }
    o.identityPath=m_identityEdit->text().trimmed();
    {
        const bool asymDecrypt=(o.mode==CryptoMode::Asymmetric)&&
            (o.action==CryptoAction::Decrypt||o.action==CryptoAction::BatchDecrypt);
        if(asymDecrypt) o.keyfilePath=o.identityPath;
        else if(o.action==CryptoAction::PubKey) o.keyfilePath=o.identityPath;
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
                                  ||s.startsWith(QLatin1String("publickey:")); });
    if(!allKeys) return raw.trimmed();
    if(!m_recipientTempFile.isEmpty()) { QFile::remove(m_recipientTempFile); m_recipientTempFile.clear(); }
    QTemporaryFile recTmp(QDir::tempPath()+QStringLiteral("/fileencryptor_recipients_XXXXXX"));
    recTmp.setAutoRemove(false);
    if(!recTmp.open()) return raw.trimmed();
    for(const QString& k:parts) recTmp.write((k+QLatin1Char('\n')).toUtf8());
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

    o.recipientPath=resolveRecipients(o.recipientPath);

    if(o.mode==CryptoMode::Aegis256 && !m_aegisAvailable) {
        MsgBox::error(this, tr("AEGIS-256 不可用"),
            tr("当前 CPU 不支持 AES-NI，AEGIS-256 在此环境下会极慢且抗侧信道能力弱。\n"
               "请改用 XChaCha20-Poly1305（默认模式）。"));
        return;
    }

    const bool isKeyGen=(o.action==CryptoAction::KeyGen);
    const bool isDerive=(o.action==CryptoAction::Derive);
    const bool isPubKey=(o.action==CryptoAction::PubKey);
    const bool noInputNeeded=(isKeyGen||isDerive||isPubKey);
    if(!noInputNeeded && o.inputPaths.isEmpty()) {
        MsgBox::warn(this,tr("缺少输入"),tr("请先添加文件或目录。"));
        return;
    }
    bool isBatch=(o.action==CryptoAction::BatchEncrypt||
        o.action==CryptoAction::BatchDecrypt);
    bool isEnc=(o.action==CryptoAction::Encrypt||o.action==CryptoAction::BatchEncrypt);
    if(!isBatch&&o.inputPaths.size()>1) {
        MsgBox::warn(this,tr("输入过多"),
            tr("单文件模式只接受一个输入路径，请清空后只选一个，或改用批量模式。"));
        return;
    }
    const bool isAsym=(o.mode==CryptoMode::Asymmetric)&&!noInputNeeded;
    if(isKeyGen) {
    } else if(isDerive) {
    } else if(isPubKey) {
        if(o.identityPath.isEmpty()) {
            MsgBox::warn(this,tr("缺少私钥"),
                tr("请先在「私钥文件」中选择包含 AGE-SECRET-KEY-... 的文件。"));
            m_identityEdit->setFocus();
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
                    tr("非对称解密需要私钥文件，例如 rage_private.txt。"));
                m_identityEdit->setFocus();
                return;
            }
        }
    }

    // 口令弹窗
    bool symNeedsPassword = !isAsym && o.keyfilePath.isEmpty()
        && (o.action==CryptoAction::Encrypt || o.action==CryptoAction::BatchEncrypt
            || o.action==CryptoAction::Decrypt || o.action==CryptoAction::BatchDecrypt
            || o.action==CryptoAction::Derive);
    std::vector<unsigned char> pw;
    if(symNeedsPassword) {
        if(o.action==CryptoAction::BatchDecrypt) {
            o.restoreName = MsgBox::confirm(this, tr("批量解密文件名"),
                tr("批量解密将对每个文件执行昂贵的密钥派生（KDF）以还原完整原始文件名，可能很慢。\n"
                   "是否启用「完整文件名还原」？\n（无论是否启用，输出文件的扩展名都会保留。）"));
        }
        PasswordDialog dlg(this);
        dlg.setPurpose(isDerive ? tr("口令派生") : (isEnc ? tr("加密口令") : tr("解密口令")));
        dlg.setRequireConfirm(o.action==CryptoAction::Encrypt
            || o.action==CryptoAction::BatchEncrypt || o.action==CryptoAction::Derive);
        if(dlg.exec()!=QDialog::Accepted) return;
        pw = dlg.takePassword();
        if(pw.empty()) return;
    }

    CommandRequest req;
    req.programPath=m_fileEncryptorPath;
    req.arguments=CliArgBuilder::buildArguments(o);
    req.extraEnv=CliArgBuilder::buildEnvironment(o);
    {
        QTemporaryFile statsTmp(QDir::tempPath()+QStringLiteral("/fe_stats_XXXXXX"));
        statsTmp.setAutoRemove(false);
        if(statsTmp.open()) {
            m_statsFile=statsTmp.fileName();
            statsTmp.close();
        }
    }
    req.extraEnv.insert(QStringLiteral("FILEENCRYPTOR_STATS_FILE"),m_statsFile);
    if(o.action==CryptoAction::BatchEncrypt||o.action==CryptoAction::BatchDecrypt) {
        req.extraEnv.insert(QStringLiteral("FILEENCRYPTOR_PROGRESS_FRAME"),QStringLiteral("1"));
        const QFontMetrics fm(m_outputView->font());
        const int cw=fm.horizontalAdvance(QLatin1Char('M'));
        int cols=cw>0?(m_outputView->viewport()->width()-8)/cw:100;
        cols=qBound(60,cols,200);
        req.extraEnv.insert(QStringLiteral("COLUMNS"),QString::number(cols));
    }

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
    if(m_framePending) flushPendingFrame();
    finishTaskRecord(r);

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
    }

    const QString notifyTitle = tr("任务完成");
    const QString notifyBody = summary.remove(QStringLiteral("---")).trimmed();
    if (isActiveWindow()) {
        QMessageBox::information(this, notifyTitle, notifyBody);
    } else if (m_trayIcon && QSystemTrayIcon::isSystemTrayAvailable()) {
        m_trayIcon->showMessage(notifyTitle, notifyBody, QSystemTrayIcon::Information, 5000);
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
    }
    return QStringLiteral("encrypt");
}

QString MainWindow::modeKey(CryptoMode m) {
    switch(m) {
        case CryptoMode::XChaCha20:   return QStringLiteral("xchacha20");
        case CryptoMode::Aegis256:    return QStringLiteral("aegis256");
        case CryptoMode::Asymmetric:  return QStringLiteral("asymmetric");
    }
    return QStringLiteral("xchacha20");
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
    m_currentTask.inputCount=o.inputPaths.size();
    m_currentTask.inputPaths=o.inputPaths;
    m_currentTask.totalBytes=m_pendingBytes;
    m_currentTask.outputDir=o.outputDir;
    m_currentTask.sourceIndex=o.sourceDisposition;
    m_currentTask.force=o.forceOverwrite;
    m_currentTask.sha256=o.writeSha256;
    m_currentTask.compress=o.compress;
    m_currentTask.compressionLevel=o.compressionLevel;
    m_currentTask.keyfile=o.keyfilePath;
    m_currentTask.recipient=o.recipientPath;
    m_currentTask.identity=o.identityPath;
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

    int mode=-1;
    if(rec.mode==QStringLiteral("xchacha20"))      mode=static_cast<int>(CryptoMode::XChaCha20);
    else if(rec.mode==QStringLiteral("aegis256"))  mode=static_cast<int>(CryptoMode::Aegis256);
    else if(rec.mode==QStringLiteral("asymmetric")) mode=static_cast<int>(CryptoMode::Asymmetric);
    if(mode>=0) {
        const int idx=m_modeCombo->findData(mode);
        if(idx>=0) m_modeCombo->setCurrentIndex(idx);
    }
    if(!rec.outputDir.isEmpty()) m_outDirEdit->setText(rec.outputDir);

    if(m_sourceCombo) {
        const int idx=m_sourceCombo->findData(rec.sourceIndex);
        if(idx>=0) m_sourceCombo->setCurrentIndex(idx);
    }
    if(m_chkForce) m_chkForce->setChecked(rec.force);
    if(m_chkSha256) m_chkSha256->setChecked(rec.sha256);
    if(m_chkCompress) m_chkCompress->setChecked(rec.compress);
    if(m_compressLevel) m_compressLevel->setValue(rec.compressionLevel);
    if(m_keyfileEdit) m_keyfileEdit->setText(rec.keyfile);
    if(m_recipientEdit) m_recipientEdit->setText(rec.recipient);
    if(m_identityEdit) m_identityEdit->setText(rec.identity);

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
