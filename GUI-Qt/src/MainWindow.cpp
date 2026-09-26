// MainWindow 实现

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
#include <vector>
#include <cstring>

// 安全擦除：见 secure_zero.h（MainWindow 与 PasswordDialog 共用）
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
#include <QThread>    // 批量线程数参考（CLI 侧同策略）
#include <QTimer>
#include <QtConcurrent/QtConcurrentRun>
#include <QFutureWatcher>
#include <QElapsedTimer>
#include <atomic>
#include <memory>

MainWindow::MainWindow(QWidget* parent): QMainWindow(parent) {
    // 标题含版本号（兜底值统一取 FileEncryptorLocator::guiVersion()，不再各自硬编码）
    setWindowTitle(QStringLiteral("FileEncryptorGUI %1").arg(
        qApp->applicationVersion().isEmpty() ? FileEncryptorLocator::guiVersion()
        : qApp->applicationVersion()));
    resize(1200,760);

    // 系统托盘：后台任务完成时发桌面通知
    m_trayIcon=new QSystemTrayIcon(this);
    m_trayIcon->setIcon(QIcon::fromTheme(QStringLiteral("fileencryptor"),
        QApplication::style()->standardIcon(QStyle::SP_ComputerIcon)));
    m_trayIcon->setToolTip(windowTitle());
    m_trayIcon->show();

    // 功能4：允许把文件 / 目录拖进主窗口加入输入列表
    setAcceptDrops(true);

    // 命令执行器（手写极简构造注入，不引 DI 容器）
    m_executor=new ProcessCommandExecutor(this);

    // 启动时检测 CLI 是否存在
    if(!FileEncryptorLocator::existsWithVersion(&m_fileEncryptorPath)) {
        // 延迟显示错误对话框，避免阻塞主窗口初始化
        QTimer::singleShot(500,this,[this]() {
            showCliNotFoundError(tr("启动时检测"));
            });
    }

    buildMenu();
    buildNavControls();

    // 中央布局：左 | 中 | 下（口令输入移至运行期 PasswordDialog 弹窗，主页面不留独立口令区）
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
    outerSplitter->setSizes({520, 380});   // 拟 cmd 输出区加高（批量帧行数多）

    setCentralWidget(outerSplitter);
    m_outerSplitter=outerSplitter;

    // 背景图：面板透明，透出主窗口底图
    applyPanelTransparency();
    // 启动期恢复已保存的背景图（不强制按比例缩放窗口，几何由下方 restoreGeometry 决定）
    QSettings s(QStringLiteral("FileEncryptor"),QStringLiteral("FileEncryptorGUI"));
    m_bgPath=s.value(QStringLiteral("backgroundImage")).toString();
    applyBackground(m_bgPath, /*resizeToRatio=*/false);
    // 恢复窗口几何（含背景图设置后的窗口大小，重启后保持生效）
    if(s.contains(QStringLiteral("geometry")))
        restoreGeometry(s.value(QStringLiteral("geometry")).toByteArray());

    // 状态栏
    m_statusLabel=new QLabel(this);
    statusBar()->addWidget(m_statusLabel,1);
    // 右侧常驻计数条：运行中实时显示「当前文件 / 完成 / 跳过 / 失败」，空闲时显示待处理规模
    m_progressLabel=new QLabel(this);
    m_progressLabel->setTextInteractionFlags(Qt::NoTextInteraction);
    statusBar()->addPermanentWidget(m_progressLabel);
    setStatus(m_fileEncryptorPath.isEmpty()
        ? tr("未找到 FileEncryptor 可执行文件 — 请设置环境变量 FILEENCRYPTOR_EXE 或将其置于本程序同目录")
        : tr("就绪 | FileEncryptor: %1").arg(m_fileEncryptorPath));

    // 目录扫描异步化：防抖（180ms）+ 工作线程执行，界面不再被递归遍历阻塞
    m_pendingTimer=new QTimer(this);
    m_pendingTimer->setSingleShot(true);
    m_pendingTimer->setInterval(180);
    connect(m_pendingTimer,&QTimer::timeout,this,&MainWindow::startPendingScan);
    m_scanWatcher=new QFutureWatcher<ScanResult>(this);
    connect(m_scanWatcher,&QFutureWatcher<ScanResult>::finished,
        this,&MainWindow::onPendingScanFinished);
    // 进度帧节流渲染
    m_frameTimer=new QTimer(this);
    m_frameTimer->setSingleShot(true);
    m_frameTimer->setInterval(120);
    connect(m_frameTimer,&QTimer::timeout,this,&MainWindow::flushPendingFrame);

    connectSignals();
    // zstd 能力探测（同步 QProcess，--features 秒回），随后按结果裁决压缩控件初始状态
    probeZstdSupport();
    updateAsymVisibility();
    refreshCommandPreview();
    updateProgressLabel();
    recomputePending();   // 异步统计初始待处理规模（大目录也不阻塞界面）
}

MainWindow::~MainWindow() {
    // 扫描线程可能在窗口关闭时仍在跑：先置取消标志再等其退出，
    // 避免工作线程继续访问已析构的窗口（lambda 只按值捕获，等待本身是安全的）。
    if(m_pendingTimer) m_pendingTimer->stop();
    if(m_scanCancel) m_scanCancel->store(true,std::memory_order_relaxed);
    if(m_scanWatcher&&m_scanWatcher->isRunning()) m_scanWatcher->waitForFinished();
}

void MainWindow::closeEvent(QCloseEvent* e) {
    // 运行中弹确认
    if(m_executor&&m_executor->isRunning()) {
        if(!MsgBox::confirm(this,tr("确认退出"),
            tr("有命令正在运行，退出将终止它。确定退出？"))) {
            e->ignore();
            return;
        }
        m_executor->cancel();
    }
    // 功能8：清理多收件人临时公钥文件（仅含公钥，仍保持不留残留文件的整洁性）
    if(!m_recipientTempFile.isEmpty()) {
        QFile::remove(m_recipientTempFile);
        m_recipientTempFile.clear();
    }
    // rewrap 新口令临时密钥文件：运行结束时 onCommandFinished 已删除，但窗口在
    // 轮换进行中被关闭（已 cancel）时该路径可能残留，此处兜底清理。
    if(!m_rewrapTempKey.isEmpty()) {
        QFile::remove(m_rewrapTempKey);
        m_rewrapTempKey.clear();
    }
    // 持久化窗口几何（含背景图设置后的窗口大小，重启后保持生效）
    QSettings(QStringLiteral("FileEncryptor"),QStringLiteral("FileEncryptorGUI"))
        .setValue(QStringLiteral("geometry"),saveGeometry());
    e->accept();
}

// ---------- 顶栏菜单（关于 + 编辑；主题/视图设置控件在菜单栏右上角，同一行）----------
void MainWindow::buildMenu() {
    m_menuBar=menuBar();

    // —— 关于菜单 ——
    auto* aboutMenu=m_menuBar->addMenu(tr("关于(&A)"));

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

    // —— 编辑菜单（顶层，与“关于”同处菜单栏一行）——
    auto* editMenu=m_menuBar->addMenu(tr("编辑(&E)"));
    auto* actEditConfig=editMenu->addAction(tr("编辑 YAML 配置..."));
    connect(actEditConfig,&QAction::triggered,this,&MainWindow::onEditConfig);

    // —— 工具菜单 ——
    // v1.3.0：密钥库管理/批量 ETA 入口已移除，菜单仅保留「任务历史」
    auto* toolsMenu=m_menuBar->addMenu(tr("工具(&T)"));
    auto* actTaskHistory=toolsMenu->addAction(tr("任务历史..."));
    connect(actTaskHistory,&QAction::triggered,this,&MainWindow::onOpenTaskHistory);
    toolsMenu->addSeparator();
    auto* actRetryCli=toolsMenu->addAction(tr("重新检测 CLI 程序"));
    connect(actRetryCli,&QAction::triggered,this,&MainWindow::onRetryCliDetection);
}

// ---------- 菜单栏右上角控件：颜色主题 + 视图设置（与“关于”同一行）----------
void MainWindow::buildNavControls() {
    m_navWidget=new QWidget(this);
    auto* lay=new QHBoxLayout(m_navWidget);
    lay->setContentsMargins(0,0,0,0);
    lay->setSpacing(6);

    // 主题：下拉框，提供 浅色 / 深色 两种模式
    lay->addWidget(new QLabel(tr("主题：")));
    m_themeCombo=new QComboBox;
    m_themeCombo->addItem(tr("浅色"),static_cast<int>(ThemeManager::Theme::Light));
    m_themeCombo->addItem(tr("深色"),static_cast<int>(ThemeManager::Theme::Dark));
    // 反映当前持久化偏好
    const int idx=m_themeCombo->findData(static_cast<int>(ThemeManager::chosenTheme()));
    m_themeCombo->setCurrentIndex(idx>=0 ? idx : 0);
    connect(m_themeCombo,QOverload<int>::of(&QComboBox::currentIndexChanged),
        this,&MainWindow::onThemeComboChanged);
    lay->addWidget(m_themeCombo);

    // 视图设置（背景图）
    m_btnViewSettings=new QPushButton(tr("视图设置"));
    connect(m_btnViewSettings,&QPushButton::clicked,this,&MainWindow::onViewSettings);
    lay->addWidget(m_btnViewSettings);

    // 置于菜单栏右上角（与“关于”同一行）
    m_menuBar->setCornerWidget(m_navWidget,Qt::TopRightCorner);

    // 主题切换（用户选择）→ 同步下拉框并刷新面板
    connect(&ThemeManager::instance(),&ThemeManager::themeChanged,
        this,&MainWindow::onThemeDarkChanged);
}

void MainWindow::onThemeComboChanged(int idx) {
    const auto t=static_cast<ThemeManager::Theme>(
        m_themeCombo->itemData(idx).toInt());
    ThemeManager::setTheme(t);   // 持久化 + 应用调色板
    applyButtonStyles();
    applyPanelTransparency();    // 面板样式随主题刷新
    refreshCommandPreview();     // 命令预览按当前主题对比色刷新
}

void MainWindow::onThemeDarkChanged(bool /*dark*/) {
    // 用户切换主题后保持下拉框与面板同步
    const int idx=m_themeCombo->findData(static_cast<int>(ThemeManager::chosenTheme()));
    if(idx>=0) {
        m_themeCombo->blockSignals(true);
        m_themeCombo->setCurrentIndex(idx);
        m_themeCombo->blockSignals(false);
    }
    applyButtonStyles();
    applyPanelTransparency();
}

// ---------- 视图设置（自定义背景图）----------
void MainWindow::onViewSettings() {
    ViewSettingsDialog dlg(m_bgPath,this);
    if(dlg.exec()!=QDialog::Accepted) return;

    const QString path=dlg.selectedImagePath();
    if(path.isEmpty()) {
        // 清除背景
        applyBackground(QString(), /*resizeToRatio=*/false);
        return;
    }
    // 先校验可加载，避免选了损坏文件还写进设置
    const QPixmap pm(path);
    if(pm.isNull()) {
        MsgBox::warn(this,tr("背景图无效"),
            tr("无法加载该图片，请选择有效的 PNG/JPG 等图片文件。"));
        return;
    }
    applyBackground(path, /*resizeToRatio=*/true);
}

// ---------- 背景图应用 ----------
void MainWindow::applyBackground(const QString& path,bool resizeToRatio) {
    // 清除
    if(path.isEmpty()||!QFileInfo(path).isFile()) {
        m_bgPath.clear();
        m_bgSource=QPixmap();
        if(m_bgLabel) m_bgLabel->hide();
        QSettings(QStringLiteral("FileEncryptor"),QStringLiteral("FileEncryptorGUI"))
            .setValue(QStringLiteral("backgroundImage"),QString());
        return;
    }

    const QPixmap pm(path);
    if(pm.isNull()) return;   // 不应发生（onViewSettings 已校验）；保险起见不改状态

    m_bgPath=path;
    m_bgSource=pm;

    if(!m_bgLabel) {
        m_bgLabel=new QLabel(this);
        m_bgLabel->setScaledContents(false);
        m_bgLabel->setAttribute(Qt::WA_TransparentForMouseEvents);
        m_bgLabel->lower();          // 置于所有内容之下
    }
    m_bgLabel->show();
    resizeBgLabel();

    // 持久化
    QSettings(QStringLiteral("FileEncryptor"),QStringLiteral("FileEncryptorGUI"))
        .setValue(QStringLiteral("backgroundImage"),path);

    // 按图片比例拉伸/缩小窗口
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

// 背景图 QLabel：铺满整个窗口，等比扩展（KeepAspectRatioByExpanding）铺满不变形
void MainWindow::resizeBgLabel() {
    if(!m_bgLabel) return;
    m_bgLabel->setGeometry(rect());
    if(!m_bgSource.isNull()) {
        m_bgLabel->setPixmap(m_bgSource.scaled(
            size(),Qt::KeepAspectRatioByExpanding,Qt::SmoothTransformation));
    }
}

// 面板透明：除输入框(QLineEdit)与按钮(QPushButton)保留自身样式外，
// 其余区域背景一律透明，与整体背景（主题底色或背景图）保持一致，避免颜色突兀的区块。
void MainWindow::applyPanelTransparency() {
    const QString transparent=QStringLiteral("background:transparent;");
    const bool dk=ThemeManager::isDarkActive();

    // 功能面板透明（其内部的标签/单选/复选本就无填充，自然融入整体背景）
    for(QWidget* p:{m_leftPanel, m_centerPanel, m_bottomPanel}) {
        if(!p) continue;
        p->setAttribute(Qt::WA_TranslucentBackground);
        p->setAutoFillBackground(false);
        p->setStyleSheet(transparent);
    }

    // 通用配色：亮色用浅灰底+深字，暗色用深底+浅字
    const QString fieldBg=dk ? QStringLiteral("#1E1E1E") : QStringLiteral("#F0F0EC");
    const QString fieldFg=dk ? QStringLiteral("#E6E6E6") : QStringLiteral("#333333");
    const QString fieldBor=dk ? QStringLiteral("#3C3C3C") : QStringLiteral("#C8C8C4");
    const QString fieldSel=dk ? QStringLiteral("#3D6B99") : QStringLiteral("#4A7C50");
    const QString altBg=dk ? QStringLiteral("#252525") : QStringLiteral("#E8E8E4");
    const QString hoverBg=dk ? QStringLiteral("#333333") : QStringLiteral("#E0E0DC");
    const QString indBg=dk ? QStringLiteral("#2A2A2A") : QStringLiteral("#FFFFFF");
    const QString indBor=dk ? QStringLiteral("#5A5A5A") : QStringLiteral("#999999");
    const QString ctrlBg=dk ? QStringLiteral("#3D3D40") : QStringLiteral("#ECECEA");
    const QString ctrlFg=dk ? QStringLiteral("#E6E6E6") : QStringLiteral("#333333");
    const QString ctrlBor=dk ? QStringLiteral("#4A4A4D") : QStringLiteral("#C8C8C4");
    const QString ctrlHover=dk ? QStringLiteral("#4A4A4D") : QStringLiteral("#DCDCD8");

    // 文件列表：随主题——亮色浅灰底+深字，暗色深底+浅字
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

    // 公共字段 QSS 模板：输入框/输出框/数值框共用的基础样式（随主题替换占位符），
    // 一处定义、多处复用，避免三处重复书写同一段样式（P2-3 抽公共模板）。
    const QString fieldCss=QStringLiteral(
        "background:%1;color:%2;border:1px solid %3;border-radius:3px;padding:2px 4px;"
        "selection-background-color:%4;selection-color:#FFFFFF;")
        .arg(fieldBg,fieldFg,fieldBor,fieldSel);
    for(QLineEdit* e:{m_outDirEdit, m_keyfileEdit,
                       m_recipientEdit, m_identityEdit}) {
        if(e) e->setStyleSheet(fieldCss);
    }
    if(m_outputView) {
        // 输出框 + 滚动条一体样式：显式接管滚动条、移除上下箭头（仅留滑块），配色随主题
        const QString sbHandle=dk ? QStringLiteral("#5A5A5A") : QStringLiteral("#A8A8A4");
        const QString sbHover=dk ? QStringLiteral("#6E6E6E") : QStringLiteral("#8A8A86");
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

    // 勾选框(QCheckBox)/单选框(QRadioButton)：随主题，亮色浅灰底+深字
    const QString optionStyle=QStringLiteral(
        "QCheckBox,QRadioButton{background:%1;color:%2;"
        "border:1px solid %3;border-radius:3px;padding:4px 6px;spacing:6px;}"
        "QCheckBox::indicator,QRadioButton::indicator{width:14px;height:14px;"
        "border:1px solid %4;background:%5;}"
        "QCheckBox::indicator{border-radius:2px;}"
        "QRadioButton::indicator{border-radius:7px;}"
        "QCheckBox::indicator:hover,QRadioButton::indicator:hover{border:1px solid #7AA7D9;}"
        "QCheckBox::indicator:checked{background:%6;border:1px solid %4;}"
        "QRadioButton::indicator:checked{background:%6;border:1px solid %4;}"
    ).arg(fieldBg,fieldFg,fieldBor,indBor,indBg,fieldSel);
    for(QWidget* c:{static_cast<QWidget*>(m_chkForce), 
                       static_cast<QWidget*>(m_chkSha256),
                       static_cast<QWidget*>(m_chkCompress),
                       static_cast<QWidget*>(m_rbEncrypt), static_cast<QWidget*>(m_rbDecrypt),
                       static_cast<QWidget*>(m_rbBatchEncrypt), static_cast<QWidget*>(m_rbBatchDecrypt),
                       static_cast<QWidget*>(m_rbKeyGen), static_cast<QWidget*>(m_rbDerive),
                       static_cast<QWidget*>(m_rbPubKey)}) {
        if(c) c->setStyleSheet(optionStyle);
    }

    // 下拉框(QComboBox：主题/模式) 与其余按钮：随主题显式配色，
    // 亮色浅灰底+深字（避免依赖调色板在某些环境下仍渲染深色）
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

    // 数值框(QSpinBox：压缩级别)：与输入框同配色。SpinBox 已 setButtonSymbols(NoButtons)
    // （无上下按钮），显式样式用于规避父级 background:transparent 层级导致的输入框透明。
    const QString spinStyle=QStringLiteral(
        "QSpinBox{%1}"
        "QSpinBox:disabled{background:%2;color:#999999;border:1px solid %3;}"
    ).arg(fieldCss,altBg,fieldBor);
    if(m_compressLevel) m_compressLevel->setStyleSheet(spinStyle);
    const QString btnStyle=QStringLiteral(
        "QPushButton{background:%1;color:%2;border:1px solid %3;border-radius:3px;padding:4px 10px;}"
        "QPushButton:hover{background:%4;}"
        "QPushButton:disabled{background:%1;color:#999999;}"
    ).arg(ctrlBg,ctrlFg,ctrlBor,ctrlHover);
    for(QPushButton* b:{m_btnAddFiles, m_btnAddDir, m_btnClearFiles,
                           m_btnOutDirBrowse, m_btnKeyfileBrowse, m_btnViewSettings,
                           m_btnRecipientBrowse, m_btnIdentityBrowse,
                           m_btnTaskHistory}) {
        if(b) b->setStyleSheet(btnStyle);
    }

    // 外层 splitter 透明，让背景在面板间隙也可见
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

// ---------- 编辑 YAML 配置（调用系统默认编辑器）----------

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

// 定位 CLI 的 yml 配置（与 CLI core/config.cpp::find_config_file 搜索顺序一致）。
// v1.3.1：统一回归标准 .yaml 后缀（与 CLI 一致）；旧名 fileencryptor.yml 仅读取时回退。
QString MainWindow::locateConfigFile() const {
    const QString name=QStringLiteral("fileencryptor.yaml");
    const QString legacy=QStringLiteral("fileencryptor.yml");
    // 在某目录下按「.yaml 优先、.yml 回退」查找的辅助逻辑
    auto findIn=[&](const QString& dir)->QString{
        if(dir.isEmpty()) return {};
        const QString p=QDir::toNativeSeparators(dir+QLatin1Char('/')+name);
        if(QFileInfo(p).isFile()) return p;
        const QString pl=QDir::toNativeSeparators(dir+QLatin1Char('/')+legacy);
        if(QFileInfo(pl).isFile()) return pl;
        return {};
    };
    // 1) FILEENCRYPTOR_CONFIG 环境变量（显式，最高优先）
    const QString env=qEnvironmentVariable("FILEENCRYPTOR_CONFIG");
    if(!env.isEmpty()&&QFileInfo(env).isFile()) return env;
    // 2) CWD：用户在哪个目录启动，配置就在哪里
    QString p=findIn(QDir::current().absolutePath());
    if(!p.isEmpty()) return p;
    // 3) CLI 可执行文件目录
    if(!m_fileEncryptorPath.isEmpty()) {
        p=findIn(QFileInfo(m_fileEncryptorPath).absolutePath());
        if(!p.isEmpty()) return p;
    }
    // 4) 用户配置目录
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
    // 未找到 → 按 CLI 行为在 CWD 生成默认配置（便于用户直接编辑）。
    // 新写入一律用 .yaml（标准 YAML 后缀），保持与 CLI 一致。
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
    // 调用系统默认编辑器打开（按文件关联；无关联时提示路径）
    if(!QDesktopServices::openUrl(QUrl::fromLocalFile(target))) {
        MsgBox::info(this,tr("请手动打开"),
            tr("系统未关联 YAML 文件的默认编辑器，请手动打开：\n%1").arg(target));
    }
}

// ---------- CLI 检测相关 ----------
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

// ---------- CLI zstd / aegis 能力探测（异步，避免主线程阻塞） ----------
void MainWindow::probeZstdSupport() {
    m_zstdAvailable=false;
    m_aegisAvailable=true;   // 默认乐观，避免误拦
    if(m_fileEncryptorPath.isEmpty()) return;
    // 复用同一 QProcess：已有探测在跑则先终止，避免排队堆积
    if(!m_probeProcess) {
        m_probeProcess=new QProcess(this);
        connect(m_probeProcess,QOverload<int,QProcess::ExitStatus>::of(&QProcess::finished),
                this,&MainWindow::onProbeFinished);
    }
    if(m_probeProcess->state()!=QProcess::NotRunning) m_probeProcess->kill();
    m_probeProcess->start(m_fileEncryptorPath,QStringList{QStringLiteral("--features")});
    // 单发定时器：超时（1s）即 kill，维持默认乐观值（zstd 不可用 / aegis 可用）
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
    // CLI 输出按 UTF-8（GUI 读 CLI 输出统一 fromUtf8 约定）
    const QString out=QString::fromUtf8(m_probeProcess->readAllStandardOutput());
    m_zstdAvailable=out.contains(QStringLiteral("zstd=1"));
    // aegis=1 → 支持；aegis=0 → 不支持（缺 AES-NI）；缺省行按支持处理
    if(out.contains(QStringLiteral("aegis=0"))) m_aegisAvailable=false;
    else if(out.contains(QStringLiteral("aegis=1"))) m_aegisAvailable=true;
    updateAsymVisibility();   // 探测完成后刷新压缩/非对称控件可用性
}

void MainWindow::onRetryCliDetection() {
    if(FileEncryptorLocator::existsWithVersion(&m_fileEncryptorPath)) {
        setStatus(tr("就绪 | FileEncryptor: %1").arg(m_fileEncryptorPath));
        MsgBox::info(this,tr("检测成功"),
            tr("已找到 CLI 程序：\n%1").arg(m_fileEncryptorPath));
        // 重新探测 zstd 能力并刷新压缩控件状态
        probeZstdSupport();
        updateAsymVisibility();
    }
    else {
        showCliNotFoundError(tr("手动重试"));
    }
}

// ---------- 运行/取消按钮样式（主题感知，保证深色下文字清晰）----------
void MainWindow::applyButtonStyles() {
    const bool dark=ThemeManager::isDarkActive();
    // 运行按钮：浅色下用柔化绿（#4A7C50）+ 白字，降低饱和度；深色下亮绿
    m_btnRun->setStyleSheet(
        dark
        ? "QPushButton{background:#43A047;color:#FFFFFF;padding:6px 18px;font-weight:bold;border-radius:4px;}"
        "QPushButton:hover{background:#66BB6A;}"
        : "QPushButton{background:#4A7C50;color:white;padding:6px 18px;font-weight:bold;border-radius:4px;}"
        "QPushButton:hover{background:#3D6B4A;}");
    m_btnCancel->setStyleSheet(
        dark
        ? "QPushButton{background:#E53935;color:#FFFFFF;padding:6px 18px;font-weight:bold;border-radius:4px;}"
        "QPushButton:hover{background:#EF5350;}"
        "QPushButton:disabled{background:#555;color:#ccc;}"
        : "QPushButton{background:#C0392B;color:white;padding:6px 18px;font-weight:bold;border-radius:4px;}"
        "QPushButton:hover{background:#A93226;}"
        "QPushButton:disabled{background:#999;color:#eee;}");
    if(m_btnRewrap)
        m_btnRewrap->setStyleSheet(
            dark
            ? "QPushButton{background:#3D3D40;color:#E6E6E6;border:1px solid #4A4A4D;border-radius:3px;padding:4px 10px;}"
              "QPushButton:hover{background:#4A4A4D;}"
              "QPushButton:disabled{background:#3D3D40;color:#999999;}"
            : "QPushButton{background:#ECECEA;color:#333333;border:1px solid #C8C8C4;border-radius:3px;padding:4px 10px;}"
              "QPushButton:hover{background:#DCDCD8;}"
              "QPushButton:disabled{background:#ECECEA;color:#999999;}");
}

// ---------- 左侧文件选择面板 ----------
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

// ---------- 中部主要功能区 ----------
QWidget* MainWindow::buildCenterPanel() {
    auto* w=new QWidget;
    m_centerPanel=w;
    auto* lay=new QGridLayout(w);
    lay->setColumnStretch(1,1);

    int row=0;

    // 动作模式
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

    // 加密模式
    auto* lblMode=new QLabel(tr("加密模式"));
    lay->addWidget(lblMode,row,0);
    m_modeCombo=new QComboBox;
    m_modeCombo->addItem(tr("XChaCha20-Poly1305（默认，兼容性最好）"),static_cast<int>(CryptoMode::XChaCha20));
    m_modeCombo->addItem(tr("AEGIS-256（需 AES-NI 指令）"),static_cast<int>(CryptoMode::Aegis256));
    m_modeCombo->addItem(tr("X25519 + ChaCha20-Poly1305（非对称）"),static_cast<int>(CryptoMode::Asymmetric));
    lay->addWidget(m_modeCombo,row,1);
    row++;

    // zstd 压缩（v5 磁盘格式；仅对称加密有意义，非对称 rage 由 CLI 拒绝）
    m_compressTitle=new QLabel(tr("压缩"));
    lay->addWidget(m_compressTitle,row,0);
    auto* compRow=new QHBoxLayout;
    m_chkCompress=new QCheckBox(tr("压缩数据"));
    m_chkCompress->setToolTip(tr("加密时逐块 zstd 压缩（磁盘格式 v5，旧版本 CLI 无法读取）。\n"
                                 "仅对称加密有效；输出名混淆下压缩率统计见 CLI 详细输出。"));
    m_compressLabel=new QLabel(tr("压缩级别 (0-22)："));
    m_compressLevel=new QSpinBox;
    m_compressLevel->setRange(-5,22);
    m_compressLevel->setValue(3);   // zstd 默认级别
    m_compressLevel->setToolTip(tr("zstd 级别：1..22 常规（越大越慢、压缩率越高），-1..-5 快速档；默认 3\n"
                                   "直接键入数值，回车或移开焦点后生效；也可用键盘 ↑/↓ 微调"));
    // 输入体验：右对齐、固定宽度、无上下按钮（纯数字输入框，配色与输入框一致，
    // 按用户要求移除与整体风格不符的箭头控件）；键盘 ↑/↓ 仍可微调。
    m_compressLevel->setButtonSymbols(QAbstractSpinBox::NoButtons);
    m_compressLevel->setAlignment(Qt::AlignRight);
    m_compressLevel->setKeyboardTracking(false);
    m_compressLevel->setFixedWidth(84);
    // 中心面板是 background:transparent 的样式表层级，QSpinBox 若无显式样式会渲染退化
    // （内部输入框透明导致看似无法编辑）；统一样式在 applyPanelTransparency() 里随主题设置。
    compRow->addWidget(m_chkCompress);
    compRow->addWidget(m_compressLabel);
    compRow->addWidget(m_compressLevel);
    compRow->addStretch();
    lay->addLayout(compRow,row,1);
    row++;

    // 非对称（age / X25519）输入区
    m_asymWidget=new QGroupBox(tr("非对称加密"));
    {
        auto* av=new QVBoxLayout(m_asymWidget);
        av->setContentsMargins(8,8,8,8);
        av->setSpacing(6);
        auto* intro=new QLabel(tr("混合加密：随机生成的文件密钥用 X25519 公钥封装（rage/age 格式）。\n"
                                  "加密只需要公钥（可公开），解密才需要私钥。"));
        intro->setWordWrap(true);
        av->addWidget(intro);

        // 收件人公钥（加密）
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

        // 身份私钥（解密）
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

    // rage 密钥动作（-g 随机生成 / -G 口令派生 / -Y 导出公钥）：只需要输出目录或密钥材料
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

    // 输出目录
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

    // 密钥文件
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

    // 选项
    auto* lblOpts=new QLabel(tr("选项"));
    lay->addWidget(lblOpts,row,0);
    auto* optsRow=new QHBoxLayout;
    // 源文件处理：加密成功后对原文件的处置方式（保留 / 删除 / 回收站 / 安全擦除）
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

    // 运行/取消 + 密钥轮换按钮
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

// ---------- 下部只读文本框 ----------
QWidget* MainWindow::buildBottomPanel() {
    auto* w=new QWidget;
    m_bottomPanel=w;
    auto* lay=new QVBoxLayout(w);
    lay->setContentsMargins(0,0,0,0);

    auto* headerRow=new QHBoxLayout;
    headerRow->setContentsMargins(0,0,0,0);
    headerRow->addWidget(new QLabel(tr("<b>命令浏览与执行输出</b>")));
    headerRow->addStretch();
    // 功能5：历史面板入口
    m_btnTaskHistory=new QPushButton(tr("任务历史..."));
    m_btnTaskHistory->setToolTip(tr("查看任务历史记录，双击一条可回填参数（回放）"));
    headerRow->addWidget(m_btnTaskHistory);
    lay->addLayout(headerRow);

    // 功能6：批量进度帧直接在 m_outputView（拟 cmd）内原地整帧刷新，
    // 不再使用独立面板（空闲态常驻的 TOTAL/ETA 行显得突兀，用户已下线）。
    m_outputView=new QPlainTextEdit;
    m_outputView->setReadOnly(true);
    // 拟 cmd：禁止自动折行（进度行超宽时横向滚动兜底，保证每条进度条独占一行不折行）
    m_outputView->setLineWrapMode(QPlainTextEdit::NoWrap);
    // 加大最小垂直高度：批量帧为 1 汇总行 + N 线程行（N=CPU 核数），
    // 预留足够行数避免帧内容被遮挡/溢出
    m_outputView->setMinimumHeight(360);
    m_outputView->setPlaceholderText(tr("此处显示命令预览与执行输出。stdout 默认色，stderr 红色。"));
    // 等宽字体便于对齐
    m_outputView->setFont(FontBootstrap::monoFont());
    // 输出文档上限 5000 块防无限增长：超出自动从头部裁剪，配合 renderFrameLine 的块锚点回退追加
    m_outputView->document()->setMaximumBlockCount(5000);
    lay->addWidget(m_outputView);

    return w;
}

// ---------- 信号连接 ----------
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

    // 选项变化刷新命令预览
    auto refresh=[this]{ refreshCommandPreview(); };
    connect(m_actionGroup,&QButtonGroup::idClicked,this,refresh);
    connect(m_modeCombo,QOverload<int>::of(&QComboBox::currentIndexChanged),this,refresh);
    connect(m_outDirEdit,&QLineEdit::textChanged,this,refresh);
    connect(m_keyfileEdit,&QLineEdit::textChanged,this,refresh);
    connect(m_sourceCombo,QOverload<int>::of(&QComboBox::currentIndexChanged),this,refresh);
    connect(m_chkForce,&QCheckBox::stateChanged,this,refresh);
    connect(m_chkSha256,&QCheckBox::stateChanged,this,refresh);
    // 压缩：勾选变化同时联动级别框可用性（updateAsymVisibility 内统一裁决）
    connect(m_chkCompress,&QCheckBox::stateChanged,this,refresh);
    connect(m_chkCompress,&QCheckBox::stateChanged,this,[this](int){ updateAsymVisibility(); });
    connect(m_compressLevel,QOverload<int>::of(&QSpinBox::valueChanged),this,refresh);
    // 文件列表勾选框切换 → 刷新命令预览（仅勾选项进入命令）
    connect(m_fileList,&QListWidget::itemChanged,this,refresh);

    // 浏览按钮
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

    // 非对称（age / X25519）：收件人公钥文件 / 身份私钥文件 浏览
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
    // 任务历史面板（功能5）
    connect(m_btnTaskHistory,&QPushButton::clicked,this,&MainWindow::onOpenTaskHistory);

    // 输入清单变化 → 重算待处理规模（字节/文件数）并刷新批量面板的空闲预估
    connect(m_fileList,&QListWidget::itemChanged,this,[this]{ recomputePending(); });
    // 模式切换：刷新非对称输入区可见性
    connect(m_modeCombo,QOverload<int>::of(&QComboBox::currentIndexChanged),
        this,&MainWindow::updateAsymVisibility);
    connect(m_actionGroup,&QButtonGroup::idClicked,
        this,[this](int){ updateAsymVisibility(); });
}

// ---------- 动作/模式切换：刷新 rage 相关控件的可见性 ----------
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

    // rage 密钥动作固定锁定到非对称算法（第三个）并禁用下拉
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

    // zstd 压缩：仅「加密/批量加密」显示整行（非对称由 CLI 拒绝）；级别框始终可编辑
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

    // 本函数改变影响 argv 的状态，统一在此刷新预览，避免各调用点遗漏
    refreshCommandPreview();
}

// ---------- 文件选择 ----------
void MainWindow::addInputPaths(const QStringList& paths) {
    // 去重：已存在的路径不重复加入（拖放重复拖同一文件是常见操作）
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
        // 单文件动作（-e/-d）不支持目录输入：加入目录时自动切换为对应批量动作，
        // 否则 CLI 会以 "Input is a directory" 拒绝整次任务
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
    resetPendingCache();       // 输入集合变化 → 作废扫描缓存
    recomputePending();   // 功能6：输入变化即刷新待处理规模与 ETA
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
    recomputePending();   // 功能6：清空后 ETA 归零
}

// ---------- 拖放（功能4） ----------
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
        // 目录与文件都允许加入：目录走批量动作（-be/-bd），文件走单/批量动作
        paths<<QDir::toNativeSeparators(p);
    }
    if(!paths.isEmpty()) {
        e->acceptProposedAction();
        addInputPaths(paths);
    }
}

// ---------- 收集选项 ----------
ShellOptions MainWindow::collectOptions() const {
    ShellOptions o;
    o.action=static_cast<CryptoAction>(m_actionGroup->checkedId());
    o.mode=static_cast<CryptoMode>(m_modeCombo->currentData().toInt());

    for(int i=0; i<m_fileList->count(); ++i) {
        auto* it=m_fileList->item(i);
        if(it->checkState()==Qt::Checked) o.inputPaths<<it->text();
    }

    o.outputDir=m_outDirEdit->text().trimmed();
    // 加密后源文件处置：0=保留 1=删除 3=回收站 2=安全擦除（与 CLI source_action 一致）
    o.sourceDisposition=m_sourceCombo ? m_sourceCombo->currentData().toInt() : 0;
    o.forceOverwrite=m_chkForce->isChecked();
    o.writeSha256=m_chkSha256->isChecked();
    o.keyfilePath=m_keyfileEdit->text().trimmed();
    // zstd 压缩：开关与级别分离 —— compress 是布尔开关（-zstd），级别仅在勾选时下发。
    // 非对称/解密等场景由 CliArgBuilder 再次把关（不下发任何压缩参数）。
    o.compress=m_chkCompress->isChecked();
    o.compressionLevel=o.compress ? m_compressLevel->value() : 0;
    // 口令不再存于主页面：运行时经 PasswordDialog 弹窗获取（见 onRunClicked）

    // 非对称收件人：支持多收件人（逗号/分号分隔 age1... 公钥串）；此处仅统计条数，写临时公钥文件推迟到运行时
    const QString rawRecip=m_recipientEdit->text().trimmed();
    o.recipientPath=rawRecip;
    o.recipientCount=0;
    for(const QString& seg:rawRecip.split(QRegularExpression(QStringLiteral("[,，;；]")),Qt::SkipEmptyParts)) {
        if(!seg.trimmed().isEmpty()) ++o.recipientCount;
    }
    o.identityPath=m_identityEdit->text().trimmed();
    // Asymmetric decryption: the private key file is handed to the CLI as -k.
    {
        const bool asymDecrypt=(o.mode==CryptoMode::Asymmetric)&&
            (o.action==CryptoAction::Decrypt||o.action==CryptoAction::BatchDecrypt);
        if(asymDecrypt) o.keyfilePath=o.identityPath;
        else if(o.action==CryptoAction::PubKey) o.keyfilePath=o.identityPath;   // -Y 从私钥文件读身份
        else if(o.mode==CryptoMode::Asymmetric) o.keyfilePath.clear(); // asym encrypt needs no key file
    }

    return o;
}

// ---------- 多收件人归一化（功能8） ----------
QString MainWindow::resolveRecipients(const QString& raw) const {
    // 多条且全部为 age1... 公钥串时写临时文件走 -r 通道；其余原样返回由 CLI 校验
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
    if(!m_recipientTempFile.isEmpty()) QFile::remove(m_recipientTempFile);
    const QString tmp=QDir::tempPath()+QStringLiteral("/fileencryptor_recipients_%1.txt")
        .arg(QCoreApplication::applicationPid());
    QSaveFile f(tmp);
    if(!f.open(QIODevice::WriteOnly|QIODevice::Text)) return raw.trimmed(); // 写失败回退
    for(const QString& k:parts) f.write((k+QLatin1Char('\n')).toUtf8());
    if(!f.commit()) return raw.trimmed();
    m_recipientTempFile=tmp;
    return tmp;
}

// ---------- 运行 ----------
void MainWindow::onRunClicked() {
    // 检测 CLI 是否存在
    if(!checkCliExists(true)) {
        return;  // 用户取消或重试失败，阻止继续
    }

    // 检查是否已经存在（双重保险）
    if(m_fileEncryptorPath.isEmpty()) {
        // 再次尝试定位
        m_fileEncryptorPath=FileEncryptorLocator::locate();
        if(m_fileEncryptorPath.isEmpty()) {
            showCliNotFoundError(tr("运行前检测"));
            return;
        }
    }

    ShellOptions o=collectOptions();

    // 功能8：多收件人临时公钥文件【仅运行时】写盘（pending 扫描不会触发，避免残留临时文件）。
    // 单收件人或普通路径原样返回；多条公钥串才写临时文件供 -r 通道使用。
    o.recipientPath=resolveRecipients(o.recipientPath);

    // AEGIS-256 非交互一致性：选中 AEGIS-256 但本机探测到不支持（缺 AES-NI）时，
    // 弹窗明确警告并中止任务，与 CLI 非交互「明确拒绝、绝不自动降级」行为完全一致。
    if(o.mode==CryptoMode::Aegis256 && !m_aegisAvailable) {
        MsgBox::error(this, tr("AEGIS-256 不可用"),
            tr("当前 CPU 不支持 AES-NI，AEGIS-256 在此环境下会极慢且抗侧信道能力弱。\n"
               "请改用 XChaCha20-Poly1305（默认模式）。"));
        return;
    }

    // 校验
    const bool isKeyGen=(o.action==CryptoAction::KeyGen);
    const bool isDerive=(o.action==CryptoAction::Derive);
    const bool isPubKey=(o.action==CryptoAction::PubKey);
    const bool noInputNeeded=(isKeyGen||isDerive||isPubKey);  // 三个 rage 密钥动作都不处理输入文件
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
        // 随机生成：不需要公钥，也不需要口令
    } else if(isDerive) {
        // 口令在下方弹窗获取并校验（策略 + 二次确认）
    } else if(isPubKey) {
        if(o.identityPath.isEmpty()) {
            MsgBox::warn(this,tr("缺少私钥"),
                tr("请先在「私钥文件」中选择包含 AGE-SECRET-KEY-... 的文件。"));
            m_identityEdit->setFocus();
            return;
        }
    } else if(isAsym) {
        // 非对称模式：不使用对称密码；加密需收件人公钥，解密需身份私钥
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

    // ---------- 对称模式口令（PIN 风格弹窗，默认星号掩码 / 按住显示 / 松开恢复） ----------
    bool symNeedsPassword = !isAsym && o.keyfilePath.isEmpty()
        && (o.action==CryptoAction::Encrypt || o.action==CryptoAction::BatchEncrypt
            || o.action==CryptoAction::Decrypt || o.action==CryptoAction::BatchDecrypt
            || o.action==CryptoAction::Derive);
    std::vector<unsigned char> pw;
    if(symNeedsPassword) {
        if(o.action==CryptoAction::BatchDecrypt) {
            // 缺陷修复：批量解密每文件完整执行 KDF 还原文件名很慢；警告用户是否启用
            o.restoreName = MsgBox::confirm(this, tr("批量解密文件名"),
                tr("批量解密将对每个文件执行昂贵的密钥派生（KDF）以还原完整原始文件名，可能很慢。\n"
                   "是否启用「完整文件名还原」？\n（无论是否启用，输出文件的扩展名都会保留。）"));
        }
        PasswordDialog dlg(this);
        dlg.setPurpose(isDerive ? tr("口令派生") : (isEnc ? tr("加密口令") : tr("解密口令")));
        dlg.setRequireConfirm(o.action==CryptoAction::Encrypt
            || o.action==CryptoAction::BatchEncrypt || o.action==CryptoAction::Derive);
        if(dlg.exec()!=QDialog::Accepted) return;   // 用户取消
        pw = dlg.takePassword();
        if(pw.empty()) return;
    }

    // 构建命令
    CommandRequest req;
    req.programPath=m_fileEncryptorPath;
    req.arguments=CliArgBuilder::buildArguments(o);
    req.extraEnv=CliArgBuilder::buildEnvironment(o);
    // CLI 统计文件：批量结束时写 JSON（total_bytes/files_done/files_failed/files_skipped/total_files）
    m_statsFile=QDir::tempPath()+QStringLiteral("/fe_stats_%1.json").arg(QCoreApplication::applicationPid());
    req.extraEnv.insert(QStringLiteral("FILEENCRYPTOR_STATS_FILE"),m_statsFile);
    // 功能6：批量模式让 CLI 输出「帧式进度」（1 行汇总 + 每线程 1 行），
    // GUI 解析整帧后在拟 cmd 输出区原地刷新，字段与 CLI 终端显示完全一致。
    if(o.action==CryptoAction::BatchEncrypt||o.action==CryptoAction::BatchDecrypt) {
        req.extraEnv.insert(QStringLiteral("FILEENCRYPTOR_PROGRESS_FRAME"),QStringLiteral("1"));
        // 帧宽按输出区可用宽度注入（等宽字符列数），保证不会折行/跳动
        const QFontMetrics fm(m_outputView->font());
        const int cw=fm.horizontalAdvance(QLatin1Char('M'));
        int cols=cw>0?(m_outputView->viewport()->width()-8)/cw:100;
        cols=qBound(60,cols,200);
        req.extraEnv.insert(QStringLiteral("COLUMNS"),QString::number(cols));
    }

    // Key material injected via child's stdin (never env/argv): symmetric password from `pw`; asym uses -r/-k.
    if(!(isKeyGen||isPubKey) && !isAsym && o.keyfilePath.isEmpty() && !pw.empty()) {
        req.stdinData=QByteArray(reinterpret_cast<const char*>(pw.data()),(int)pw.size());
    }

    // 立即擦除内存中的口令副本（stdin 已写入子进程，见 ProcessCommandExecutor::execute）
    if(!pw.empty()) {
        // v2.1.2：std::memset 后紧跟 clear()，编译器可判定为 dead store 而整段优化掉，
        // 口令明文会一直留在堆上。改用 volatile 逐字节写零，确保真正落到内存。
        secure_zero(pw.data(),pw.size());
        pw.clear();
    }

    // 输出区清空并显示命令预览
    m_outputView->clear();
    const QString preview=CliArgBuilder::buildPreview(m_fileEncryptorPath,o);
    appendOutput(QStringLiteral(">>> %1\n").arg(preview),false);
    appendOutput(QStringLiteral("--- 执行开始 ---\n"),false);

    // UI 状态切换
    m_btnRun->setEnabled(false);
    m_btnCancel->setEnabled(true);
    m_runFileStarts=0;   // 功能11：重新统计本次运行的文件开始标记
    m_doneFiles=0; m_skipFiles=0; m_failFiles=0; m_totalFiles=0;
    m_currentFile.clear();
    m_frameBlock=QTextBlock();  // 批量进度帧块随新任务重建
    m_frameLen=0;
    updateProgressLabel();
    setStatus(tr("运行中..."));

    // 功能5：登记本次任务（结束时补全结果写入历史）
    beginTaskRecord(o);

    m_executor->execute(req);
    // v2.1.2：QByteArray::clear() 只减引用计数、**不清零**，口令明文会留在堆上直到被复用。
    // 先逐字节写零再释放（secure_zero 用 volatile 写，不会被优化掉）。
    if(!req.stdinData.isEmpty()) {
        secure_zero(req.stdinData.data(),(size_t)req.stdinData.size());
        req.stdinData.clear();
    }
}

// ---------- 密钥轮换（v6 容器 rewrap） ----------
// 旧口令走 --key-stdin，新口令写临时文件走 --new-key-file；载荷密文不动，仅重裹 DEK。
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

    // 旧口令：解开当前容器
    std::vector<unsigned char> oldPw;
    {
        PasswordDialog dlg(this);
        dlg.setPurpose(tr("旧口令（当前容器口令）"));
        dlg.setRequireConfirm(false);
        if(dlg.exec()!=QDialog::Accepted) return;
        oldPw=dlg.takePassword();
        if(oldPw.empty()) return;
    }
    // 新口令：重裹后的容器口令
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

    // 新口令经临时密钥文件注入（CLI --new-key-file），结束后删除
    const QString tmp=QDir::tempPath()+QStringLiteral("/fileencryptor_rewrap_%1.key")
        .arg(QCoreApplication::applicationPid());
    QFile::remove(tmp);
    {
        QSaveFile f(tmp);
        if(!f.open(QIODevice::WriteOnly)) {
            MsgBox::error(this,tr("密钥轮换"),tr("无法写入临时新口令文件。"));
            secure_zero(oldPw.data(),oldPw.size()); oldPw.clear();
            secure_zero(newPw.data(),newPw.size()); newPw.clear();
            return;
        }
        f.write(reinterpret_cast<const char*>(newPw.data()),(qint64)newPw.size());
        if(!f.commit()) {
            MsgBox::error(this,tr("密钥轮换"),tr("无法落盘临时新口令文件。"));
            secure_zero(oldPw.data(),oldPw.size()); oldPw.clear();
            secure_zero(newPw.data(),newPw.size()); newPw.clear();
            return;
        }
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
    appendOutput(QStringLiteral("--- 密钥轮换（载荷密文不动） ---\n"),false);

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

// ---------- 执行回显 ----------
void MainWindow::onOutputLine(const OutputLine& line) {
    // 进度帧按 120ms 合并渲染，避免每帧整帧替换+滚动拖慢界面
    if(line.isFrame) {
        m_pendingFrame=line;
        m_framePending=true;
        if(!m_frameTimer->isActive()) m_frameTimer->start();
        return;
    }
    if(line.isProgress) {
        // 进度行原地替换，避免重复堆积/清屏异常
        const unsigned int rgb=line.isError ? ThemeManager::stderrColorRGB()
            : ThemeManager::stdoutColorRGB();
        QTextCharFormat fmt;
        fmt.setForeground(QColor((rgb>>16)&0xFF,(rgb>>8)&0xFF,rgb&0xFF));
        QTextCursor cur=m_outputView->textCursor();
        cur.movePosition(QTextCursor::End);
        if(m_lastProgressLine) {
            // 上一行即进度行 → 替换它
            cur.movePosition(QTextCursor::StartOfLine);
            cur.movePosition(QTextCursor::EndOfLine,QTextCursor::KeepAnchor);
            cur.insertText(line.text,fmt);
        } else {
            // 首条进度 → 换行后另起一行，保留上一普通行
            cur.insertText(QStringLiteral("\n")+line.text,fmt);
        }
        m_lastProgressLine=true;
        QScrollBar* bar=m_outputView->verticalScrollBar();
        bar->setValue(bar->maximum());
        return;
    }
    m_lastProgressLine=false;
    // 统计 Encrypting:/Decrypting: 标记：取消时汇总已完成数，并显示当前文件（单文件模式唯一来源）
    if(line.text.startsWith(QLatin1String("Encrypting: "))||
       line.text.startsWith(QLatin1String("Decrypting: "))) {
        ++m_runFileStarts;
        m_currentTask.filesDone=m_runFileStarts;   // 功能5：记录已完成文件数（取消时也保留）
        const int arrow=line.text.indexOf(QStringLiteral(" -> "));
        m_currentFile=(arrow>0) ? line.text.mid(12,arrow-12).trimmed()
                                : line.text.mid(12).trimmed();
        updateProgressLabel();
    }
    // 已完成条目计入「跳过」
    else if(line.text.startsWith(QLatin1String("Skipped: "))) {
        ++m_skipFiles;
        updateProgressLabel();
    }
    // 单文件失败（口令错误 / 文件损坏等）：CLI 已打印原因并继续后续文件，此处只累加计数
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

// 进度帧渲染：整帧原地替换（区间失效则追加自愈），并从 FILES 末行与槽位行解析实时计数
void MainWindow::renderFrameLine(const OutputLine& line) {
    QStringList lines=line.text.split(QLatin1Char('\n'));
    while(!lines.isEmpty()&&lines.last().trimmed().isEmpty()) lines.removeLast();
    if(lines.isEmpty()) return;

    // 解析计数：FILES 末行给完成/跳过/失败，槽位行首列为当前文件
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

    // —— 渲染 ——
    const QString block=lines.join(QLatin1Char('\n'))+QLatin1Char('\n');
    const unsigned int rgb=ThemeManager::stdoutColorRGB();
    QTextCharFormat fmt;
    fmt.setForeground(QColor((rgb>>16)&0xFF,(rgb>>8)&0xFF,rgb&0xFF));

    bool replaced=false;
    // 用 QTextBlock 句柄锚定帧首块：position() 随文档裁剪（setMaximumBlockCount）
    // 自动前移，因此字符偏移无需自行维护；块被裁掉则 isValid() 失效 → 回退追加。
    if(m_frameBlock.isValid()&&m_frameLen>0) {
        const int pos=m_frameBlock.position();
        const int docLen=m_outputView->document()->characterCount();
        if(pos>=0&&pos+m_frameLen<=docLen
           // 区间自愈：帧首不再是汇总行 'T' 即视为失效，放弃替换、回退追加，避免残影
           &&m_outputView->document()->characterAt(pos)==QLatin1Char('T')) {
            QTextCursor sel(m_outputView->document());
            sel.setPosition(pos);
            sel.setPosition(pos+m_frameLen,QTextCursor::KeepAnchor);
            sel.insertText(block,fmt);   // 原地整帧替换（新旧帧长度可不同）
            replaced=true;
        }
    }
    if(!replaced) {
        // 首帧或区间失效：追加新帧块到文档末尾，记录其首块句柄
        QTextCursor cur=m_outputView->textCursor();
        cur.movePosition(QTextCursor::End);
        const int base=cur.position();
        cur.insertText(QStringLiteral("\n")+block,fmt);
        QTextCursor anchor(m_outputView->document());
        anchor.setPosition(base+1);          // 前导换行之后即帧首
        m_frameBlock=anchor.block();
    }
    m_frameLen=block.size();
    m_lastProgressLine=false;
    QScrollBar* bar=m_outputView->verticalScrollBar();
    bar->setValue(bar->maximum());
}

// 状态栏右侧计数条：运行中实时刷新 当前文件/完成/跳过/失败；空闲展示待处理规模
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
    if(!m_rewrapTempKey.isEmpty()) {          // rewrap 的新口令只用于本次运行
        QFile::remove(m_rewrapTempKey);
        m_rewrapTempKey.clear();
    }
    // 收尾前把节流中未渲染的最后一帧刷出，保证计数与进度条终态一致
    if(m_framePending) flushPendingFrame();
    finishTaskRecord(r);         // 功能5：结果落盘

    QString summary;
    if(r.wasCancelled) {
        // 功能11：取消不回滚已完成的输出。最后一个已开始的文件可能被中断，
        // 以「文件开始标记数 - 1」估算已保留的完成文件数；重跑同一任务可从 .prs 续传。
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
    // 运行终态汇总：失败/跳过计数非 0 时一并提示，呼应「记录并提示后继续」
    if(m_failFiles>0||m_skipFiles>0) {
        summary+=tr("\n（完成 %1 / 跳过 %2 / 失败 %3）")
                    .arg(m_doneFiles).arg(m_skipFiles).arg(m_failFiles);
    }
    appendOutput(QStringLiteral("\n%1\n").arg(summary),r.exitCode!=0);
    // 任务结束：源文件集合已变化（部分被删除/移回收站），作废缓存并重新统计待处理规模
    resetPendingCache();
    recomputePending();
    updateProgressLabel();

    // 任务完成汇总弹窗（仅成功/失败的批量或加密任务，非取消）
    if(!r.wasCancelled && (m_doneFiles>0||m_failFiles>0)) {
        // 计算加密后大小（扫描输出目录 .ptd）
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

    // 任务完成提醒：窗口有焦点则弹窗，否则发系统通知
    const QString notifyTitle = tr("任务完成");
    const QString notifyBody = summary.remove(QStringLiteral("---")).trimmed();
    if (isActiveWindow()) {
        QMessageBox::information(this, notifyTitle, notifyBody);
    } else if (m_trayIcon && QSystemTrayIcon::isSystemTrayAvailable()) {
        m_trayIcon->showMessage(notifyTitle, notifyBody, QSystemTrayIcon::Information, 5000);
    }
}

// ---------- 功能5 / 功能6：任务历史与批量进度面板 ----------
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

// 工作线程递归统计规模；命中缓存的输入不再遍历（勾选/取消频繁重算，无缓存会反复全盘扫）
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

// 仅做防抖登记，真正扫描在工作线程完成（UI 线程递归大目录会卡顿数百毫秒~数秒）
void MainWindow::recomputePending() {
    if(!m_pendingTimer) return;
    m_pendingTimer->start();
}

// 输入变化（新增/清空/回放）→ 缓存的整体统计失效，作废
void MainWindow::resetPendingCache() {
    m_dirCache.clear();
}

void MainWindow::startPendingScan() {
    if(m_scanWatcher->isRunning()) {
        // 上一轮还在扫：请求其尽快退出并标记补扫，避免排队堆积
        if(m_scanCancel) m_scanCancel->store(true,std::memory_order_relaxed);
        m_scanRestartPending=true;
        return;
    }
    m_scanCancel=std::make_shared<std::atomic<bool>>(false);
    auto cancel=m_scanCancel;
    const QStringList paths=collectOptions().inputPaths;
    // 以共享快照传入工作线程：按值捕获 shared_ptr（仅原子增引用计数，不拷贝整张 QHash），
    // 既避免每轮整表拷贝，又因快照不可变、主线程仅在扫描结束后回填而天然无竞态。
    auto cache=std::make_shared<const QHash<QString,DirStat>>(m_dirCache);
    m_scanWatcher->setFuture(QtConcurrent::run(
        [paths,cache,cancel]{ return scanInputs(paths,cache,cancel); }));
}

void MainWindow::onPendingScanFinished() {
    const ScanResult r=m_scanWatcher->result();
    if(m_scanRestartPending) {
        m_scanRestartPending=false;
        startPendingScan();     // 有更新请求：丢弃本轮结果，按最新输入重扫
        return;
    }
    if(!r.complete) return;     // 被取消的半截结果不入库，也不覆盖上一次的有效值
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
    m_currentTask.inputPaths=o.inputPaths;   // 回放时据原路径恢复输入列表
    m_currentTask.totalBytes=m_pendingBytes;
    m_currentTask.outputDir=o.outputDir;
    // 完整参数快照（用于任务回放）
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
    // 优先用 CLI 统计文件（精确），其次用帧/逐文件计数，最后回退「文件开始标记数」
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
    m_currentTask=TaskRecord();     // 先摘出再清空，避免落盘期间被后续运行覆盖
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

// 回放：把历史记录的动作/模式/输出目录回填到主窗口（输入路径需用户自行选择）
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

    // 完整参数回放
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

    // 输入路径随记录回填：把该次任务处理的文件/文件夹恢复到输入列表原位
    if(!rec.inputPaths.isEmpty()) {
        m_fileList->clear();
        addInputPaths(rec.inputPaths);
    }

    updateAsymVisibility();
    refreshCommandPreview();
    recomputePending();
    setStatus(tr("已回填历史任务参数：%1").arg(rec.actionLabel));
}

// ---------- 输出追加 + 自动滚动 ----------
void MainWindow::appendOutput(const QString& text,bool isError) {
    // 输出框背景随主题：亮色浅灰底→深字，暗色深底→浅字
    const unsigned int rgb=isError ? ThemeManager::stderrColorRGB()
        : ThemeManager::stdoutColorRGB();
    QTextCharFormat fmt;
    fmt.setForeground(QColor((rgb>>16)&0xFF,(rgb>>8)&0xFF,rgb&0xFF));
    QTextCursor cur=m_outputView->textCursor();
    cur.movePosition(QTextCursor::End);
    cur.insertText(text,fmt);
    // 自动滚到底
    QScrollBar* bar=m_outputView->verticalScrollBar();
    bar->setValue(bar->maximum());
}

// ---------- 命令预览刷新 ----------
void MainWindow::refreshCommandPreview() {
    // 仅在空闲时刷新预览（运行中不打断回显）；不做文本嗅探，一律整块重绘
    if(m_executor&&m_executor->isRunning()) return;
    const ShellOptions o=collectOptions();
    const QString preview=CliArgBuilder::buildPreview(m_fileEncryptorPath,o);
    m_outputView->clear();
    appendOutput(QStringLiteral(">>> 命令预览: %1\n").arg(preview),false);
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
