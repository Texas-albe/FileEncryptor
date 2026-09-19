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
#include "TaskHistoryDialog.h"
#include <vector>
#include <cstring>

// 安全擦除：std::memset 紧跟着释放/clear 会被编译器判定为 dead store 而优化掉，
// 口令明文因此长期残留在堆上（审计问题 9）。用 volatile 指针逐字节写零可确保落内存。
static void secure_zero(void* p,size_t n) {
    if(!p||n==0) return;
    volatile unsigned char* vp=static_cast<volatile unsigned char*>(p);
    while(n--) *vp++=0;
}

#include <QMenuBar>
#include <QApplication>
#include <QStatusBar>
#include <QMenu>
#include <QAction>
#include <QActionGroup>
#include <QFileDialog>
#include <QListWidget>
#include <QPlainTextEdit>
#include <QLineEdit>
#include <QLabel>
#include <QComboBox>
#include <QRadioButton>
#include <QCheckBox>
#include <QSpinBox>
#include <QProcess>
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

MainWindow::MainWindow(QWidget* parent): QMainWindow(parent) {
    // 标题含版本号（缺陷18：兜底值统一取 FileEncryptorLocator::guiVersion()，不再各自硬编码）
    setWindowTitle(QStringLiteral("FileEncryptorGUI %1").arg(
        qApp->applicationVersion().isEmpty() ? FileEncryptorLocator::guiVersion()
        : qApp->applicationVersion()));
    resize(1200,760);

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

    // 中央布局：左 | 中 | 下
    // 口令输入已移至运行期弹窗（PasswordDialog），主页面不再保留独立口令提示区，
    // 让中央选项面板自然占满横向空间，布局更连贯。
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
    setStatus(m_fileEncryptorPath.isEmpty()
        ? tr("未找到 FileEncryptor 可执行文件 — 请设置环境变量 FILEENCRYPTOR_EXE 或将其置于本程序同目录")
        : tr("就绪 | FileEncryptor: %1").arg(m_fileEncryptorPath));

    connectSignals();
    // zstd 能力探测（同步 QProcess，--features 秒回），随后按结果裁决压缩控件初始状态
    probeZstdSupport();
    updateAsymVisibility();
    refreshCommandPreview();
}

MainWindow::~MainWindow()=default;

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
    // v1.3.0：密钥库管理与批量 ETA 入口已从工具菜单移除（密钥库功能已整体下线，
    // 批量 ETA 迁到拟命令行上部的「批量进度面板」），菜单仅保留「任务历史」。
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

    // 文件列表：随主题——亮色浅灰底+深字，暗色深底+浅字
    if(m_fileList) {
        m_fileList->setStyleSheet(QStringLiteral(
            "QListWidget{background:%1;color:%2;border:1px solid %3;"
            "border-radius:3px;outline:0;}"
            "QListWidget::item{background:%1;color:%2;padding:2px 4px;}"
            "QListWidget::item:alternate{background:%4;}"
            "QListWidget::item:selected{background:%5;color:#FFFFFF;}"
            "QListWidget::item:hover{background:%6;}"
            "QListWidget::indicator{width:14px;height:14px;border:1px solid %7;"
            "border-radius:2px;background:%8;}"
            "QListWidget::indicator:checked{background:%5;border:1px solid %7;}"
        ).arg(fieldBg,fieldFg,fieldBor,altBg,fieldSel,hoverBg,indBor,indBg));
    }

    // 文本输入框(QLineEdit)与命令预览/输出框：随主题，亮色浅灰底+深字
    const QString fieldStyle=QStringLiteral(
        "background:%1;color:%2;border:1px solid %3;"
        "border-radius:3px;padding:2px 4px;"
        "selection-background-color:%4;selection-color:#FFFFFF;"
    ).arg(fieldBg,fieldFg,fieldBor,fieldSel);
    for(QLineEdit* e:{m_outDirEdit, m_keyfileEdit,
                       m_recipientEdit, m_identityEdit}) {
        if(e) e->setStyleSheet(fieldStyle);
    }
    if(m_outputView) {
        // 输出框 + 滚动条一体样式：部分样式表会让 QAbstractScrollArea 的原生滚动条
        // 退化为样式表基元绘制（Windows 上典型表现为滑块与上下箭头按钮重叠错乱）。
        // 此处显式接管滚动条：箭头按钮尺寸清零（移除），仅保留滑块，配色随主题。
        const QString sbHandle=dk ? QStringLiteral("#5A5A5A") : QStringLiteral("#A8A8A4");
        const QString sbHover=dk ? QStringLiteral("#6E6E6E") : QStringLiteral("#8A8A86");
        m_outputView->setStyleSheet(QStringLiteral(
            "QPlainTextEdit{background:%1;color:%2;border:1px solid %3;"
            "border-radius:3px;padding:2px 4px;"
            "selection-background-color:%4;selection-color:#FFFFFF;}"
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
        ).arg(fieldBg,fieldFg,fieldBor,fieldSel,altBg,sbHandle,sbHover));
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
    for(QWidget* c:{static_cast<QWidget*>(m_chkDeleteSource), static_cast<QWidget*>(m_chkForce),
                       static_cast<QWidget*>(m_chkVerbose),
                       static_cast<QWidget*>(m_chkSha256),
                       static_cast<QWidget*>(m_rbEncrypt), static_cast<QWidget*>(m_rbDecrypt),
                       static_cast<QWidget*>(m_rbBatchEncrypt), static_cast<QWidget*>(m_rbBatchDecrypt),
                       static_cast<QWidget*>(m_rbKeyGen), static_cast<QWidget*>(m_rbDerive),
                       static_cast<QWidget*>(m_rbPubKey)}) {
        if(c) c->setStyleSheet(optionStyle);
    }

    // 下拉框(QComboBox：主题/模式) 与其余按钮：随主题显式配色，
    // 亮色浅灰底+深字（避免依赖调色板在某些环境下仍渲染深色）
    const QString ctrlBg=dk ? QStringLiteral("#3D3D40") : QStringLiteral("#ECECEA");
    const QString ctrlFg=dk ? QStringLiteral("#E6E6E6") : QStringLiteral("#333333");
    const QString ctrlBor=dk ? QStringLiteral("#4A4A4D") : QStringLiteral("#C8C8C4");
    const QString ctrlHover=dk ? QStringLiteral("#4A4A4D") : QStringLiteral("#DCDCD8");
    const QString comboStyle=QStringLiteral(
        "QComboBox{background:%1;color:%2;border:1px solid %3;border-radius:3px;padding:2px 6px;min-width:60px;}"
        "QComboBox::drop-down{border:none;width:18px;}"
        "QComboBox::down-arrow{image:none;width:0;height:0;border-left:4px solid transparent;"
        "border-right:4px solid transparent;border-top:5px solid %2;}"
        "QComboBox QAbstractItemView{background:%1;color:%2;border:1px solid %3;"
        "selection-background-color:%4;selection-color:#FFFFFF;outline:0;}"
    ).arg(ctrlBg,ctrlFg,ctrlBor,fieldSel);
    for(QComboBox* cb:{m_themeCombo, m_modeCombo}) {
        if(cb) cb->setStyleSheet(comboStyle);
    }

    // 数值框(QSpinBox：压缩级别)：与输入框同配色。SpinBox 已 setButtonSymbols(NoButtons)
    // （无上下按钮），显式样式用于规避父级 background:transparent 层级导致的输入框透明。
    const QString spinStyle=QStringLiteral(
        "QSpinBox{background:%1;color:%2;border:1px solid %3;border-radius:3px;"
        "padding:2px 4px;selection-background-color:%4;selection-color:#FFFFFF;}"
        "QSpinBox:disabled{background:%5;color:#999999;border:1px solid %3;}"
    ).arg(fieldBg,fieldFg,fieldBor,fieldSel,altBg);
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

// ---------- CLI zstd 能力探测 ----------
void MainWindow::probeZstdSupport() {
    m_zstdAvailable=false;
    if(m_fileEncryptorPath.isEmpty()) return;
    QProcess p;
    p.start(m_fileEncryptorPath,QStringList{QStringLiteral("--features")});
    if(!p.waitForStarted(2000)) return;
    if(!p.waitForFinished(3000)) {
        p.kill();
        p.waitForFinished(1000);
        return;
    }
    // CLI 输出按 UTF-8（GUI 读 CLI 输出统一 fromUtf8 约定）
    const QString out=QString::fromUtf8(p.readAllStandardOutput());
    m_zstdAvailable=out.contains(QStringLiteral("zstd=1"));
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
    m_rbEncrypt=new QRadioButton(tr("加密 (-e)"));
    m_rbDecrypt=new QRadioButton(tr("解密 (-d)"));
    m_rbBatchEncrypt=new QRadioButton(tr("批量加密 (-be)"));
    m_rbBatchDecrypt=new QRadioButton(tr("批量解密 (-bd)"));
    m_rbKeyGen=new QRadioButton(tr("生成密钥对 (-g)"));
    m_rbDerive=new QRadioButton(tr("口令派生密钥对 (-G)"));
    m_rbPubKey=new QRadioButton(tr("导出公钥 (-Y)"));
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

    auto* lblKeyMgmt=new QLabel(tr("密钥管理 (rage/age)"));
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
    m_compressTitle=new QLabel(tr("压缩 (zstd)"));
    lay->addWidget(m_compressTitle,row,0);
    auto* compRow=new QHBoxLayout;
    m_chkCompress=new QCheckBox(tr("压缩数据 (-z)"));
    m_chkCompress->setToolTip(tr("加密时逐块 zstd 压缩（磁盘格式 v5，旧版本 CLI 无法读取）。\n"
                                 "仅对称加密有效；输出名混淆下压缩率统计见 CLI -v 输出。"));
    m_compressLabel=new QLabel(tr("压缩级别："));
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
    m_asymWidget=new QGroupBox(tr("非对称加密 (rage)"));
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
            rr->addWidget(new QLabel(tr("公钥 (-r)：")));
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
            ir->addWidget(new QLabel(tr("私钥文件 (-k)：")));
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
    auto* lblOut=new QLabel(tr("输出目录 (-o)"));
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
    auto* lblKey=new QLabel(tr("密钥文件 (-k)"));
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
    m_chkDeleteSource=new QCheckBox(tr("完成后删除源文件 (-de)"));
    m_chkForce=new QCheckBox(tr("覆盖已存在文件 (-y)"));
    m_chkVerbose=new QCheckBox(tr("详细输出 (-v)"));
    m_chkSha256=new QCheckBox(tr("生成校验单 (--sha256)"));
    m_chkSha256->setToolTip(tr("加密成功后额外生成 <输出名>.ptd.sha256 校验单（密文 SHA-256 十六进制 + 文件名），\n"
                               "便于与外部备份 / 传输工具链配合校验传输完整性。仅加密动作有效。"));
    optsRow->addWidget(m_chkDeleteSource);
    optsRow->addWidget(m_chkForce);
    optsRow->addWidget(m_chkVerbose);
    optsRow->addWidget(m_chkSha256);
    optsRow->addStretch();
    lay->addLayout(optsRow,row,1);
    row++;

    // 运行/取消按钮
    auto* runRow=new QHBoxLayout;
    m_btnRun=new QPushButton(tr("▶ 运行"));
    m_btnCancel=new QPushButton(tr("■ 取消"));
    m_btnCancel->setEnabled(false);
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
    lay->addWidget(m_outputView);

    return w;
}

// ---------- 信号连接 ----------
void MainWindow::connectSignals() {
    connect(m_btnAddFiles,&QPushButton::clicked,this,&MainWindow::onAddFiles);
    connect(m_btnAddDir,&QPushButton::clicked,this,&MainWindow::onAddDir);
    connect(m_btnClearFiles,&QPushButton::clicked,this,&MainWindow::onClearFiles);

    connect(m_btnRun,&QPushButton::clicked,this,&MainWindow::onRunClicked);
    connect(m_btnCancel,&QPushButton::clicked,this,&MainWindow::onCancelClicked);

    connect(m_executor,&ICommandExecutor::outputLine,this,&MainWindow::onOutputLine);
    connect(m_executor,&ICommandExecutor::finished,this,&MainWindow::onCommandFinished);

    // 选项变化刷新命令预览
    auto refresh=[this]{ refreshCommandPreview(); };
    connect(m_actionGroup,&QButtonGroup::idClicked,this,refresh);
    connect(m_modeCombo,QOverload<int>::of(&QComboBox::currentIndexChanged),this,refresh);
    connect(m_outDirEdit,&QLineEdit::textChanged,this,refresh);
    connect(m_keyfileEdit,&QLineEdit::textChanged,this,refresh);
    connect(m_chkDeleteSource,&QCheckBox::stateChanged,this,refresh);
    connect(m_chkForce,&QCheckBox::stateChanged,this,refresh);
    connect(m_chkVerbose,&QCheckBox::stateChanged,this,refresh);
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
        m_keygenWidget->setTitle(tr("rage 随机生成密钥对 (-g)"));
        m_keygenIntro->setText(tr("在下方输出目录 (-o) 中随机生成一对 X25519 密钥：\n"
                                  "  公钥             -> 打印到输出面板（age1...，可公开分享）\n"
                                  "  rage_private.txt -> 私钥文件（AGE-SECRET-KEY-...，务必妥善保管）"));
    } else if(derive) {
        m_keygenWidget->setTitle(tr("rage 口令派生密钥对 (-G)"));
        m_keygenIntro->setText(tr("用右侧「口令」经 Argon2id 确定性派生一对 X25519 密钥：\n"
                                  "  公钥                  -> 打印到输出面板（age1...）\n"
                                  "  rage_private.txt      -> 私钥文件（AGE-SECRET-KEY-...）\n"
                                  "  rage_derive_salt.txt  -> 16 字节随机盐，复现同一密钥对必需\n"
                                  "同一口令 + 同一盐永远得到同一对密钥，因此口令可以代替私钥文件；"
                                  "但盐必须一并保存，否则无法再次派生出来。"));
    } else if(pubkey) {
        m_keygenWidget->setTitle(tr("rage 由私钥导出公钥 (-Y)"));
        m_keygenIntro->setText(tr("读取下方「私钥文件 (-k)」里的 AGE-SECRET-KEY-...，"
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

    // zstd 压缩（v1.3.0）：仅「加密 / 批量加密」动作显示整行（含行首标题）；
    // 非对称模式由 CLI 拒绝压缩，故 asym 下同样隐藏。行可见时级别框始终可编辑
    // （不随勾选态/zstd 探测结果禁用，避免灰色不可输入）。
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
            setStatus(tr("检测到目录输入，已自动切换为批量动作（-be/-bd）"));
        }
        refreshCommandPreview();
    }
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
    o.deleteSource=m_chkDeleteSource->isChecked();
    o.forceOverwrite=m_chkForce->isChecked();
    o.verbose=m_chkVerbose->isChecked();
    o.writeSha256=m_chkSha256->isChecked();
    o.keyfilePath=m_keyfileEdit->text().trimmed();
    // zstd 压缩级别：勾选才生效；非对称/解密等场景由 CliArgBuilder 再次把关（不落 --compression-level）
    o.compressionLevel=(m_chkCompress->isChecked()) ? m_compressLevel->value() : 0;
    // 口令不再存于主页面：运行时经 PasswordDialog 弹窗获取（见 onRunClicked）

    // 非对称（age）输入。功能8：收件人框支持多收件人（逗号/分号分隔的 age1... 公钥串，
    // 自动写临时公钥文件走 -r 文件通道）；单条目维持原语义（公钥串或公钥文件路径）。
    o.recipientPath=resolveRecipients(m_recipientEdit->text().trimmed());
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
    // 收件人框支持：age1... 公钥串（可多个，逗号/分号分隔）或单个公钥文件路径（原语义）。
    // 多条且全部为公钥串时写临时公钥文件走 CLI 的 -r 文件通道（文件内容仅公钥，非机密）；
    // 其余情况原样返回，由 CLI 做校验与报错。
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
                tr("请先在「私钥文件 (-k)」中选择包含 AGE-SECRET-KEY-... 的文件。"));
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
                    tr("非对称解密需要私钥文件 (-k)，例如 rage_private.txt。"));
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

    // Key material is injected through the child's stdin pipe (never env / argv):
    //   - symmetric mode without -k: the password (from the PIN dialog, held in `pw`);
    //   - asymmetric modes: nothing - public key goes via -r, private key via -k.
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
    m_framePos=-1;              // 批量进度帧块随新任务重建
    m_frameLen=0;
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

void MainWindow::onCancelClicked() {
    if(m_executor->isRunning()) {
        appendOutput(tr("\n--- 用户取消，正在终止子进程... ---\n"),true);
        m_executor->cancel();
    }
}

// ---------- 执行回显 ----------
void MainWindow::onOutputLine(const OutputLine& line) {
    // 功能6：批量进度帧 → 在拟 cmd 输出区内「原地整帧刷新」：
    // 首帧在文档末尾另起一行写入，后续帧按字符区间 [帧首, 帧尾) 整体替换。
    // 字符区间之前的文本只会追加（位置不变），不会像块锚点那样漂移，
    // 从而保证每条进度条始终覆盖刷新、显示区域固定、不越刷越多。
    if(line.isFrame) {
        QStringList lines=line.text.split(QLatin1Char('\n'));
        while(!lines.isEmpty()&&lines.last().trimmed().isEmpty()) lines.removeLast();
        if(lines.isEmpty()) return;
        // 帧文本以换行结尾：与后续普通输出行保持块结构隔离
        const QString block=lines.join(QLatin1Char('\n'))+QLatin1Char('\n');
        const unsigned int rgb=ThemeManager::stdoutColorRGB();
        QTextCharFormat fmt;
        fmt.setForeground(QColor((rgb>>16)&0xFF,(rgb>>8)&0xFF,rgb&0xFF));

        bool replaced=false;
        const int docLen=m_outputView->document()->characterCount();
        if(m_framePos>=0&&m_frameLen>0&&m_framePos+m_frameLen<=docLen) {
            // 自校验：帧首应是汇总行开头（'T'，即 "TOTAL ..."）。
            // 文档被裁剪/外部改动导致区间失效时立即放弃替换，回退追加，自愈不留残影。
            if(m_outputView->document()->characterAt(m_framePos)==QLatin1Char('T')) {
                // 视图光标先挪到末尾并清选区，避免残留选区干扰替换
                QTextCursor guard=m_outputView->textCursor();
                guard.movePosition(QTextCursor::End);
                m_outputView->setTextCursor(guard);

                QTextCursor sel(m_outputView->document());
                sel.setPosition(m_framePos);
                sel.setPosition(m_framePos+m_frameLen,QTextCursor::KeepAnchor);
                sel.insertText(block,fmt);   // 原地整帧替换（新旧帧长度可不同）
                replaced=true;
            }
        }
        if(!replaced) {
            // 首帧或区间失效：追加新帧块到文档末尾，记录其字符区间
            QTextCursor cur=m_outputView->textCursor();
            cur.movePosition(QTextCursor::End);
            const int base=cur.position();
            cur.insertText(QStringLiteral("\n")+block,fmt);
            m_framePos=base+1;           // 前导换行之后即帧首
        }
        m_frameLen=block.size();
        m_lastProgressLine=false;
        QScrollBar* bar=m_outputView->verticalScrollBar();
        bar->setValue(bar->maximum());
        return;
    }
    if(line.isProgress) {
        // 模拟 CMD 进度条：原地刷新上一行（替换），避免末尾进度行重复堆积、清屏异常
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
    // 功能11：统计 CLI 的文件开始标记（Encrypting:/Decrypting:），取消时据此汇总已完成数
    if(line.text.startsWith(QLatin1String("Encrypting: "))||
       line.text.startsWith(QLatin1String("Decrypting: "))) {
        ++m_runFileStarts;
        m_currentTask.filesDone=m_runFileStarts;   // 功能5：记录已完成文件数（取消时也保留）
    }
    appendOutput(line.text+QStringLiteral("\n"),line.isError);
}

void MainWindow::onCommandFinished(const CommandResult& r) {
    m_btnRun->setEnabled(true);
    m_btnCancel->setEnabled(false);
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
    appendOutput(QStringLiteral("\n%1\n").arg(summary),r.exitCode!=0);
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

// 统计单个输入路径的字节数与文件数（目录递归）
static void scanPath(const QString& path,qint64& bytes,int& files) {
    QFileInfo fi(path);
    if(fi.isFile()) { bytes+=fi.size(); ++files; return; }
    if(!fi.isDir()) return;
    QDirIterator it(path,QDir::Files,QDirIterator::Subdirectories);
    while(it.hasNext()) {
        it.next();
        bytes+=it.fileInfo().size();
        ++files;
    }
}

void MainWindow::recomputePending() {
    const ShellOptions o=collectOptions();
    qint64 bytes=0;
    int files=0;
    for(const QString& p : o.inputPaths) scanPath(p,bytes,files);
    m_pendingBytes=bytes;
    m_pendingFiles=files;
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
    m_runTimer.start();
}

void MainWindow::finishTaskRecord(const CommandResult& r) {
    if(m_currentTask.id.isEmpty()) return;
    m_currentTask.finishedAt=QDateTime::currentDateTime()
        .toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"));
    m_currentTask.durationMs=m_runTimer.isValid() ? m_runTimer.elapsed() : 0;
    m_currentTask.filesDone=m_runFileStarts;
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
    // 不运行时刷新顶部命令预览（运行中不打断输出）
    if(m_executor&&m_executor->isRunning()) return;
    const ShellOptions o=collectOptions();
    const QString preview=CliArgBuilder::buildPreview(m_fileEncryptorPath,o);
    // 仅当输出区为空或上一次是预览时刷新（避免覆盖执行结果）
    if(m_outputView->toPlainText().isEmpty()||
        m_outputView->toPlainText().startsWith(QStringLiteral(">>>"))) {
        m_outputView->clear();
        appendOutput(QStringLiteral(">>> 命令预览: %1\n").arg(preview),false);
    }
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