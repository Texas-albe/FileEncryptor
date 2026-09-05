// MainWindow 实现
#include "MainWindow.h"
#include "AboutDialogs.h"
#include "FileEncryptorLocator.h"
#include "PasswordStrength.h"
#include "ProcessCommandExecutor.h"

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
#include <QPushButton>
#include <QButtonGroup>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QGridLayout>
#include <QSplitter>
#include <QGroupBox>
#include <QMessageBox>
#include <QCloseEvent>
#include <QFileInfo>
#include <QDir>
#include <QStandardPaths>
#include <QTextCharFormat>
#include <QTextCursor>
#include <QScrollBar>
#include <QFontDatabase>
#include <QColor>

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
    // 标题含版本号（与 CMake project VERSION 同步为 1.0.0）
    setWindowTitle(QStringLiteral("FileEncryptorGUI %1").arg(
        qApp->applicationVersion().isEmpty() ? QStringLiteral("1.0.0")
                                              : qApp->applicationVersion()));
    resize(1200, 760);

    // 命令执行器（手写极简构造注入，不引 DI 容器）
    m_executor = new ProcessCommandExecutor(this);

    // 定位 FileEncryptor 可执行文件
    m_fileEncryptorPath = FileEncryptorLocator::locate();

    buildMenu();

    // 中央布局：左 | (中+右 纵向) | 下
    auto* centralSplitter = new QSplitter(Qt::Horizontal);

    auto* left = buildLeftPanel();
    auto* center = buildCenterPanel();
    auto* right = buildRightPanel();

    // 中 + 右 橫向
    auto* midRight = new QSplitter(Qt::Horizontal);
    midRight->addWidget(center);
    midRight->addWidget(right);
    midRight->setStretchFactor(0, 3);  // 中部占多
    midRight->setStretchFactor(1, 1);  // 右侧密码框窄
    midRight->setSizes({700, 220});

    centralSplitter->addWidget(left);
    centralSplitter->addWidget(midRight);
    centralSplitter->setStretchFactor(0, 1);
    centralSplitter->setStretchFactor(1, 3);
    centralSplitter->setSizes({300, 900});

    // 下部输出 + 上半 整体，纵向 splitter
    // 命令输出窗口高度缩减为原来的一半：从 300 → 150；拉伸比 6:1 让窗口缩放时
    // 下部保持约 1/7（≈ 原 2/5 的一半），既满足"减半"又不至于无法查看长输出。
    auto* bottom = buildBottomPanel();
    auto* outerSplitter = new QSplitter(Qt::Vertical);
    outerSplitter->addWidget(centralSplitter);
    outerSplitter->addWidget(bottom);
    outerSplitter->setStretchFactor(0, 6);
    outerSplitter->setStretchFactor(1, 1);
    outerSplitter->setSizes({610, 150});

    setCentralWidget(outerSplitter);

    // 状态栏
    m_statusLabel = new QLabel(this);
    statusBar()->addWidget(m_statusLabel, 1);
    setStatus(m_fileEncryptorPath.isEmpty()
                 ? tr("未找到 FileEncryptor 可执行文件 — 请设置环境变量 FILEENCRYPTOR_EXE 或将其置于本程序同目录")
                 : tr("就绪 | FileEncryptor: %1").arg(m_fileEncryptorPath));

    connectSignals();
    refreshCommandPreview();
}

MainWindow::~MainWindow() = default;

void MainWindow::closeEvent(QCloseEvent* e) {
    // 运行中弹确认
    if (m_executor && m_executor->isRunning()) {
        auto ret = QMessageBox::question(
            this, tr("确认退出"),
            tr("有命令正在运行，退出将终止它。确定退出？"),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
        if (ret != QMessageBox::Yes) {
            e->ignore();
            return;
        }
        m_executor->cancel();
    }
    e->accept();
}

// ---------- 顶栏菜单 ----------
void MainWindow::buildMenu() {
    m_menuBar = menuBar();

    // —— 关于菜单 ——
    auto* aboutMenu = m_menuBar->addMenu(tr("关于(&A)"));

    auto* actCredits = aboutMenu->addAction(tr("鸣谢..."));
    connect(actCredits, &QAction::triggered, this, [this]{
        CreditsDialog dlg(this);
        dlg.exec();
    });

    auto* actReadme = aboutMenu->addAction(tr("README 摘要..."));
    connect(actReadme, &QAction::triggered, this, [this]{
        ReadmeDialog dlg(this);
        dlg.exec();
    });

    aboutMenu->addSeparator();
    auto* actAboutQt = aboutMenu->addAction(tr("关于 Qt..."));
    connect(actAboutQt, &QAction::triggered, qApp, &QApplication::aboutQt);

    // —— 视图菜单：颜色主题切换 ——
    auto* viewMenu = m_menuBar->addMenu(tr("视图(&V)"));

    m_themeGroup = new QActionGroup(this);
    m_themeGroup->setExclusive(true);

    m_actThemeSystem = viewMenu->addAction(tr("跟随系统"));
    m_actThemeLight  = viewMenu->addAction(tr("浅色"));
    m_actThemeDark   = viewMenu->addAction(tr("深色"));

    m_actThemeSystem->setCheckable(true);
    m_actThemeLight->setCheckable(true);
    m_actThemeDark->setCheckable(true);

    m_themeGroup->addAction(m_actThemeSystem);
    m_themeGroup->addAction(m_actThemeLight);
    m_themeGroup->addAction(m_actThemeDark);

    // 反映当前持久化的偏好
    const auto t = ThemeManager::chosenTheme();
    if (t == ThemeManager::Theme::Light)      m_actThemeLight->setChecked(true);
    else if (t == ThemeManager::Theme::Dark)  m_actThemeDark->setChecked(true);
    else                                      m_actThemeSystem->setChecked(true);

    connect(m_actThemeSystem, &QAction::triggered, this, &MainWindow::onThemeSwitched);
    connect(m_actThemeLight,  &QAction::triggered, this, &MainWindow::onThemeSwitched);
    connect(m_actThemeDark,   &QAction::triggered, this, &MainWindow::onThemeSwitched);

    viewMenu->addSeparator();
    auto* actAbout = viewMenu->addAction(tr("颜色主题..."));
    actAbout->setEnabled(false);  // 仅作分组标题占位
}

void MainWindow::onThemeSwitched() {
    ThemeManager::Theme t = ThemeManager::Theme::System;
    if (m_actThemeLight->isChecked())      t = ThemeManager::Theme::Light;
    else if (m_actThemeDark->isChecked())  t = ThemeManager::Theme::Dark;
    else                                    t = ThemeManager::Theme::System;
    ThemeManager::setTheme(t);   // 持久化 + 应用调色板 + 通知全窗口重绘
    applyButtonStyles();
    // 已显示的输出重新着色（按当前主题的对比色）
    // 注：QPlainTextEdit 的既有富文本不会因 setPalette 自动重着色，
    // 这里仅刷新命令预览；运行中的输出保持原样，避免打断。
    refreshCommandPreview();
}

// ---------- 运行/取消按钮样式（主题感知，保证深色下文字清晰）----------
void MainWindow::applyButtonStyles() {
    const bool dark = ThemeManager::isDarkActive();
    // 运行按钮：深色下用更亮的绿 + 白字；浅色下保持品牌绿
    m_btnRun->setStyleSheet(
        dark
        ? "QPushButton{background:#43A047;color:#FFFFFF;padding:6px 18px;font-weight:bold;border-radius:4px;}"
          "QPushButton:hover{background:#66BB6A;}"
        : "QPushButton{background:#2E7D32;color:white;padding:6px 18px;font-weight:bold;border-radius:4px;}"
          "QPushButton:hover{background:#1B5E20;}");
    m_btnCancel->setStyleSheet(
        dark
        ? "QPushButton{background:#E53935;color:#FFFFFF;padding:6px 18px;font-weight:bold;border-radius:4px;}"
          "QPushButton:hover{background:#EF5350;}"
          "QPushButton:disabled{background:#555;color:#ccc;}"
        : "QPushButton{background:#C62828;color:white;padding:6px 18px;font-weight:bold;border-radius:4px;}"
          "QPushButton:hover{background:#B71C1C;}"
          "QPushButton:disabled{background:#999;color:#eee;}");
}

// ---------- 左侧文件选择面板 ----------
QWidget* MainWindow::buildLeftPanel() {
    auto* w = new QWidget;
    auto* lay = new QVBoxLayout(w);

    auto* title = new QLabel(tr("<b>文件选择</b>"));
    title->setAlignment(Qt::AlignCenter);
    lay->addWidget(title);

    m_fileList = new QListWidget;
    m_fileList->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_fileList->setAlternatingRowColors(true);
    lay->addWidget(m_fileList, 1);

    auto* btnRow1 = new QHBoxLayout;
    m_btnAddFiles = new QPushButton(tr("添加文件..."));
    m_btnAddDir   = new QPushButton(tr("添加目录..."));
    btnRow1->addWidget(m_btnAddFiles);
    btnRow1->addWidget(m_btnAddDir);
    lay->addLayout(btnRow1);

    auto* btnRow2 = new QHBoxLayout;
    m_btnClearFiles = new QPushButton(tr("清空"));
    btnRow2->addStretch();
    btnRow2->addWidget(m_btnClearFiles);
    lay->addLayout(btnRow2);

    return w;
}

// ---------- 中部主要功能区 ----------
QWidget* MainWindow::buildCenterPanel() {
    auto* w = new QWidget;
    auto* lay = new QGridLayout(w);
    lay->setColumnStretch(1, 1);

    int row = 0;

    // 动作模式
    auto* lblAction = new QLabel(tr("<b>操作</b>"));
    lay->addWidget(lblAction, row, 0);
    m_rbEncrypt = new QRadioButton(tr("加密 (-e)"));
    m_rbDecrypt = new QRadioButton(tr("解密 (-d)"));
    m_rbBatchEncrypt = new QRadioButton(tr("批量加密 (-be)"));
    m_rbBatchDecrypt = new QRadioButton(tr("批量解密 (-bd)"));
    m_actionGroup = new QButtonGroup(this);
    m_actionGroup->addButton(m_rbEncrypt,      static_cast<int>(CryptoAction::Encrypt));
    m_actionGroup->addButton(m_rbDecrypt,      static_cast<int>(CryptoAction::Decrypt));
    m_actionGroup->addButton(m_rbBatchEncrypt, static_cast<int>(CryptoAction::BatchEncrypt));
    m_actionGroup->addButton(m_rbBatchDecrypt, static_cast<int>(CryptoAction::BatchDecrypt));
    m_rbEncrypt->setChecked(true);

    auto* actionRow = new QHBoxLayout;
    actionRow->addWidget(m_rbEncrypt);
    actionRow->addWidget(m_rbDecrypt);
    actionRow->addWidget(m_rbBatchEncrypt);
    actionRow->addWidget(m_rbBatchDecrypt);
    actionRow->addStretch();
    lay->addLayout(actionRow, row, 1);
    row++;

    // 加密模式
    auto* lblMode = new QLabel(tr("加密模式"));
    lay->addWidget(lblMode, row, 0);
    m_modeCombo = new QComboBox;
    m_modeCombo->addItem(tr("XChaCha20-Poly1305（默认，兼容性最好）"), static_cast<int>(CryptoMode::XChaCha20));
    m_modeCombo->addItem(tr("AEGIS-256（需 AES-NI 指令）"),              static_cast<int>(CryptoMode::Aegis256));
    lay->addWidget(m_modeCombo, row, 1);
    row++;

    // 输出目录
    auto* lblOut = new QLabel(tr("输出目录 (-o)"));
    lay->addWidget(lblOut, row, 0);
    auto* outRow = new QHBoxLayout;
    m_outDirEdit = new QLineEdit;
    m_outDirEdit->setPlaceholderText(tr("留空 = 输出到源文件目录"));
    m_btnOutDirBrowse = new QPushButton(tr("浏览..."));
    outRow->addWidget(m_outDirEdit);
    outRow->addWidget(m_btnOutDirBrowse);
    lay->addLayout(outRow, row, 1);
    row++;

    // 密钥文件
    auto* lblKey = new QLabel(tr("密钥文件 (-k)"));
    lay->addWidget(lblKey, row, 0);
    auto* keyRow = new QHBoxLayout;
    m_keyfileEdit = new QLineEdit;
    m_keyfileEdit->setPlaceholderText(tr("留空 = 用右侧密码经 ENCRYPTOR_KEY"));
    m_btnKeyfileBrowse = new QPushButton(tr("浏览..."));
    keyRow->addWidget(m_keyfileEdit);
    keyRow->addWidget(m_btnKeyfileBrowse);
    lay->addLayout(keyRow, row, 1);
    row++;

    // 选项
    auto* lblOpts = new QLabel(tr("选项"));
    lay->addWidget(lblOpts, row, 0);
    auto* optsRow = new QHBoxLayout;
    m_chkDeleteSource = new QCheckBox(tr("完成后删除源文件 (-de)"));
    m_chkForce = new QCheckBox(tr("覆盖已存在文件 (-y)"));
    m_chkForce->setChecked(true);
    m_chkVerbose = new QCheckBox(tr("详细输出 (-v)"));
    optsRow->addWidget(m_chkDeleteSource);
    optsRow->addWidget(m_chkForce);
    optsRow->addWidget(m_chkVerbose);
    optsRow->addStretch();
    lay->addLayout(optsRow, row, 1);
    row++;

    // 运行/取消按钮
    auto* runRow = new QHBoxLayout;
    m_btnRun = new QPushButton(tr("▶ 运行"));
    m_btnCancel = new QPushButton(tr("■ 取消"));
    m_btnCancel->setEnabled(false);
    runRow->addStretch();
    runRow->addWidget(m_btnRun);
    runRow->addWidget(m_btnCancel);
    lay->addLayout(runRow, row, 1);
    row++;
    // 按钮样式按当前主题应用（构造期 + 主题切换期都会调用）
    applyButtonStyles();

    lay->setRowStretch(row, 1);
    return w;
}

// ---------- 右侧密码输入框 ----------
QWidget* MainWindow::buildRightPanel() {
    auto* w = new QWidget;
    auto* lay = new QVBoxLayout(w);

    auto* title = new QLabel(tr("<b>密码</b>"));
    title->setAlignment(Qt::AlignCenter);
    lay->addWidget(title);

    auto* lbl = new QLabel(tr("加密口令："));
    lay->addWidget(lbl);

    m_passwordEdit = new QLineEdit;
    m_passwordEdit->setEchoMode(QLineEdit::Password);   // 星号隐藏
    m_passwordEdit->setPlaceholderText(tr("输入密码（经环境变量注入，不留盘）"));
    lay->addWidget(m_passwordEdit);

    // 强度提示
    auto* lblStrength = new QLabel(tr("强度："));
    lay->addWidget(lblStrength);
    m_strengthLabel = new QLabel(tr("未输入"));
    m_strengthLabel->setAlignment(Qt::AlignCenter);
    QFont f = m_strengthLabel->font();
    f.setBold(true);
    f.setPointSize(f.pointSize() + 2);
    m_strengthLabel->setFont(f);
    lay->addWidget(m_strengthLabel);

    lay->addStretch();

    // 提示文字
    auto* tip = new QLabel(tr(
        "<small><i>提示：密码经 ENCRYPTOR_KEY 环境变量\n"
        "注入子进程，不写入命令行/磁盘。\n"
        "提供密钥文件 (-k) 时优先用密钥文件。</i></small>"));
    tip->setWordWrap(true);
    lay->addWidget(tip);

    return w;
}

// ---------- 下部只读文本框 ----------
QWidget* MainWindow::buildBottomPanel() {
    auto* w = new QWidget;
    auto* lay = new QVBoxLayout(w);
    lay->setContentsMargins(0, 0, 0, 0);

    auto* header = new QLabel(tr("<b>命令浏览与执行输出</b>"));
    lay->addWidget(header);

    m_outputView = new QPlainTextEdit;
    m_outputView->setReadOnly(true);   // 只读
    m_outputView->setPlaceholderText(tr("此处显示命令预览与执行输出。stdout 默认色，stderr 红色。"));
    // 等宽字体便于对齐
    QFont mono = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    m_outputView->setFont(mono);
    lay->addWidget(m_outputView);

    return w;
}

// ---------- 信号连接 ----------
void MainWindow::connectSignals() {
    connect(m_btnAddFiles, &QPushButton::clicked, this, &MainWindow::onAddFiles);
    connect(m_btnAddDir, &QPushButton::clicked, this, &MainWindow::onAddDir);
    connect(m_btnClearFiles, &QPushButton::clicked, this, &MainWindow::onClearFiles);

    connect(m_btnRun, &QPushButton::clicked, this, &MainWindow::onRunClicked);
    connect(m_btnCancel, &QPushButton::clicked, this, &MainWindow::onCancelClicked);

    connect(m_executor, &ICommandExecutor::outputLine, this, &MainWindow::onOutputLine);
    connect(m_executor, &ICommandExecutor::finished, this, &MainWindow::onCommandFinished);

    connect(m_passwordEdit, &QLineEdit::textChanged, this, &MainWindow::onPasswordChanged);

    // 选项变化刷新命令预览
    auto refresh = [this]{ refreshCommandPreview(); };
    connect(m_actionGroup, &QButtonGroup::idClicked, this, refresh);
    connect(m_modeCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, refresh);
    connect(m_outDirEdit, &QLineEdit::textChanged, this, refresh);
    connect(m_keyfileEdit, &QLineEdit::textChanged, this, refresh);
    connect(m_chkDeleteSource, &QCheckBox::stateChanged, this, refresh);
    connect(m_chkForce, &QCheckBox::stateChanged, this, refresh);
    connect(m_chkVerbose, &QCheckBox::stateChanged, this, refresh);

    // 浏览按钮
    connect(m_btnOutDirBrowse, &QPushButton::clicked, this, [this]{
        QString d = QFileDialog::getExistingDirectory(this, tr("选择输出目录"),
                       m_outDirEdit->text().isEmpty() ? QDir::homePath() : m_outDirEdit->text());
        if (!d.isEmpty()) m_outDirEdit->setText(d);
    });
    connect(m_btnKeyfileBrowse, &QPushButton::clicked, this, [this]{
        QString f = QFileDialog::getOpenFileName(this, tr("选择密钥文件"),
                       QDir::homePath(), tr("所有文件 (*)"));
        if (!f.isEmpty()) m_keyfileEdit->setText(f);
    });
}

// ---------- 文件选择 ----------
void MainWindow::onAddFiles() {
    const QStringList files = QFileDialog::getOpenFileNames(
        this, tr("选择文件"), QDir::homePath(), tr("所有文件 (*)"));
    for (const QString& f : files) {
        m_fileList->addItem(f);
    }
    refreshCommandPreview();
}

void MainWindow::onAddDir() {
    const QString d = QFileDialog::getExistingDirectory(
        this, tr("选择目录"), QDir::homePath());
    if (!d.isEmpty()) {
        m_fileList->addItem(d);
        refreshCommandPreview();
    }
}

void MainWindow::onClearFiles() {
    m_fileList->clear();
    refreshCommandPreview();
}

// ---------- 密码强度 ----------
void MainWindow::onPasswordChanged(const QString& text) {
    const StrengthResult r = PasswordStrength::evaluate(text);
    m_strengthLabel->setText(r.label);
    m_strengthLabel->setStyleSheet(
        QStringLiteral("color:%1;").arg(r.colorHex));
    m_strengthLabel->setToolTip(r.detail);
    refreshCommandPreview();
}

// ---------- 收集选项 ----------
ShellOptions MainWindow::collectOptions() const {
    ShellOptions o;
    o.action = static_cast<CryptoAction>(m_actionGroup->checkedId());
    o.mode = static_cast<CryptoMode>(m_modeCombo->currentData().toInt());

    for (int i = 0; i < m_fileList->count(); ++i) {
        o.inputPaths << m_fileList->item(i)->text();
    }

    o.outputDir = m_outDirEdit->text().trimmed();
    o.deleteSource = m_chkDeleteSource->isChecked();
    o.forceOverwrite = m_chkForce->isChecked();
    o.verbose = m_chkVerbose->isChecked();
    o.keyfilePath = m_keyfileEdit->text().trimmed();
    o.password = m_passwordEdit->text();

    return o;
}

// ---------- 运行 ----------
void MainWindow::onRunClicked() {
    if (m_fileEncryptorPath.isEmpty()) {
        QMessageBox::critical(this, tr("无法运行"),
            tr("未找到 FileEncryptor 可执行文件。\n"
               "请将 FileEncryptor(.exe) 置于本程序同目录，"
               "或设置环境变量 FILEENCRYPTOR_EXE 指向其完整路径。"));
        return;
    }

    const ShellOptions o = collectOptions();

    // 校验
    if (o.inputPaths.isEmpty()) {
        QMessageBox::warning(this, tr("缺少输入"), tr("请先添加文件或目录。"));
        return;
    }
    bool isBatch = (o.action == CryptoAction::BatchEncrypt ||
                    o.action == CryptoAction::BatchDecrypt);
    if (!isBatch && o.inputPaths.size() > 1) {
        QMessageBox::warning(this, tr("输入过多"),
            tr("单文件模式只接受一个输入路径，请清空后只选一个，或改用批量模式。"));
        return;
    }
    // 密钥校验：未提供密钥文件时，密码必须 >=6（main.cpp L338-341）
    if (o.keyfilePath.isEmpty() && o.password.length() < 6) {
        QMessageBox::warning(this, tr("密码过短"),
            tr("密码至少 6 个字符（或提供密钥文件 -k）。"));
        m_passwordEdit->setFocus();
        return;
    }

    // 构建命令
    CommandRequest req;
    req.programPath = m_fileEncryptorPath;
    req.arguments = CliArgBuilder::buildArguments(o);
    req.extraEnv = CliArgBuilder::buildEnvironment(o);

    // 输出区清空并显示命令预览
    m_outputView->clear();
    const QString preview = CliArgBuilder::buildPreview(m_fileEncryptorPath, o);
    appendOutput(QStringLiteral(">>> %1\n").arg(preview), false);
    appendOutput(QStringLiteral("--- 执行开始 ---\n"), false);

    // UI 状态切换
    m_btnRun->setEnabled(false);
    m_btnCancel->setEnabled(true);
    setStatus(tr("运行中..."));

    m_executor->execute(req);
}

void MainWindow::onCancelClicked() {
    if (m_executor->isRunning()) {
        appendOutput(tr("\n--- 用户取消，正在终止子进程... ---\n"), true);
        m_executor->cancel();
    }
}

// ---------- 执行回显 ----------
void MainWindow::onOutputLine(const OutputLine& line) {
    appendOutput(line.text + QStringLiteral("\n"), line.isError);
}

void MainWindow::onCommandFinished(const CommandResult& r) {
    m_btnRun->setEnabled(true);
    m_btnCancel->setEnabled(false);

    QString summary;
    if (r.wasCancelled) {
        summary = tr("--- 已取消（退出码 %1） ---").arg(r.exitCode);
        setStatus(tr("已取消"));
    } else if (!r.errorString.isEmpty()) {
        summary = tr("--- 执行失败：%1 ---").arg(r.errorString);
        setStatus(tr("失败：%1").arg(r.errorString));
    } else if (r.exitCode == 0) {
        summary = tr("--- 执行成功（退出码 0） ---");
        setStatus(tr("完成"));
    } else {
        summary = tr("--- 执行结束（退出码 %1） ---").arg(r.exitCode);
        setStatus(tr("结束（退出码 %1）").arg(r.exitCode));
    }
    appendOutput(QStringLiteral("\n%1\n").arg(summary), r.exitCode != 0);
}

// ---------- 输出追加 + 自动滚动 ----------
void MainWindow::appendOutput(const QString& text, bool isError) {
    // 主题感知着色：深色模式用高对比浅色文字，满足 WCAG AA（>= 4.5:1）
    const unsigned int rgb = isError ? ThemeManager::stderrColorRGB()
                                      : ThemeManager::stdoutColorRGB();
    QTextCharFormat fmt;
    fmt.setForeground(QColor((rgb >> 16) & 0xFF, (rgb >> 8) & 0xFF, rgb & 0xFF));
    QTextCursor cur = m_outputView->textCursor();
    cur.movePosition(QTextCursor::End);
    cur.insertText(text, fmt);
    // 自动滚到底
    QScrollBar* bar = m_outputView->verticalScrollBar();
    bar->setValue(bar->maximum());
}

// ---------- 命令预览刷新 ----------
void MainWindow::refreshCommandPreview() {
    // 不运行时刷新顶部命令预览（运行中不打断输出）
    if (m_executor && m_executor->isRunning()) return;
    const ShellOptions o = collectOptions();
    const QString preview = CliArgBuilder::buildPreview(m_fileEncryptorPath, o);
    // 仅当输出区为空或上一次是预览时刷新（避免覆盖执行结果）
    if (m_outputView->toPlainText().isEmpty() ||
        m_outputView->toPlainText().startsWith(QStringLiteral(">>>"))) {
        m_outputView->clear();
        appendOutput(QStringLiteral(">>> 命令预览: %1\n").arg(preview), false);
    }
}

void MainWindow::setStatus(const QString& msg) {
    if (m_statusLabel) m_statusLabel->setText(msg);
}
