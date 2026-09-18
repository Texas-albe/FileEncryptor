// KeyLibraryDialog 实现（功能1）
#include "KeyLibraryDialog.h"

#include "MsgBox.h"

#include <QApplication>
#include <QClipboard>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QProcess>
#include <QPushButton>
#include <QTableWidget>
#include <QVBoxLayout>

namespace {
constexpr int COL_NAME = 0;
constexpr int COL_KIND = 1;
constexpr int COL_ALIAS = 2;
constexpr int COL_CREATED = 3;
constexpr int COL_NOTES = 4;
constexpr int COL_PUBLIC = 5;
}

KeyLibraryDialog::KeyLibraryDialog(const QString& cliPath, QWidget* parent)
    : QDialog(parent), m_cliPath(cliPath) {
    setWindowTitle(tr("密钥库"));
    setModal(true);
    resize(760, 420);

    auto* lay = new QVBoxLayout(this);

    const QString dir = KeyLibrary::dir();
    auto* hint = new QLabel(tr("密钥库目录：%1\nCLI 与 GUI 共用此库；身份条目会缓存对应公钥，"
                               "加密时无需再接触私钥。").arg(dir.isEmpty() ? tr("（不可用）") : dir));
    hint->setWordWrap(true);
    lay->addWidget(hint);

    m_table = new QTableWidget(this);
    m_table->setColumnCount(6);
    m_table->setHorizontalHeaderLabels({tr("名称"), tr("类型"), tr("别名"),
                                        tr("创建时间"), tr("备注"), tr("公钥")});
    m_table->horizontalHeader()->setSectionResizeMode(COL_NAME, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(COL_KIND, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(COL_ALIAS, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(COL_CREATED, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(COL_NOTES, QHeaderView::Stretch);
    m_table->horizontalHeader()->setSectionResizeMode(COL_PUBLIC, QHeaderView::Stretch);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setCornerButtonEnabled(false);
    lay->addWidget(m_table, 1);

    auto* btns = new QHBoxLayout;
    m_btnImport = new QPushButton(tr("导入密钥..."), this);
    m_btnRemove = new QPushButton(tr("移除"), this);
    m_btnExport = new QPushButton(tr("导出..."), this);
    m_btnCopyPub = new QPushButton(tr("复制公钥"), this);
    m_btnApplyRecipient = new QPushButton(tr("应用为收件人"), this);
    m_btnApplyIdentity = new QPushButton(tr("应用为身份"), this);
    m_btnClose = new QPushButton(tr("关闭"), this);
    btns->addWidget(m_btnImport);
    btns->addWidget(m_btnRemove);
    btns->addWidget(m_btnExport);
    btns->addWidget(m_btnCopyPub);
    btns->addStretch();
    btns->addWidget(m_btnApplyRecipient);
    btns->addWidget(m_btnApplyIdentity);
    btns->addWidget(m_btnClose);
    lay->addLayout(btns);

    connect(m_btnImport, &QPushButton::clicked, this, &KeyLibraryDialog::onImport);
    connect(m_btnRemove, &QPushButton::clicked, this, &KeyLibraryDialog::onRemove);
    connect(m_btnExport, &QPushButton::clicked, this, &KeyLibraryDialog::onExport);
    connect(m_btnCopyPub, &QPushButton::clicked, this, &KeyLibraryDialog::onCopyPublicKey);
    connect(m_btnApplyRecipient, &QPushButton::clicked, this, &KeyLibraryDialog::onApplyRecipients);
    connect(m_btnApplyIdentity, &QPushButton::clicked, this, &KeyLibraryDialog::onApplyIdentity);
    connect(m_btnClose, &QPushButton::clicked, this, &QDialog::accept);
    connect(m_table, &QTableWidget::itemSelectionChanged,
            this, &KeyLibraryDialog::updateButtonState);

    refresh();
}

void KeyLibraryDialog::refresh() {
    QVector<KeyLibEntry> entries;
    QString err;
    if (!KeyLibrary::load(entries, err) && !err.isEmpty()) {
        MsgBox::warn(this, tr("密钥库"), err);
    }
    m_table->setRowCount(entries.size());
    for (int i = 0; i < entries.size(); ++i) {
        const KeyLibEntry& e = entries.at(i);
        const QString kind = (e.kind == QStringLiteral("identity"))
                             ? tr("身份（私钥）") : tr("收件人（公钥）");
        auto put = [this, i](int col, const QString& text) {
            m_table->setItem(i, col, new QTableWidgetItem(text));
        };
        put(COL_NAME, e.name);
        put(COL_KIND, kind);
        put(COL_ALIAS, e.alias);
        put(COL_CREATED, e.created);
        put(COL_NOTES, e.notes);
        put(COL_PUBLIC, e.publicKey);
    }
    updateButtonState();
}

QVector<KeyLibEntry> KeyLibraryDialog::selectedEntries() const {
    QVector<KeyLibEntry> entries;
    QString err;
    if (!KeyLibrary::load(entries, err)) return {};
    QVector<KeyLibEntry> sel;
    const auto rows = m_table->selectionModel()->selectedRows();
    for (const auto& idx : rows) {
        const int r = idx.row();
        if (r < 0 || r >= entries.size()) continue;
        // 表格与索引同序构建；按名称匹配避免显示期间列表变化的错位
        const QString name = m_table->item(r, COL_NAME) ? m_table->item(r, COL_NAME)->text()
                                                        : QString();
        KeyLibEntry e;
        if (!name.isEmpty() && KeyLibrary::find(entries, name, &e)) sel.append(e);
    }
    return sel;
}

void KeyLibraryDialog::updateButtonState() {
    const bool has = !selectedEntries().isEmpty();
    m_btnRemove->setEnabled(has);
    m_btnExport->setEnabled(has);
    m_btnCopyPub->setEnabled(has);
    m_btnApplyRecipient->setEnabled(has);
    m_btnApplyIdentity->setEnabled(has);
}

// 私钥 -> 公钥：经 CLI -Y 派生（等价 rage-keygen -y）。失败返回空串。
QString derivePublicKey(const QString& cliPath, const QString& keyFile) {
    if (cliPath.isEmpty() || !QFileInfo::exists(cliPath)) return {};
    QProcess p;
    p.start(cliPath, {QStringLiteral("-Y"), QStringLiteral("-k"), keyFile});
    if (!p.waitForStarted(3000)) return {};
    if (!p.waitForFinished(60000)) { p.kill(); p.waitForFinished(2000); return {}; }
    if (p.exitCode() != 0) return {};
    const QString out = QString::fromUtf8(p.readAllStandardOutput()).trimmed();
    const QStringList lines = out.split(QLatin1Char('\n'), Qt::SkipEmptyParts);
    for (const QString& l : lines) {
        const QString t = l.trimmed();
        if (t.startsWith(QStringLiteral("age1"))) return t;
    }
    return {};
}

void KeyLibraryDialog::onImport() {
    const QString file = QFileDialog::getOpenFileName(
        this, tr("选择密钥文件"), QDir::homePath(), tr("所有文件 (*)"));
    if (file.isEmpty()) return;

    QString base = QFileInfo(file).completeBaseName();
    QString name;
    for (QChar ch : base) {
        const char c = ch.toLatin1();
        const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                        (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
        if (ok) name.append(ch);
    }
    if (name.isEmpty()) name = QStringLiteral("key");

    bool ok = false;
    name = QInputDialog::getText(this, tr("导入密钥"), tr("库名称（唯一）："),
                                 QLineEdit::Normal, name, &ok);
    if (!ok || name.isEmpty()) return;
    const QString alias = QInputDialog::getText(this, tr("导入密钥"), tr("别名（可选）："),
                                                QLineEdit::Normal, QString(), &ok);
    if (!ok) return;
    const QString notes = QInputDialog::getText(this, tr("导入密钥"), tr("备注（可选）："),
                                                QLineEdit::Normal, QString(), &ok);
    if (!ok) return;

    // 身份条目：导入时经 CLI 派生公钥并缓存（失败不阻塞导入）
    QString pub;
    QFile probe(file);
    if (probe.open(QIODevice::ReadOnly)) {
        const QString head = QString::fromUtf8(probe.read(64)).trimmed();
        probe.close();
        if (head.startsWith(QStringLiteral("AGE-SECRET-KEY-"))) {
            pub = derivePublicKey(m_cliPath, file);
            if (pub.isEmpty()) {
                MsgBox::warn(this, tr("导入密钥"),
                    tr("未能自动派生公钥（CLI 不可用或密钥无效）。"
                       "条目仍会导入，但加密前需用 CLI 执行 -L pub <名称> 生成缓存。"));
            }
        }
    }

    QString err;
    if (!KeyLibrary::add(file, name, alias, notes, pub, err)) {
        MsgBox::warn(this, tr("导入密钥"), err);
        return;
    }
    refresh();
}

void KeyLibraryDialog::onRemove() {
    const QVector<KeyLibEntry> sel = selectedEntries();
    if (sel.isEmpty()) return;
    QStringList names;
    for (const auto& e : sel) names << e.name;
    if (!MsgBox::confirm(this, tr("移除密钥"),
            tr("确定从密钥库移除：%1？密钥材料文件将一并删除。").arg(names.join(tr("、"))))) {
        return;
    }
    for (const QString& n : names) {
        QString err;
        if (!KeyLibrary::remove(n, err) && !err.isEmpty()) {
            MsgBox::warn(this, tr("移除密钥"), err);
        }
    }
    refresh();
}

void KeyLibraryDialog::onExport() {
    const QVector<KeyLibEntry> sel = selectedEntries();
    if (sel.size() != 1) {
        MsgBox::info(this, tr("导出"), tr("请先选中一个条目。"));
        return;
    }
    const QString dir = QFileDialog::getExistingDirectory(
        this, tr("选择导出目录"), QDir::homePath());
    if (dir.isEmpty()) return;
    QString err;
    if (!KeyLibrary::exportKey(sel.first().name, dir, err)) {
        MsgBox::warn(this, tr("导出"), err);
    }
}

void KeyLibraryDialog::onCopyPublicKey() {
    const QVector<KeyLibEntry> sel = selectedEntries();
    QStringList pubs;
    for (const auto& e : sel) {
        if (!e.publicKey.isEmpty()) pubs << e.publicKey;
    }
    if (pubs.isEmpty()) {
        MsgBox::info(this, tr("复制公钥"),
            tr("选中条目没有缓存的公钥（收件人条目的公钥即密钥文件内容，"
               "可用「导出」获取）。"));
        return;
    }
    QApplication::clipboard()->setText(pubs.join(QStringLiteral(", ")));
}

void KeyLibraryDialog::onApplyRecipients() {
    const QVector<KeyLibEntry> sel = selectedEntries();
    QStringList pubs;
    for (const auto& e : sel) {
        if (!e.publicKey.isEmpty()) pubs << e.publicKey;
    }
    if (pubs.isEmpty()) {
        MsgBox::info(this, tr("应用为收件人"),
            tr("选中条目均没有缓存的公钥。身份条目可在导入时自动缓存；"
               "也可用 CLI 执行 -L pub <名称> 后重试。"));
        return;
    }
    m_resultPublicKeys = pubs.join(QStringLiteral(", "));
    accept();
}

void KeyLibraryDialog::onApplyIdentity() {
    const QVector<KeyLibEntry> sel = selectedEntries();
    for (const auto& e : sel) {
        if (e.kind == QStringLiteral("identity")) {
            QString path;
            QString err;
            if (KeyLibrary::keyPath(e.name, path, err)) {
                m_resultIdentityPath = path;
                accept();
                return;
            }
            MsgBox::warn(this, tr("应用为身份"), err);
            return;
        }
    }
    MsgBox::info(this, tr("应用为身份"), tr("请先选中一个身份（私钥）条目。"));
}
