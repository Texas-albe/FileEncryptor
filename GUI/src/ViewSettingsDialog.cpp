// ViewSettingsDialog 实现
#include "ViewSettingsDialog.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QFileDialog>
#include <QDialogButtonBox>
#include <QPixmap>
#include <QFileInfo>
#include <QDir>

ViewSettingsDialog::ViewSettingsDialog(const QString& currentPath, QWidget* parent)
    : QDialog(parent), m_current(currentPath) {
    setWindowTitle(tr("视图设置"));
    setMinimumWidth(420);

    auto* root = new QVBoxLayout(this);

    // 说明
    auto* tip = new QLabel(tr("选择一张图片作为主窗口背景。背景会随窗口大小自适应铺满，"
                             "并在主题切换 / 重启后保持生效。"));
    tip->setWordWrap(true);
    root->addWidget(tip);

    // 预览区
    m_preview = new QLabel;
    m_preview->setFixedHeight(200);
    m_preview->setAlignment(Qt::AlignCenter);
    m_preview->setFrameShape(QFrame::StyledPanel);
    m_preview->setScaledContents(false);
    root->addWidget(m_preview);
    updatePreview(m_current);

    // 操作按钮行
    auto* row = new QHBoxLayout;
    m_btnChoose = new QPushButton(tr("选择图片..."));
    m_btnClear  = new QPushButton(tr("清除背景"));
    row->addWidget(m_btnChoose);
    row->addWidget(m_btnClear);
    row->addStretch();
    root->addLayout(row);

    // 标准确定/取消
    auto* box = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    root->addWidget(box);

    connect(m_btnChoose, &QPushButton::clicked, this, &ViewSettingsDialog::onChoose);
    connect(m_btnClear,  &QPushButton::clicked, this, &ViewSettingsDialog::onClear);
    connect(box, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(box, &QDialogButtonBox::rejected, this, &QDialog::reject);

    // 确定前把当前选择写入结果
    connect(this, &QDialog::accepted, this, [this]{ m_result = m_current; });
}

void ViewSettingsDialog::onChoose() {
    const QString path = QFileDialog::getOpenFileName(
        this, tr("选择背景图片"),
        m_current.isEmpty() ? QDir::homePath() : QFileInfo(m_current).absolutePath(),
        tr("图片文件 (*.png *.jpg *.jpeg *.bmp *.gif *.webp);;所有文件 (*)"));
    if (path.isEmpty()) return;
    if (!QFileInfo(path).isFile()) {
        m_preview->setText(tr("文件不存在或不可读"));
        return;
    }
    m_current = path;
    updatePreview(path);
}

void ViewSettingsDialog::onClear() {
    m_current = QString();
    m_preview->setText(tr("（无背景，使用纯色主题背景）"));
    m_preview->setPixmap(QPixmap());
}

void ViewSettingsDialog::updatePreview(const QString& path) {
    if (path.isEmpty()) {
        m_preview->setText(tr("（无背景，使用纯色主题背景）"));
        m_preview->setPixmap(QPixmap());
        return;
    }
    const QPixmap pm(path);
    if (pm.isNull()) {
        m_preview->setText(tr("无法加载图片：%1").arg(path));
        m_preview->setPixmap(QPixmap());
        return;
    }
    // 等比缩放到预览区宽度
    const QPixmap scaled = pm.scaledToWidth(m_preview->width() > 0 ? m_preview->width() : 400,
                                            Qt::SmoothTransformation);
    m_preview->setPixmap(scaled);
}
