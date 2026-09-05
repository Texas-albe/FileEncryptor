// AboutDialogs 实现
#include "AboutDialogs.h"
#include "ThemeManager.h"
#include <QVBoxLayout>
#include <QTextBrowser>
#include <QDialogButtonBox>
#include <QFont>
#include <QApplication>

CreditsDialog::CreditsDialog(QWidget* parent) : QDialog(parent) {
    setWindowTitle(tr("鸣谢"));
    setMinimumSize(560, 320);

    const auto& p = ThemeManager::htmlPalette();
    const QString ver = qApp->applicationVersion().isEmpty()
                          ? QStringLiteral("1.0.0") : qApp->applicationVersion();
    auto* browser = new QTextBrowser(this);
    browser->setOpenExternalLinks(true);  // 点击链接用系统浏览器打开
    // 主题感知 HTML：body 文字/背景取自当前主题调色板，保证深色下可读（WCAG AA）
    browser->setStyleSheet(QStringLiteral("QTextBrowser{background:%1;color:%2;}")
        .arg(QLatin1String(p.bodyBg)).arg(QLatin1String(p.bodyFg)));
    browser->setHtml(QStringLiteral(
        "<html><body style='font-family: \"Microsoft YaHei\", \"Noto Sans CJK SC\", "
        "line-height: 1.7; color:%1; background:%2;'>"
        "<h2 style='color:%3;'>FileEncryptor v%7 — 鸣谢</h2>"
        "<p>感谢以下贡献者的付出：</p>"
        "<table cellspacing='8' cellpadding='2'>"
        "<tr><td><b>代码开发</b></td>"
        "<td>瑶璎珞</td>"
        "<td><a href='https://space.bilibili.com/3546692557212318' style='color:%6;'>个人主页</a></td></tr>"
        "<tr><td><b>测试</b></td>"
        "<td>就不错了我</td>"
        "<td><a href='https://space.bilibili.com/1705671238' style='color:%6;'>个人主页</a></td></tr>"
        "<tr><td><b>宣传</b></td>"
        "<td>Twilight飞友</td>"
        "<td><a href='https://space.bilibili.com/3546728261224829' style='color:%6;'>个人主页</a></td></tr>"
        "</table>"
        "<hr/>"
        "<p style='color:%4; font-size:small;'>"
        "本项目基于 libsodium 实现文件加密（XChaCha20-Poly1305 / AEGIS-256），"
        "采用 C++17 编写，跨平台运行于 Windows / Linux / macOS。</p>"
        "</body></html>")
        .arg(QLatin1String(p.bodyFg))
        .arg(QLatin1String(p.bodyBg))
        .arg(QLatin1String(p.headingGreen))
        .arg(QLatin1String(p.mutedFg))
        .arg(QLatin1String(p.headingGreen))
        .arg(QLatin1String(p.linkColor))
        .arg(ver));

    auto* btns = new QDialogButtonBox(QDialogButtonBox::Close, this);
    connect(btns, &QDialogButtonBox::rejected, this, &QDialog::accept);

    auto* lay = new QVBoxLayout(this);
    lay->addWidget(browser);
    lay->addWidget(btns);
}

ReadmeDialog::ReadmeDialog(QWidget* parent) : QDialog(parent) {
    setWindowTitle(tr("README 摘要"));
    setMinimumSize(600, 420);

    const auto& p = ThemeManager::htmlPalette();
    const QString ver = qApp->applicationVersion().isEmpty()
                          ? QStringLiteral("1.0.0") : qApp->applicationVersion();
    auto* browser = new QTextBrowser(this);
    browser->setOpenExternalLinks(true);
    browser->setStyleSheet(QStringLiteral("QTextBrowser{background:%1;color:%2;}")
        .arg(QLatin1String(p.bodyBg)).arg(QLatin1String(p.bodyFg)));
    browser->setHtml(QStringLiteral(
        "<html><body style='font-family: \"Microsoft YaHei\", \"Noto Sans CJK SC\", "
        "line-height: 1.7; color:%1; background:%2;'>"
        "<h2 style='color:%3;'>FileEncryptor v%7 — 项目摘要</h2>"
        "<p><b>简介</b>：跨平台（Windows / Linux / macOS）文件加密工具，"
        "基于 libsodium 实现 XChaCha20-Poly1305 与 AEGIS-256 加密。</p>"
        "<h3>核心特性</h3>"
        "<ul>"
        "<li><b>加密算法</b>：XChaCha20-Poly1305（默认）/ AEGIS-256，密钥经 Argon2id 派生</li>"
        "<li><b>单文件与批量</b>：支持单文件加/解密，及目录批量加/解密（递归）</li>"
        "<li><b>断点续传</b>：加密中断后可从上次进度继续，防静默数据丢失</li>"
        "<li><b>路径安全</b>：拒绝目录穿越（..），白名单前缀校验</li>"
        "<li><b>限速</b>：进程级令牌桶限速（YAML max_speed 配置）</li>"
        "<li><b>配置化</b>：日志/并发/路径策略等运维参数经 YAML 配置</li>"
        "</ul>"
        "<h3>命令行用法</h3>"
        "<pre style='background:%4; color:%5; padding:8px; border-radius:4px;'>"
        "FileEncryptor -e/-d &lt;FileName&gt; [-o &lt;Path&gt;] [-de] [-m xchacha20|aegis256] [-y]\n"
        "FileEncryptor -be/-bd &lt;Path&gt; [-o &lt;Path&gt;] [-de] [-m xchacha20|aegis256] [-y]"
        "</pre>"
        "<h3>密钥来源优先级</h3>"
        "<p><code>-k &lt;keyfile&gt;</code>（密钥文件） &gt; <code>ENCRYPTOR_KEY</code>（环境变量）"
        " &gt; 交互式输入</p>"
        "<h3>许可证</h3>"
        "<p>GPLv3</p>"
        "<hr/>"
        "<p style='color:%6; font-size:small;'>本窗口为 README 摘要，完整文档请见项目根目录 README.md</p>"
        "</body></html>")
        .arg(QLatin1String(p.bodyFg))
        .arg(QLatin1String(p.bodyBg))
        .arg(QLatin1String(p.headingBlue))
        .arg(QLatin1String(p.preBg))
        .arg(QLatin1String(p.preFg))
        .arg(QLatin1String(p.mutedFg))
        .arg(ver));

    auto* btns = new QDialogButtonBox(QDialogButtonBox::Close, this);
    connect(btns, &QDialogButtonBox::rejected, this, &QDialog::accept);

    auto* lay = new QVBoxLayout(this);
    lay->addWidget(browser);
    lay->addWidget(btns);
}
