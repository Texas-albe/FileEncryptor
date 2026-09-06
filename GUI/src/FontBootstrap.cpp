// FontBootstrap.cpp

#include "FontBootstrap.h"

#include <QApplication>
#include <QFontDatabase>
#include <QFontMetrics>
#include <QProcessEnvironment>
#include <QDir>
#include <QFileInfo>
#include <QStringList>
#include <QDebug>

QString FontBootstrap::s_family;
bool    FontBootstrap::s_initialized=false;
bool    FontBootstrap::s_cjk=false;

namespace {

    // 探针字符：'中'（U+4E2D）。能画它就是一款覆盖简中的字体。
    constexpr ushort kProbeChar=0x4E2D;

    bool hasCjkGlyph(const QFont& f) {
        QFontMetrics fm(f);
        return fm.inFont(QChar(kProbeChar));
    }

    // 候选字体族：按"简中桌面常见度"排序，跨平台都列全
    QStringList cjkCandidates() {
        return {
            QStringLiteral("Noto Sans CJK SC"),
            QStringLiteral("Noto Sans SC"),
            QStringLiteral("Source Han Sans SC"),
            QStringLiteral("Source Han Sans CN"),
            QStringLiteral("WenQuanYi Zen Hei"),
            QStringLiteral("WenQuanYi Micro Hei"),
            QStringLiteral("WenQuanYi Bitmap Song"),
            QStringLiteral("AR PL UMing CN"),
            QStringLiteral("AR PL UKai CN"),
            QStringLiteral("Microsoft YaHei"),
            QStringLiteral("Microsoft YaHei UI"),
            QStringLiteral("PingFang SC"),
            QStringLiteral("Hiragino Sans GB"),
            QStringLiteral("Heiti SC"),
            QStringLiteral("Songti SC"),
            QStringLiteral("SimSun"),
            QStringLiteral("NSimSun"),
            QStringLiteral("SimHei"),
        };
    }

    // 等宽候选（命令输出窗口）：先要等宽，其次要有中文
    QStringList monoCjkCandidates() {
        return {
            QStringLiteral("Noto Sans Mono CJK SC"),
            QStringLiteral("Sarasa Mono SC"),
            QStringLiteral("Source Han Mono SC"),
            QStringLiteral("WenQuanYi Zen Hei Mono"),
            QStringLiteral("DejaVu Sans Mono"),
            QStringLiteral("Liberation Mono"),
            QStringLiteral("Consolas"),
        };
    }

    bool debugEnabled() {
        return QProcessEnvironment::systemEnvironment()
            .value(QStringLiteral("FILEENCRYPTOR_FONT_DEBUG"))==QStringLiteral("1");
    }

    // 从构建期嵌入的资源字体里挑一款含中文的
    QString loadBundledFont() {
        QDir d(QStringLiteral(":/fonts"));
        if(!d.exists()) return {};
        const QFileInfoList files=d.entryInfoList(
            {QStringLiteral("*.ttf"), QStringLiteral("*.otf")},QDir::Files,QDir::Name);
        for(const QFileInfo& fi:files) {
            const int id=QFontDatabase::addApplicationFont(fi.absoluteFilePath());
            if(id<0) {
                qWarning()<<"[font] 嵌入字体加载失败:"<<fi.fileName();
                continue;
            }
            const QStringList fams=QFontDatabase::applicationFontFamilies(id);
            for(const QString& fam:fams) {
                QFont f(fam);
                if(hasCjkGlyph(f)) {
                    if(debugEnabled())
                        qWarning()<<"[font] 使用嵌入字体:"<<fam<<"("<<fi.fileName()<<")";
                    return fam;
                }
            }
        }
        return {};
    }

} // namespace

void FontBootstrap::initialize() {
    if(s_initialized) return;
    s_initialized=true;

    QApplication* app=qobject_cast<QApplication*>(QCoreApplication::instance());
    if(!app) return;

    const QFont appFont=app->font();
    const QStringList available=QFontDatabase::families();

    if(debugEnabled()) {
        qWarning()<<"[font] 系统字体数:"<<available.size()
            <<"默认字体:"<<appFont.family()
            <<"含中文:"<<hasCjkGlyph(appFont);
    }

    QString chosen;

    // 1) 显式覆盖（排障 / 用户偏好）
    const QString override=QProcessEnvironment::systemEnvironment()
        .value(QStringLiteral("FILEENCRYPTOR_UI_FONT")).trimmed();
    if(!override.isEmpty()) {
        chosen=override;
    }
    // 2) 默认字体本身就有中文 → 不动（Windows / macOS 常规路径）
    else if(hasCjkGlyph(appFont)) {
        chosen=appFont.family();
    }
    // 3) 系统字体里挑一款含中文的
    else {
        for(const QString& fam:cjkCandidates()) {
            if(!available.contains(fam,Qt::CaseInsensitive)) continue;
            QFont f(fam);
            if(hasCjkGlyph(f)) { chosen=fam; break; }
        }
        // 4) 兜底：构建期嵌入的字体
        if(chosen.isEmpty()) chosen=loadBundledFont();
    }

    if(chosen.isEmpty()) {
        // 5) 都没有：不阻塞启动，仅告警
        qWarning()<<"[font] 未找到含中文的字体，界面中文可能显示为方块。"
            <<"请安装中文字体（Debian/Ubuntu: sudo apt install fonts-noto-cjk）"
            <<"或用 FILEENCRYPTOR_UI_FONT=<字体族名> 指定。";
        s_family=appFont.family();
        s_cjk=hasCjkGlyph(appFont);
        return;
    }

    QFont f(chosen);
    const qreal pt=appFont.pointSizeF()>0 ? appFont.pointSizeF() : 9.0;
    f.setPointSizeF(pt);
    app->setFont(f);

    s_family=chosen;
    s_cjk=true;

    if(debugEnabled())
        qWarning()<<"[font] 界面字体:"<<chosen<<"字号:"<<pt;
}

QFont FontBootstrap::monoFont() {
    initialize();
    QFont mono=QFontDatabase::systemFont(QFontDatabase::FixedFont);
    if(hasCjkGlyph(mono)) return mono;

    // 系统等宽字体没有中文：先试含中文的等宽候选，再退回界面字体
    const QStringList available=QFontDatabase::families();
    for(const QString& fam:monoCjkCandidates()) {
        if(!available.contains(fam,Qt::CaseInsensitive)) continue;
        QFont f(fam);
        f.setPointSizeF(mono.pointSizeF()>0 ? mono.pointSizeF() : 9.0);
        if(hasCjkGlyph(f)) return f;
    }
    if(!s_family.isEmpty()) {
        QFont f(s_family);
        f.setPointSizeF(mono.pointSizeF()>0 ? mono.pointSizeF() : 9.0);
        return f;
    }
    return mono;
}

QString FontBootstrap::uiFamily() {
    initialize();
    return s_family;
}

bool FontBootstrap::cjkAvailable() {
    initialize();
    return s_cjk;
}