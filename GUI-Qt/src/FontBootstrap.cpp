
#include "FontBootstrap.h"

#include <QApplication>
#include <QFontDatabase>
#include <QFontMetrics>
#include <QProcessEnvironment>
#include <QProcess>
#include <QStandardPaths>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QStringList>
#include <QDebug>

QString FontBootstrap::s_family;
bool    FontBootstrap::s_initialized=false;
bool    FontBootstrap::s_cjk=false;

namespace {

    // 探针字符：中
    constexpr ushort kProbeChar=0x4E2D;

    bool hasCjkGlyph(const QFont& f) {
        QFontMetrics fm(f);
        return fm.inFont(QChar(kProbeChar));
    }

    // 候选字体族按常见度排序
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

    // 从嵌入资源字体挑选
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

    // 导出嵌入字体给 fontconfig
    void exportBundledFontForSystem() {
        QFile src(QStringLiteral(":/fonts/NotoSansSC-Regular.otf"));
        if(!src.exists()) return;

        const QString dir=QStandardPaths::writableLocation(
            QStandardPaths::GenericDataLocation)+QStringLiteral("/fonts/FileEncryptor");
        if(!QDir().mkpath(dir)) return;

        const QString dst=dir+QStringLiteral("/NotoSansSC-Regular.otf");
        if(!QFileInfo::exists(dst)) {
            if(!src.copy(dst)) {
                if(debugEnabled()) qWarning()<<"[font] 嵌入字体导出失败:"<<dst;
                return;
            }
            if(debugEnabled()) qWarning()<<"[font] 已导出嵌入字体供系统使用:"<<dst;
        }
        QProcess::startDetached(QStringLiteral("fc-cache"),{QStringLiteral("-f"),dir});
    }

}

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

    // 1) 显式覆盖
    const QString override=QProcessEnvironment::systemEnvironment()
        .value(QStringLiteral("FILEENCRYPTOR_UI_FONT")).trimmed();
    if(!override.isEmpty()) {
        chosen=override;
    }
    // 2) 默认字体已含中文
    else if(hasCjkGlyph(appFont)) {
        chosen=appFont.family();
    }
    // 3) 挑选系统含中文字体
    else {
        for(const QString& fam:cjkCandidates()) {
            if(!available.contains(fam,Qt::CaseInsensitive)) continue;
            QFont f(fam);
            if(hasCjkGlyph(f)) { chosen=fam; break; }
        }
        // 4) 兜底嵌入字体
        if(chosen.isEmpty()) {
            chosen=loadBundledFont();
            if(!chosen.isEmpty()) exportBundledFontForSystem();
        }
    }

    if(chosen.isEmpty()) {
        // 5) 都没有则告警放行
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