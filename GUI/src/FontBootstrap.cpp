// FontBootstrap.cpp

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

    // 把嵌入字体导出到 fontconfig 用户字体目录并刷新缓存。
    //
    // 背景：系统无任何 CJK 字体时，界面内文字由 Qt 用嵌入字体兜底渲染正常，
    // 但窗口标题栏由窗口管理器（fontconfig/Pango）绘制——它拿不到 CJK 字形，
    // 标题里的汉字会渲染为码点方块（如"未找到"→ 672A/627E/5230）。
    // 导出后 fontconfig 客户端（WM / Pango）即可找到字形；通常重启应用后生效。
    void exportBundledFontForSystem() {
        QFile src(QStringLiteral(":/fonts/NotoSansSC-Regular.otf"));
        if(!src.exists()) return; // Windows 构建不嵌入字体，无需导出

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
        // 已导出过或刚导出：刷新缓存（fc-cache 不存在则静默忽略，
        // 部分 fontconfig 实现会自动扫描用户目录）
        QProcess::startDetached(QStringLiteral("fc-cache"),{QStringLiteral("-f"),dir});
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
        // 4) 兜底：构建期嵌入的字体（系统侧也没有 CJK 字体时，
        //    顺手把字体导出给 fontconfig，修复标题栏方块）
        if(chosen.isEmpty()) {
            chosen=loadBundledFont();
            if(!chosen.isEmpty()) exportBundledFontForSystem();
        }
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