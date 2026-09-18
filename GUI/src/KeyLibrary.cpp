// KeyLibrary 实现。索引格式与 CLI core/keylib.cpp 严格一致：
//   # 注释行
//   keys:
//     - name: "x"
//       kind: "identity"
//       file: "x.key"
//       alias: ""
//       notes: ""
//       created: "2026-09-18 21:00:00"
//       public: "age1..."
// 解析按行进行（GUI 不链接 yaml-cpp）；写入与 CLI 逐字段相同。
#include "KeyLibrary.h"

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QSaveFile>
#include <QTextStream>

#include <algorithm>

#ifdef Q_OS_WIN
#include <windows.h>
#endif

namespace {

// 单行清洗：去控制字符与引号/反斜杠（与 CLI sanitize_single_line 一致）
QString sanitizeLine(const QString& s) {
    QString out;
    out.reserve(s.size());
    for (QChar ch : s) {
        const ushort u = ch.unicode();
        if (u < 0x20 || u == 0x7F) continue;
        if (u == '"' || u == '\\') continue;
        out.append(ch);
    }
    return out.trimmed();
}

// 行首到冒号：字段名；冒号后：原始值（可能带引号）
bool splitField(const QString& line, QString& key, QString& value) {
    const int pos = line.indexOf(QLatin1Char(':'));
    if (pos < 0) return false;
    key = line.left(pos).trimmed();
    value = line.mid(pos + 1).trimmed();
    // 去包裹引号并反转义（CLI 兜底转义 \" 与 \\）
    if (value.size() >= 2 && value.startsWith(QLatin1Char('"')) && value.endsWith(QLatin1Char('"'))) {
        QString inner = value.mid(1, value.size() - 2);
        QString out;
        out.reserve(inner.size());
        for (int i = 0; i < inner.size(); ++i) {
            if (inner.at(i) == QLatin1Char('\\') && i + 1 < inner.size()) { ++i; }
            out.append(inner.at(i));
        }
        value = out;
    }
    return true;
}

} // namespace

QString KeyLibrary::dir() {
#ifdef Q_OS_WIN
    QString base = qEnvironmentVariable("APPDATA");
    if (base.isEmpty()) return QString();
    // APPDATA 本身是反斜杠；拼接后统一转为系统原生分隔符，避免 "/"、"\" 混用
    return QDir::toNativeSeparators(base + QStringLiteral("/FileEncryptor/keys"));
#else
    QString base = qEnvironmentVariable("XDG_CONFIG_HOME");
    if (base.isEmpty()) {
        const QString home = QDir::homePath();
        if (home.isEmpty()) return QString();
        base = home + QStringLiteral("/.config");
    }
    return QDir::toNativeSeparators(base + QStringLiteral("/fileencryptor/keys"));
#endif
}

QString KeyLibrary::indexPath() {
    const QString d = dir();
    return d.isEmpty() ? QString()
                       : QDir::toNativeSeparators(d + QStringLiteral("/library.yaml"));
}

bool KeyLibrary::isValidName(const QString& name) {
    if (name.isEmpty() || name.size() > 64) return false;
    if (name == QStringLiteral(".") || name == QStringLiteral("..")) return false;
    for (QChar ch : name) {
        const char c = ch.toLatin1();
        const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                        (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
        if (!ok) return false;
    }
    return true;
}

bool KeyLibrary::load(QVector<KeyLibEntry>& out, QString& err) {
    out.clear();
    const QString path = indexPath();
    if (path.isEmpty()) { err = QObject::tr("无用户配置目录可用。"); return false; }
    QFile f(path);
    if (!f.exists()) return true;   // 空库
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) {
        err = QObject::tr("无法读取密钥库索引: %1").arg(path);
        return false;
    }
    bool inKeys = false;
    bool haveEntry = false;
    KeyLibEntry cur;
    while (!f.atEnd()) {
        QString line = QString::fromUtf8(f.readLine()).trimmed();
        if (line.isEmpty() || line.startsWith(QLatin1Char('#'))) continue;
        if (line == QStringLiteral("keys:")) { inKeys = true; continue; }
        if (!inKeys) continue;
        if (line.startsWith(QStringLiteral("- "))) {
            if (haveEntry && !cur.name.isEmpty() && !cur.file.isEmpty()) out.append(cur);
            cur = KeyLibEntry();
            haveEntry = true;
            line = line.mid(2).trimmed();
        }
        if (!haveEntry) continue;
        QString key, value;
        if (!splitField(line, key, value)) continue;
        if      (key == QStringLiteral("name"))   cur.name = value;
        else if (key == QStringLiteral("kind"))   cur.kind = value;
        else if (key == QStringLiteral("file"))   cur.file = value;
        else if (key == QStringLiteral("alias"))  cur.alias = value;
        else if (key == QStringLiteral("notes"))  cur.notes = value;
        else if (key == QStringLiteral("created")) cur.created = value;
        else if (key == QStringLiteral("public")) cur.publicKey = value;
    }
    f.close();
    if (haveEntry && !cur.name.isEmpty() && !cur.file.isEmpty()) out.append(cur);

    // 重名取首条（与 CLI 一致）
    QVector<KeyLibEntry> dedup;
    for (const auto& e : out) {
        bool dup = false;
        for (const auto& d : dedup) if (d.name == e.name) { dup = true; break; }
        if (!dup) dedup.append(e);
    }
    out = dedup;
    return true;
}

bool KeyLibrary::save(const QVector<KeyLibEntry>& entries, QString& err) {
    const QString d = dir();
    const QString path = indexPath();
    if (d.isEmpty() || path.isEmpty()) { err = QObject::tr("无用户配置目录可用。"); return false; }
    if (!QDir().mkpath(d)) { err = QObject::tr("无法创建密钥库目录: %1").arg(d); return false; }

    QString text = QStringLiteral(
        "# FileEncryptor key library index.\n"
        "# Key material lives in the individual .key files next to this index;\n"
        "# this file holds metadata only. Names are referenced by -K <name>.\n"
        "keys:\n");
    for (const auto& e : entries) {
        text += QStringLiteral("  - name: \"%1\"\n").arg(e.name);
        text += QStringLiteral("    kind: \"%1\"\n").arg(e.kind);
        text += QStringLiteral("    file: \"%1\"\n").arg(e.file);
        text += QStringLiteral("    alias: \"%1\"\n").arg(e.alias);
        text += QStringLiteral("    notes: \"%1\"\n").arg(e.notes);
        text += QStringLiteral("    created: \"%1\"\n").arg(e.created);
        text += QStringLiteral("    public: \"%1\"\n").arg(e.publicKey);
    }

    QSaveFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) {
        err = QObject::tr("无法写入密钥库索引: %1").arg(path);
        return false;
    }
    f.write(text.toUtf8());
    if (!f.commit()) {
        err = QObject::tr("写入密钥库索引失败: %1").arg(path);
        return false;
    }
    return true;
}

bool KeyLibrary::find(const QVector<KeyLibEntry>& entries,
                      const QString& name, KeyLibEntry* out) {
    for (const auto& e : entries) {
        if (e.name == name) {
            if (out) *out = e;
            return true;
        }
    }
    return false;
}

bool KeyLibrary::add(const QString& keyPath, const QString& name,
                     const QString& alias, const QString& notes,
                     const QString& publicKey, QString& err) {
    if (!isValidName(name)) {
        err = QObject::tr("密钥名称非法（1..64 字符，仅限 A-Z a-z 0-9 . _ -）: %1").arg(name);
        return false;
    }
    QVector<KeyLibEntry> entries;
    if (!load(entries, err)) return false;
    if (find(entries, name, nullptr)) {
        err = QObject::tr("同名密钥已存在: %1（请先移除）").arg(name);
        return false;
    }

    // 读取材料并识别类型（与 CLI 相同的前缀判定）
    QFile src(keyPath);
    if (!src.open(QIODevice::ReadOnly)) {
        err = QObject::tr("无法打开密钥文件: %1").arg(keyPath);
        return false;
    }
    const QByteArray raw = src.readAll();
    src.close();
    if (raw.size() > 256 * 1024) {
        err = QObject::tr("密钥文件过大（>256 KB）: %1").arg(keyPath);
        return false;
    }
    const QString content = QString::fromUtf8(raw).trimmed();
    if (content.isEmpty()) { err = QObject::tr("密钥文件为空: %1").arg(keyPath); return false; }

    QString kind;
    if (content.startsWith(QStringLiteral("AGE-SECRET-KEY-"))) {
        kind = QStringLiteral("identity");
    } else if (content.startsWith(QStringLiteral("age1"), Qt::CaseInsensitive) ||
               content.startsWith(QStringLiteral("publickey:"), Qt::CaseInsensitive)) {
        kind = QStringLiteral("recipient");
    } else {
        err = QObject::tr("无法识别的密钥内容（应为 AGE-SECRET-KEY-... 或 age1...）: %1").arg(keyPath);
        return false;
    }

    const QString d = dir();
    if (!QDir().mkpath(d)) { err = QObject::tr("无法创建密钥库目录: %1").arg(d); return false; }
    const QString fileName = name + QStringLiteral(".key");
    const QString dst = QDir::toNativeSeparators(d + QLatin1Char('/') + fileName);
    // 目标已存在（索引残缺时可能发生）：先清只读再覆盖
    if (QFileInfo::exists(dst)) {
#ifdef Q_OS_WIN
        const QString wpath = QDir::toNativeSeparators(dst);
        const DWORD attrs = GetFileAttributesW(reinterpret_cast<const wchar_t*>(wpath.utf16()));
        if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_READONLY))
            SetFileAttributesW(reinterpret_cast<const wchar_t*>(wpath.utf16()),
                               attrs & ~FILE_ATTRIBUTE_READONLY);
#endif
    }
    QSaveFile out(dst);
    if (!out.open(QIODevice::WriteOnly | QIODevice::Text)) {
        err = QObject::tr("无法写入密钥文件: %1").arg(dst);
        return false;
    }
    out.write((content + QLatin1Char('\n')).toUtf8());
    if (!out.commit()) { err = QObject::tr("写入密钥文件失败: %1").arg(dst); return false; }

    KeyLibEntry e;
    e.name = name;
    e.kind = kind;
    e.file = fileName;
    e.alias = sanitizeLine(alias);
    e.notes = sanitizeLine(notes);
    e.created = QDateTime::currentDateTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"));
    e.publicKey = (kind == QStringLiteral("identity")) ? publicKey.trimmed() : QString();
    entries.append(e);
    return save(entries, err);
}

bool KeyLibrary::remove(const QString& name, QString& err) {
    QVector<KeyLibEntry> entries;
    if (!load(entries, err)) return false;
    KeyLibEntry found;
    if (!find(entries, name, &found)) {
        err = QObject::tr("密钥库中不存在: %1").arg(name);
        return false;
    }
    QVector<KeyLibEntry> remaining;
    remaining.reserve(entries.size() - 1);
    for (const auto& e : entries) if (e.name != name) remaining.append(e);
    if (!save(remaining, err)) return false;

    const QString dst = QDir::toNativeSeparators(dir() + QLatin1Char('/') + found.file);
    if (QFileInfo::exists(dst) && !QFile::remove(dst)) {
        err = QObject::tr("索引已更新，但密钥材料文件删除失败: %1").arg(dst);
    }
    return true;
}

bool KeyLibrary::keyPath(const QString& name, QString& path, QString& err) {
    QVector<KeyLibEntry> entries;
    if (!load(entries, err)) return false;
    KeyLibEntry e;
    if (!find(entries, name, &e)) {
        err = QObject::tr("密钥库中不存在: %1").arg(name);
        return false;
    }
    path = QDir::toNativeSeparators(dir() + QLatin1Char('/') + e.file);
    if (!QFileInfo::exists(path)) {
        err = QObject::tr("密钥材料文件缺失: %1").arg(path);
        return false;
    }
    return true;
}

bool KeyLibrary::exportKey(const QString& name, const QString& destDir, QString& err) {
    QVector<KeyLibEntry> entries;
    if (!load(entries, err)) return false;
    KeyLibEntry e;
    if (!find(entries, name, &e)) {
        err = QObject::tr("密钥库中不存在: %1").arg(name);
        return false;
    }
    QString dest = destDir.isEmpty() ? QStringLiteral(".") : destDir;
    if (!dest.endsWith(QLatin1Char('/')) && !dest.endsWith(QLatin1Char('\\'))) dest += QLatin1Char('/');
    dest += e.file;
    if (QFileInfo::exists(dest)) {
        err = QObject::tr("目标文件已存在，拒绝覆盖: %1").arg(dest);
        return false;
    }
    const QString src = dir() + QLatin1Char('/') + e.file;
    if (!QFile::copy(src, dest)) {
        err = QObject::tr("导出失败: %1 -> %2").arg(src, dest);
        return false;
    }
    return true;
}
