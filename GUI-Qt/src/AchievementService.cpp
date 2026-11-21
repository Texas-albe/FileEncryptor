#include "AchievementService.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSaveFile>
#include <QSet>
#include <utility>

namespace {

// 包清单随 exe
QString packPath() {
    return QDir(QCoreApplication::applicationDirPath())
        .filePath(QStringLiteral("pack.json"));
}

// 命名空间 ID 转相对路径
QString toRelPath(const QString& id) {
    const int colon = id.indexOf(QLatin1Char(':'));
    if (colon < 0 || colon == id.size() - 1) return QString();
    return id.mid(colon + 1) + QStringLiteral(".json");
}

// 状态目录 与任务历史同级
QString stateDir() {
#ifdef Q_OS_WIN
    QString base = qEnvironmentVariable("APPDATA");
    if (base.isEmpty()) return QString();
    base = base + QStringLiteral("/FileEncryptor");
#else
    QString base = qEnvironmentVariable("XDG_CONFIG_HOME");
    if (base.isEmpty()) base = QDir::homePath() + QStringLiteral("/.config");
    if (base.isEmpty()) return QString();
    base = base + QStringLiteral("/fileencryptor");
#endif
    return QDir::toNativeSeparators(base);
}

QString statePath() {
    const QString d = stateDir();
    if (d.isEmpty()) return QString();
    return QDir(d).filePath(QStringLiteral("achievements.state.json"));
}

// 文本组件 字符串或对象
AdvText parseText(const QJsonValue& v) {
    AdvText t;
    if (v.isString()) {
        t.text = v.toString();
        return t;
    }
    if (!v.isObject()) return t;
    const QJsonObject o = v.toObject();
    t.text = o.value(QStringLiteral("text")).toString();
    t.textEn = o.value(QStringLiteral("text_en")).toString();
    t.textRu = o.value(QStringLiteral("text_ru")).toString();
    return t;
}

// 准则条件 count 界限 数字或 minmax
CriterionDef parseCriterion(const QJsonObject& co) {
    CriterionDef c;
    c.trigger = co.value(QStringLiteral("trigger")).toString();
    if (!co.contains(QStringLiteral("conditions"))) return c;
    const QJsonValue cv = co.value(QStringLiteral("conditions"))
                              .toObject().value(QStringLiteral("count"));
    if (cv.isDouble()) {
        c.hasMin = c.hasMax = true;
        c.min = c.max = static_cast<qint64>(cv.toDouble());
    } else if (cv.isObject()) {
        const QJsonObject o = cv.toObject();
        if (o.contains(QStringLiteral("min"))) {
            c.hasMin = true;
            c.min = static_cast<qint64>(o.value(QStringLiteral("min")).toDouble());
        }
        if (o.contains(QStringLiteral("max"))) {
            c.hasMax = true;
            c.max = static_cast<qint64>(o.value(QStringLiteral("max")).toDouble());
        }
    }
    return c;
}

AdvDisplay parseDisplay(const QJsonObject& dv) {
    AdvDisplay d;
    d.icon = dv.value(QStringLiteral("icon")).toString();
    d.title = parseText(dv.value(QStringLiteral("title")));
    d.desc = parseText(dv.value(QStringLiteral("description")));
    const QString frame = dv.value(QStringLiteral("frame")).toString();
    if (frame == QStringLiteral("task") || frame == QStringLiteral("goal") ||
        frame == QStringLiteral("challenge"))
        d.frame = frame;
    d.background = dv.value(QStringLiteral("background")).toString();
    if (dv.contains(QStringLiteral("show_toast")))
        d.showToast = dv.value(QStringLiteral("show_toast")).toBool(true);
    if (dv.contains(QStringLiteral("hidden")))
        d.hidden = dv.value(QStringLiteral("hidden")).toBool(false);
    return d;
}

// 单个进度读入
AdvDef parseOne(const QString& id, const QJsonObject& o) {
    AdvDef d;
    d.id = id;
    if (o.contains(QStringLiteral("parent"))) {
        d.hasParent = true;
        d.parent = o.value(QStringLiteral("parent")).toString();
    }
    if (o.contains(QStringLiteral("display"))) {
        d.hasDisplay = true;
        d.display = parseDisplay(o.value(QStringLiteral("display")).toObject());
    }
    const QJsonObject cs = o.value(QStringLiteral("criteria")).toObject();
    for (auto it = cs.begin(); it != cs.end(); ++it)
        d.criteria.insert(it.key(), parseCriterion(it.value().toObject()));
    if (o.contains(QStringLiteral("requirements"))) {
        d.hasReqs = true;
        const QJsonArray arr = o.value(QStringLiteral("requirements")).toArray();
        for (const QJsonValue& g : arr) {
            QStringList grp;
            const QJsonArray ga = g.toArray();
            for (const QJsonValue& item : ga) grp.append(item.toString());
            d.requirements.append(grp);
        }
    }
    d.experience = o.value(QStringLiteral("rewards")).toObject()
                       .value(QStringLiteral("experience")).toInt(0);
    return d;
}

// 定义 JSON 读入 按 pack 清单逐文件
bool readDefs(const QString& pack, QVector<AdvDef>& out) {
    QFile pf(pack);
    if (!pf.open(QIODevice::ReadOnly)) return false;
    const QJsonDocument pdoc = QJsonDocument::fromJson(pf.readAll());
    if (!pdoc.isObject()) return false;
    const QJsonArray ids = pdoc.object()
        .value(QStringLiteral("achievements")).toArray();
    const QString root = QDir(QCoreApplication::applicationDirPath())
        .filePath(QStringLiteral("achievements"));
    for (const QJsonValue& v : ids) {
        if (!v.isString()) continue;
        const QString id = v.toString();
        const QString rel = toRelPath(id);
        if (rel.isEmpty()) continue;
        QFile f(QDir(root).filePath(rel));
        if (!f.open(QIODevice::ReadOnly)) continue;
        const QJsonDocument doc = QJsonDocument::fromJson(f.readAll());
        if (!doc.isObject()) continue;
        AdvDef d = parseOne(id, doc.object());
        if (!d.criteria.isEmpty()) out.append(d);
    }
    return true;
}

// 状态 JSON 读入
void applyState(const QJsonObject& root, QMap<QString, AdvState>& out) {
    out.clear();
    for (auto it = root.begin(); it != root.end(); ++it) {
        const QJsonObject o = it.value().toObject();
        AdvState st;
        st.done = o.value(QStringLiteral("done")).toBool(false);
        const QJsonObject cs = o.value(QStringLiteral("criteria")).toObject();
        for (auto c = cs.begin(); c != cs.end(); ++c)
            st.criteria.insert(c.key(), c.value().toString());
        out.insert(it.key(), st);
    }
}

QString pickOf(const QString& lang, const QString& def,
               const QString& en, const QString& ru) {
    if (lang == QStringLiteral("en")) return en.isEmpty() ? def : en;
    if (lang == QStringLiteral("ru")) return ru.isEmpty() ? def : ru;
    return def;
}

}  // namespace

QString AdvText::of(const QString& lang) const {
    return pickOf(lang, text, textEn, textRu);
}

AchievementService& AchievementService::instance() {
    static AchievementService s;
    return s;
}

bool AchievementService::load() {
    QMutexLocker lock(&mutex_);
    defs_.clear();
    index_.clear();
    state_.clear();
    readDefs(packPath(), defs_);
    pruneTree();
    const QString sp = statePath();
    QFile f(sp);
    if (f.exists() && f.open(QIODevice::ReadOnly)) {
        const QJsonDocument doc = QJsonDocument::fromJson(f.readAll());
        if (doc.isObject()) applyState(doc.object(), state_);
    }
    return !defs_.isEmpty();
}

QVector<AdvDef> AchievementService::observe(const QString& ev, qint64 n) {
    QVector<AdvDef> gained;
    if (ev.isEmpty()) return gained;
    {
    QMutexLocker lock(&mutex_);
    bool dirty = false;
    for (const AdvDef& d : std::as_const(defs_)) {
        AdvState& st = stateOf(d.id);
        if (st.done) continue;
        bool touched = false;
        for (auto cit = d.criteria.constBegin();
             cit != d.criteria.constEnd(); ++cit) {
            const CriterionDef& c = cit.value();
            if (c.trigger != ev) continue;
            if (st.criteria.contains(cit.key())) continue;
            // 无条件 触发即达成
            if (!c.hasMin && !c.hasMax) {
                st.criteria.insert(cit.key(), now());
                touched = true;
                continue;
            }
            if (n <= 0) continue;
            qint64 p = st.progress.value(cit.key(), 0) + n;
            if (c.hasMax && p > c.max) p = c.max;
            st.progress.insert(cit.key(), p);
            if (p >= (c.hasMin ? c.min : 0) && (!c.hasMax || p <= c.max)) {
                st.criteria.insert(cit.key(), now());
                touched = true;
            }
        }
        if (touched && isDone(d, st)) {
            st.done = true;
            gained.append(d);
            dirty = true;
        }
    }
    if (dirty) save();
    }
    // 锁外回调 防死锁
    if (onUnlocked) {
        for (const AdvDef& d : gained) onUnlocked(d);
    }
    return gained;
}

QVector<AchievementService::Entry> AchievementService::entries() const {
    QMutexLocker lock(&mutex_);
    QMap<QString, bool> cache;
    QVector<Entry> out;
    for (const AdvDef& d : std::as_const(defs_)) {
        Entry e;
        e.def = d;
        e.state = state_.value(d.id);
        e.visible = visible(d, cache);
        if (!e.visible) continue;
        out.append(e);
    }
    return out;
}

QPair<int, int> AchievementService::progress() const {
    QMutexLocker lock(&mutex_);
    int n = 0;
    for (const AdvDef& d : std::as_const(defs_))
        if (state_.value(d.id).done) n++;
    return {n, defs_.size()};
}

AdvState& AchievementService::stateOf(const QString& id) {
    return state_[id];
}

// requirements 判定 缺省全达成
bool AchievementService::isDone(const AdvDef& d, const AdvState& st) {
    if (d.criteria.isEmpty()) return false;
    if (d.hasReqs) {
        for (const QStringList& grp : std::as_const(d.requirements)) {
            if (grp.isEmpty()) return false;
            bool any = false;
            for (const QString& name : std::as_const(grp))
                if (st.criteria.contains(name)) { any = true; break; }
            if (!any) return false;
        }
        return true;
    }
    for (auto it = d.criteria.constBegin(); it != d.criteria.constEnd(); ++it)
        if (!st.criteria.contains(it.key())) return false;
    return true;
}

// MC 显示规则 根可见 父可见且非hidden 完成恒可见
bool AchievementService::visible(const AdvDef& d, QMap<QString, bool>& cache) const {
    if (cache.contains(d.id)) return cache.value(d.id);
    bool vis;
    if (state_.value(d.id).done) vis = true;
    else if (!d.hasDisplay || d.display.hidden) vis = false;
    else if (!d.hasParent) vis = true;
    else {
        auto pit = index_.constFind(d.parent);
        const AdvDef* pd = pit != index_.constEnd() ? &pit.value() : nullptr;
        vis = pd != nullptr && visible(*pd, cache);
    }
    cache.insert(d.id, vis);
    return vis;
}

// 剥离孤儿与循环引用
void AchievementService::pruneTree() {
    for (const AdvDef& d : std::as_const(defs_)) index_.insert(d.id, d);
    QSet<QString> alive;
    for (auto it = index_.constBegin(); it != index_.constEnd(); ++it)
        alive.insert(it.key());
    bool changed = true;
    while (changed) {
        changed = false;
        const QStringList ids = alive.values();
        for (const QString& id : ids) {
            const AdvDef& d = index_[id];
            if (d.hasParent && !alive.contains(d.parent)) {
                alive.remove(id);
                changed = true;
            }
        }
    }
    if (alive.size() != index_.size()) {
        QVector<AdvDef> kept;
        for (const AdvDef& d : std::as_const(defs_))
            if (alive.contains(d.id)) kept.append(d);
        defs_ = kept;
        index_.clear();
        for (const AdvDef& d : std::as_const(defs_)) index_.insert(d.id, d);
    }
}

QString AchievementService::now() {
    return QDateTime::currentDateTime().toString(Qt::ISODate);
}

void AchievementService::save() const {
    const QString sp = statePath();
    if (sp.isEmpty()) return;
    QDir().mkpath(stateDir());
    QJsonObject root;
    for (auto it = state_.constBegin(); it != state_.constEnd(); ++it) {
        QJsonObject o;
        o.insert(QStringLiteral("done"), it.value().done);
        QJsonObject cs;
        for (auto c = it.value().criteria.constBegin();
             c != it.value().criteria.constEnd(); ++c)
            cs.insert(c.key(), c.value());
        o.insert(QStringLiteral("criteria"), cs);
        root.insert(it.key(), o);
    }
    // QSaveFile 原子写
    QSaveFile f(sp);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) return;
    f.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
    f.commit();
}
