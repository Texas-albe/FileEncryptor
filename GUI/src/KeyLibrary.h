// KeyLibrary - GUI 侧密钥库存取（功能1）
// 与 CLI core/keylib.{hpp,cpp} 共用同一存储布局：
//   <用户配置目录>/keys/library.yaml   索引（仅元数据：名称/类型/别名/备注/创建时间/缓存公钥）
//   <用户配置目录>/keys/<name>.key     密钥材料文件
// 两端任一端导入的密钥对另一端立即可见。GUI 不链接 yaml-cpp，
// 索引按行解析（CLI 写出的扁平格式：每键一行标量，双引号包裹）。
#pragma once
#include <QString>
#include <QVector>

struct KeyLibEntry {
    QString name;         // 唯一名称 [A-Za-z0-9._-]，同时用作 .key 文件名
    QString kind;         // "identity" | "recipient"
    QString file;         // 材料文件名（相对库目录）
    QString alias;
    QString notes;
    QString created;      // "YYYY-MM-DD HH:MM:SS"（本地时间）
    QString publicKey;    // identity 的缓存收件人公钥（age1...）；recipient 为空
};

class KeyLibrary {
public:
    // 库目录；无用户目录（APPDATA / HOME 缺失）时返回空串
    static QString dir();
    static QString indexPath();

    static bool isValidName(const QString& name);

    // 读取索引；文件不存在视为空库（返回 true、空列表）
    static bool load(QVector<KeyLibEntry>& out, QString& err);
    static bool save(const QVector<KeyLibEntry>& entries, QString& err);
    static bool find(const QVector<KeyLibEntry>& entries,
                     const QString& name, KeyLibEntry* out = nullptr);

    // 导入密钥：复制材料到库中并收紧权限。publicKey 可空；
    // 身份公钥可由调用方先经 CLI -Y 派生后传入缓存。
    static bool add(const QString& keyPath, const QString& name,
                    const QString& alias, const QString& notes,
                    const QString& publicKey, QString& err);

    static bool remove(const QString& name, QString& err);
    static bool keyPath(const QString& name, QString& path, QString& err);
    static bool exportKey(const QString& name, const QString& destDir, QString& err);
};
