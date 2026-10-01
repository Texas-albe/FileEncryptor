// GUI 参数到 argv 的映射
#pragma once
#include <QString>
#include <QStringList>
#include <QProcess>

// 加密动作枚举
enum class CryptoAction {
    Encrypt,
    Decrypt,
    BatchEncrypt,
    BatchDecrypt,
    KeyGen,
    Derive,
    PubKey
};

// 加密模式枚举
enum class CryptoMode {
    XChaCha20,
    Aegis256,
    Asymmetric
};

// GUI 收集的完整参数集
struct ShellOptions {
    CryptoAction action = CryptoAction::Encrypt;
    CryptoMode mode = CryptoMode::XChaCha20;

    // 单模式取首个，批模式全部
    QStringList inputPaths;

    QString outputDir;
    // 源文件处理方式（仅加密）
    int sourceDisposition = 0;
    bool forceOverwrite = true;
    QString keyfilePath;
    QString recipientPath;
    int recipientCount = 0;
    QString identityPath;

    bool restoreName = false;

    bool writeSha256 = false;

    // zstd 开关与级别分离
    bool compress = false;
    int compressionLevel = 0;
};

class CliArgBuilder {
public:
    // 构建 argv（不含程序名）
    static QStringList buildArguments(const ShellOptions& options);

    static QProcessEnvironment buildEnvironment(const ShellOptions& options);

    // 命令预览文本构建
    static QString buildPreview(const QString& programPath, const ShellOptions& options);
};
