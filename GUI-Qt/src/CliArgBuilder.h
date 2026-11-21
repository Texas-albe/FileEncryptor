// GUI 参数到 argv
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
    PubKey,
    WrapKey,
    UnwrapKey
};

// 密钥包装算法
enum class WrapAlg {
    Kwp,        // RFC 5649 AES-256-KWP，长度不受
    AesKw,      // RFC 3394 原始 AES-KW，供旧工具互
    Pubkey      // 收件人公钥封装
};

// 加密模式枚举
enum class CryptoMode {
    XChaCha20,
    Aegis256,
    AesGcm,
    Sm4,
    Asymmetric
};

// GUI 收集
struct ShellOptions {
    CryptoAction action = CryptoAction::Encrypt;
    CryptoMode mode = CryptoMode::XChaCha20;
    // 非对称模式下加
    CryptoMode fileMode = CryptoMode::XChaCha20;

    // 单模式取首
    QStringList inputPaths;

    QString outputDir;
    // 源文件处理方式
    int sourceDisposition = 0;
    bool forceOverwrite = true;
    QString keyfilePath;
    QString recipientPath;
    int recipientCount = 0;
    QString identityPath;

    bool restoreName = false;

    // 加密压缩包
    bool pack = false;

    // 分卷
    bool split = false;
    double splitSize = 100;
    // 0=MB 1=GB 2=TB
    int splitUnit = 0;

    // 目录输入 + 删除类
    bool sourceDeleteOk = false;

    bool writeSha256 = false;

    // 非对称曲线
    bool useX448 = false;

    // zstd 开关
    bool compress = false;
    int compressionLevel = 0;

    // 后量子
    bool pqc = true;

    // 尾部水印
    bool watermark = false;
    // 水印签名私钥 PEM
    QString watermarkKeyPath;

    // 加密盘
    QString intoVault;

    // 批量过滤
    QStringList excludePatterns;
    bool skipHidden = false;

    // 密钥包装
    // 待包装
    QString wrapInput;
    // 产物路径
    QString wrapOutput;
    WrapAlg wrapAlg = WrapAlg::Kwp;
};

class CliArgBuilder {
public:
    // 构建 argv
    static QStringList buildArguments(const ShellOptions& options);

    // M49
    static QStringList buildArgumentsForPreview(const ShellOptions& options);

    // H6b
    static void setTempFileAcl(const QString& path);

    static QProcessEnvironment buildEnvironment(const ShellOptions& options);

    // 命令预览文本构
    static QString buildPreview(const QString& programPath, const ShellOptions& options);

    // 水印签名私钥
    static bool isPrivateKeyMaterial(const QString& key);

    // 任务结束后删掉
    static void cleanupWatermarkTemp();
};
