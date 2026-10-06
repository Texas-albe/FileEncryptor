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
    PubKey,
    WrapKey,
    UnwrapKey
};

// 密钥包装算法（与载荷加密正交：包装的是密钥，不是文件内容）
enum class WrapAlg {
    Kwp,        // RFC 5649 AES-256-KWP，长度不受 8 字节倍数限制（默认）
    AesKw,      // RFC 3394 原始 AES-KW，供旧工具互操作
    Pubkey      // 收件人公钥封装，不需要密码
};

// 加密模式枚举
enum class CryptoMode {
    XChaCha20,
    Aegis256,
    AesGcm,
    Sm4,
    Asymmetric
};

// GUI 收集的完整参数集
struct ShellOptions {
    CryptoAction action = CryptoAction::Encrypt;
    CryptoMode mode = CryptoMode::XChaCha20;
    // 非对称模式下加密文件载荷的对称算法（会话密钥由它产生，非对称只包裹该密钥）
    CryptoMode fileMode = CryptoMode::XChaCha20;

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

    // 加密压缩包：把目录树 / 多个文件打成单个 .ptd（CLI --pack）
    bool pack = false;

    // 分卷：切成 <base>.001.ptd/002/…（--split <size>），默认不勾选
    bool split = false;
    double splitSize = 100;
    // 0=MB 1=GB 2=TB
    int splitUnit = 0;

    // 目录输入 + 删除类源处置已由界面弹窗确认，CLI 不必再问一次
    bool sourceDeleteOk = false;

    bool writeSha256 = false;

    // 非对称曲线：false=X25519，true=X448（非对称封装与 -g 生成密钥对都走该曲线）
    bool useX448 = false;

    // zstd 开关与级别分离
    bool compress = false;
    int compressionLevel = 0;

    // 后量子：true=X25519+ML-KEM-768 混合收件人 / ML-DSA-65 水印；false=经典 X25519、X448 + RSA
    bool pqc = true;

    // 尾部水印（仅加密动作）：开启后在密文尾部追加签名水印记录
    bool watermark = false;
    // 水印签名私钥 PEM；为空时仍写未签名记录，CLI 不阻断加密
    QString watermarkKeyPath;

    // 加密盘（M1/M4）：非空且为加密动作时，产物入该库并写入加密索引（CLI --into-vault）
    QString intoVault;

    // ===== 密钥包装（WrapKey / UnwrapKey 动作专用）=====
    // 待包装的 32 字节 DEK 文件（WrapKey）/ 待解开的 .fekw（UnwrapKey）
    QString wrapInput;
    // 产物路径：包装为 .fekw、解包为 .dek；留空则由 CLI 按输入文件名推导
    QString wrapOutput;
    WrapAlg wrapAlg = WrapAlg::Kwp;
};

class CliArgBuilder {
public:
    // 构建 argv（不含程序名）
    static QStringList buildArguments(const ShellOptions& options);

    static QProcessEnvironment buildEnvironment(const ShellOptions& options);

    // 命令预览文本构建
    static QString buildPreview(const QString& programPath, const ShellOptions& options);

    // 水印签名私钥：界面里存的是 PEM 明文，判断它是否是密钥材料
    static bool isPrivateKeyMaterial(const QString& key);

    // 任务结束后删掉为 CLI 落的那份临时私钥
    static void cleanupWatermarkTemp();
};
