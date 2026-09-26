// CliArgBuilder - GUI 参数 → FileEncryptor argv，严格 1:1 映射 main.cpp 的参数解析（模式 -e/-d/-be/-bd，选项 -o/-de/-m/-i/-y/-k/-r 等）。
// 密钥/身份私钥不经 argv 与环境变量，改由子进程 stdin 管道注入（--key-stdin），避免被 ps / 环境窥探。
#pragma once
#include <QString>
#include <QStringList>
#include <QProcess>

// 加密动作（对应 main.cpp 的 ACTION_*）
enum class CryptoAction {
    Encrypt,        // -e
    Decrypt,        // -d
    BatchEncrypt,   // -be
    BatchDecrypt,   // -bd
    KeyGen,         // -g：随机生成 X25519 密钥对（rage），无需输入文件
    Derive,         // -G：由口令确定性派生 X25519 密钥对（Argon2id + 随机盐）
    PubKey          // -Y：由私钥文件导出对应公钥（等价 rage-keygen -y）
};

// 加密模式（对应 main.cpp CryptoMode + -m age）
enum class CryptoMode {
    XChaCha20,   // xchacha20（默认；AEGIS-256 缺 AES-NI 时也回退到此）
    Aegis256,    // aegis256
    Asymmetric   // rage 非对称混合加密：随机文件密钥用 X25519 收件人公钥包装（rage/age 格式）
};

// GUI 收集的完整参数集
struct ShellOptions {
    CryptoAction action = CryptoAction::Encrypt;
    CryptoMode mode = CryptoMode::XChaCha20;

    // 输入路径：单模式只取第一个；批模式全部传入（每条 -i <path>）
    QStringList inputPaths;

    QString outputDir;          // -o（空=默认源目录）
    // 源文件处理方式（仅加密）：0=保留 1=删除(-de) 2=安全擦除(--wipe-source) 3=回收站(--recycle-source)
    int sourceDisposition = 0;
    bool forceOverwrite = true;  // -y（GUI 非交互，默认带 -y 避开 stdin 覆盖提示）
    QString keyfilePath;         // -k <keyfile>（对称模式：密钥文件；空=密码经 stdin）
    QString recipientPath;       // -r <pub|file> (asymmetric encrypt: "age1..." public key or a file of them; goes via argv)
    int recipientCount = 0;       // 收件人条数（collectOptions 统计；多收件人预览显示"N 个收件人"而非临时文件路径）
    QString identityPath;        // asymmetric decrypt: private key file, handed to the CLI as -k (never via env/argv/stdin)

    bool restoreName = false;    // 批量解密是否还原完整原始文件名（默认 false：仅保留扩展名，省去每文件 KDF）

    bool writeSha256 = false;    // --sha256：加密成功后生成 <out>.ptd.sha256 校验单（仅加密下发）

    // zstd 压缩：开关与级别分离 —— compress 是布尔开关（下发 -zstd，不带参数值），
    // compressionLevel 仅在需要非默认级别时才额外下发 --compression-level <N>。
    bool compress = false;       // -zstd（布尔开关；仅对称加密有效）
    int compressionLevel = 0;    // 0 = 不指定（用 CLI 默认级别 1）；否则 -5..22
};

class CliArgBuilder {
public:
    // 构建 argv（不含程序名）。options.inputPaths 至少需 1 条，否则返回空（由调用方校验）。
    static QStringList buildArguments(const ShellOptions& options);

    // 密钥经子进程 stdin 管道注入（见 buildArguments 的 --key-stdin），不写入 ENCRYPTOR_KEY 环境变量。
    // 调用方将其合并到 CommandRequest.extraEnv。
    static QProcessEnvironment buildEnvironment(const ShellOptions& options);

    // 命令预览（用于下部只读文本框展示"将要执行的命令"）
    static QString buildPreview(const QString& programPath, const ShellOptions& options);
};
