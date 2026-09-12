// CliArgBuilder - GUI 参数 → FileEncryptor argv
// 严格 1:1 映射 main.cpp 的参数解析（见 FileEncryptor/main.cpp L188-262）：
//   模式：-e / -d / -be / -bd
//   选项：-o <dir> / -de / -m xchacha20|aegis256|rage / -i <path>(批) / -y / -v / -k <keyfile>
//        / -r <pub|file> (asymmetric encrypt) / -k <private key file> (asymmetric decrypt)
//   输入：单模式用位置参数；批模式用 -i
// 密钥/身份私钥不经 argv（避免出现在命令行/进程列表被 ps 窥探），也不经环境变量，
//   改由子进程 stdin 管道注入（对应 main.cpp --key-stdin：读取整段 stdin 作为密钥材料），
//   更加安全（stdin 管道不被其它进程通过 /proc 或环境窥探）。
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
    bool deleteSource = false;   // -de（仅加密）
    bool forceOverwrite = true;  // -y（GUI 非交互，默认带 -y 避开 stdin 覆盖提示）
    bool verbose = false;        // -v
    QString keyfilePath;         // -k <keyfile>（对称模式：密钥文件；空=密码经 stdin）
    QString recipientPath;       // -r <pub|file> (asymmetric encrypt: "age1..." public key or a file of them; goes via argv)
    QString identityPath;        // asymmetric decrypt: private key file, handed to the CLI as -k (never via env/argv/stdin)

    bool restoreName = false;    // 批量解密是否还原完整原始文件名（默认 false：仅保留扩展名，省去每文件 KDF）
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
