// CliArgBuilder - GUI 参数 → FileEncryptor argv
// 严格 1:1 映射 main.cpp 的参数解析（见 FileEncryptor/main.cpp L188-262）：
//   模式：-e / -d / -be / -bd
//   选项：-o <dir> / -de / -m xchacha20|aegis256 / -i <path>(批) / -y / -v / -k <keyfile>
//   输入：单模式用位置参数；批模式用 -i
// 密钥不经 argv（避免出现在命令行/进程列表被 ps 窥探），改由 ENCRYPTOR_KEY 环境变量注入
//   （对应 main.cpp L327：const char* ek=std::getenv("ENCRYPTOR_KEY")）
#pragma once
#include <QString>
#include <QStringList>
#include <QProcess>

// 加密动作（对应 main.cpp 的 ACTION_*）
enum class CryptoAction {
    Encrypt,        // -e
    Decrypt,        // -d
    BatchEncrypt,   // -be
    BatchDecrypt    // -bd
};

// 加密模式（对应 main.cpp CryptoMode）
enum class CryptoMode {
    XChaCha20,   // xchacha20（默认；AEGIS-256 缺 AES-NI 时也回退到此）
    Aegis256     // aegis256
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
    QString keyfilePath;         // -k <keyfile>（空=用密码经 ENCRYPTOR_KEY env）

    QString password;            // 右侧密码框内容（经 ENCRYPTOR_KEY env 注入子进程）
};

class CliArgBuilder {
public:
    // 构建 argv（不含程序名）。options.inputPaths 至少需 1 条，否则返回空（由调用方校验）。
    static QStringList buildArguments(const ShellOptions& options);

    // 构建环境变量覆盖：把密码写入 ENCRYPTOR_KEY（仅当未用 -k 密钥文件时）。
    // 调用方将其合并到 CommandRequest.extraEnv。
    static QProcessEnvironment buildEnvironment(const ShellOptions& options);

    // 命令预览（用于下部只读文本框展示"将要执行的命令"）
    static QString buildPreview(const QString& programPath, const ShellOptions& options);
};
