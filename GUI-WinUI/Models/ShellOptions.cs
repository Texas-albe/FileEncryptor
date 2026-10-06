namespace FileEncryptorGUI.Models;

public enum CryptoAction
{
    Encrypt,
    Decrypt,
    BatchEncrypt,
    BatchDecrypt,
    KeyGen,
    Derive,
    PubKey,
    WrapKey,
    UnwrapKey
}

// 密钥包装算法（与载荷加密正交：包装的是密钥，不是文件内容）
public enum WrapAlg
{
    Kwp = 0,        // RFC 5649 AES-256-KWP，长度不受 8 字节倍数限制（默认）
    AesKw = 1,      // RFC 3394 原始 AES-KW，供旧工具互操作
    Pubkey = 2      // 收件人公钥封装，不需要密码
}

public enum CryptoMode
{
    XChaCha20,
    Aegis256,
    AesGcm,
    Sm4,
    Asymmetric
}

public enum SourceDisposition
{
    Keep = 0,
    Delete = 1,
    Wipe = 2,
    Recycle = 3
}

// 分卷单位（CLI --split 认 1024 进制：MB=2^20, GB=2^30, TB=2^40）
public enum SplitUnit
{
    MB = 0,
    GB = 1,
    TB = 2
}

public class ShellOptions
{
    public CryptoAction Action { get; set; } = CryptoAction.Encrypt;
    public CryptoMode Mode { get; set; } = CryptoMode.XChaCha20;
    // 非对称模式下加密文件载荷的对称算法（会话密钥由它产生，非对称只包裹该密钥）
    public CryptoMode FileMode { get; set; } = CryptoMode.XChaCha20;
    public List<string> InputPaths { get; set; } = new();
    public string OutputDir { get; set; } = "";
    // 加密盘：非空且为加密动作时产物入该库并写入加密索引（CLI --into-vault）
    public string IntoVault { get; set; } = "";
    public SourceDisposition SourceDisposition { get; set; } = SourceDisposition.Keep;
    // 加密压缩包：把目录树 / 多个文件打成单个 .ptd（CLI --pack）
    public bool Pack { get; set; } = false;
    // 分卷：切成 <base>.001.ptd/002/003…（--split <size>），默认不勾选
    public bool Split { get; set; } = false;
    public double SplitSize { get; set; } = 100;
    public SplitUnit SplitUnit { get; set; } = SplitUnit.MB;
    // 目录输入 + 删除类源处置已由界面弹窗确认，CLI 不必再问一次
    public bool SourceDeleteOk { get; set; } = false;
    public bool ForceOverwrite { get; set; } = true;
    public string KeyfilePath { get; set; } = "";
    public string RecipientPath { get; set; } = "";
    public int RecipientCount { get; set; } = 0;
    public string IdentityPath { get; set; } = "";
    public bool RestoreName { get; set; } = false;
    public bool WriteSha256 { get; set; } = false;
    public bool Compress { get; set; } = false;
    public int CompressionLevel { get; set; } = 0;
    // 非对称曲线：false=X25519，true=X448（非对称封装与 -g 生成密钥对都走该曲线）
    public bool UseX448 { get; set; } = false;
    // 控制台模式：密码由 CLI 在控制台交互读取，不经 stdin 管道
    public bool ConsoleMode { get; set; } = false;
    // 后量子：true=X25519+ML-KEM-768 / ML-DSA-65；false=经典（仅 KeyGen 与水印下发 --no-pqc）
    public bool Pqc { get; set; } = true;
    public bool Watermark { get; set; } = false;
    public string WatermarkKeyPath { get; set; } = "";
    // 水印私钥临时文件（每任务独立，避免并发互相覆盖；任务结束由 CleanupWatermarkTemp 删除）
    public string? WatermarkTempKeyPath { get; set; } = null;
    // ===== 密钥包装（WrapKey / UnwrapKey 动作专用）=====
    // 待包装的 32 字节 DEK 文件（WrapKey）/ 待解开的 .fekw（UnwrapKey）
    public string WrapInput { get; set; } = "";
    // 产物路径：包装为 .fekw、解包为 .dek；留空则由 CLI 按输入文件名推导
    public string WrapOutput { get; set; } = "";
    public WrapAlg WrapAlg { get; set; } = WrapAlg.Kwp;
}
