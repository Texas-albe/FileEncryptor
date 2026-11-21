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

// 密钥包装算法
public enum WrapAlg
{
    Kwp = 0,        // RFC 5649 AES-256-KWP，长度不受
    AesKw = 1,      // RFC 3394 原始 AES-KW，供旧工具互
    Pubkey = 2      // 收件人公钥封装
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

// 分卷单位
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
    // 非对称模式下加
    public CryptoMode FileMode { get; set; } = CryptoMode.XChaCha20;
    public List<string> InputPaths { get; set; } = new();
    public string OutputDir { get; set; } = "";
    // 加密盘
    public string IntoVault { get; set; } = "";
    // 批量过滤
    public List<string> ExcludePatterns { get; set; } = new();
    public bool SkipHidden { get; set; } = false;
    public SourceDisposition SourceDisposition { get; set; } = SourceDisposition.Keep;
    // 加密压缩包
    public bool Pack { get; set; } = false;
    // 分卷
    public bool Split { get; set; } = false;
    public double SplitSize { get; set; } = 100;
    public SplitUnit SplitUnit { get; set; } = SplitUnit.MB;
    // 目录输入 + 删除类
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
    // 非对称曲线
    public bool UseX448 { get; set; } = false;
    // 控制台模式
    public bool ConsoleMode { get; set; } = false;
    // 后量子
    public bool Pqc { get; set; } = true;
    public bool Watermark { get; set; } = false;
    public string WatermarkKeyPath { get; set; } = "";
    // 水印私钥临时文
    public string? WatermarkTempKeyPath { get; set; } = null;
    // 密钥包装
    // 待包装
    public string WrapInput { get; set; } = "";
    // 产物路径
    public string WrapOutput { get; set; } = "";
    public WrapAlg WrapAlg { get; set; } = WrapAlg.Kwp;
}
