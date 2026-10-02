namespace FileEncryptorGUI.Models;

public enum CryptoAction
{
    Encrypt,
    Decrypt,
    BatchEncrypt,
    BatchDecrypt,
    KeyGen,
    Derive,
    PubKey
}

public enum CryptoMode
{
    XChaCha20,
    Aegis256,
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

public class ShellOptions
{
    public CryptoAction Action { get; set; } = CryptoAction.Encrypt;
    public CryptoMode Mode { get; set; } = CryptoMode.XChaCha20;
    // 非对称模式下加密文件载荷的对称算法（会话密钥由它产生，非对称只包裹该密钥）
    public CryptoMode FileMode { get; set; } = CryptoMode.XChaCha20;
    public List<string> InputPaths { get; set; } = new();
    public string OutputDir { get; set; } = "";
    public SourceDisposition SourceDisposition { get; set; } = SourceDisposition.Keep;
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
    // 控制台模式：口令由 CLI 在控制台交互读取，不经 stdin 管道
    public bool ConsoleMode { get; set; } = false;
    // 后量子：true=X25519+ML-KEM-768 / ML-DSA-65；false=经典（仅在 KeyGen、水印处下发 --no-pqc）
    public bool Pqc { get; set; } = true;
    public bool Watermark { get; set; } = false;
    public string WatermarkKeyPath { get; set; } = "";
}
