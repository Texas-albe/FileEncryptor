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
}
