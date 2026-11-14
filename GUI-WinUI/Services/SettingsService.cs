using System.IO;
using System.Text.Json;

namespace FileEncryptorGUI.Services;

public enum BackgroundMode
{
    // 元素级 Mica
    FullAcrylic = 0,
    // 系统 Mica
    SystemAcrylic = 1,
    // 不用任何模糊
    Flat = 2
}

public enum AppTheme
{
    Light = 0,
    Dark = 1,
    System = 2
}

// 已挂载
public class MountedVault
{
    public string VaultDir { get; set; } = "";
    public string MountPoint { get; set; } = "";
}

public class AppSettings
{
    public bool FirstLaunchDone { get; set; }
    public BackgroundMode BackgroundMode { get; set; } = BackgroundMode.FullAcrylic;
    public AppTheme Theme { get; set; } = AppTheme.Dark;
    public string? CustomBackgroundPath { get; set; }
    public string? LastOutputDir { get; set; }
    public string? LastCliPath { get; set; }
    // 加密盘
    public string? LastVaultDir { get; set; }
    public string? LastMountPoint { get; set; }
    // 已挂载加密盘列
    public List<MountedVault> MountedVaults { get; set; } = new();
    public int WindowWidth { get; set; } = 1100;
    public int WindowHeight { get; set; } = 720;
    // 界面语言
    public string? Language { get; set; } = "";
    // M18 隐私
    // 只记录文件名
    // 置 true 才写入完整
    public bool HistoryStorePaths { get; set; } = false;
}

public class SettingsService
{
    private static readonly string ConfigDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "FileEncryptor", "GUI");
    private static readonly string ConfigPath = Path.Combine(ConfigDir, "settings.json");

    public AppSettings Current { get; private set; } = new();

    public SettingsService()
    {
        Load();
    }

    public void Load()
    {
        try
        {
            if (File.Exists(ConfigPath))
            {
                var json = File.ReadAllText(ConfigPath);
                var s = JsonSerializer.Deserialize<AppSettings>(json);
                if (s != null) Current = s;
            }
        }
        catch {  }
    }

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(ConfigDir);
            var json = JsonSerializer.Serialize(Current, new JsonSerializerOptions { WriteIndented = true });
            // 原子写
            var tmp = ConfigPath + ".tmp";
            File.WriteAllText(tmp, json);
            File.Move(tmp, ConfigPath, overwrite: true);
        }
        catch {  }
    }
}
