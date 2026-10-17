using System.IO;
using System.Text.Json;

namespace FileEncryptorGUI.Services;

public enum BackgroundMode
{
    // 元素级 Mica：RootGrid 铺 MicaBrush，tint 完全可控
    FullAcrylic = 0,
    // 系统 Mica（DWM DWMSBT_MAIN）：最通透，但 tint 跟随**系统**深浅不可控
    SystemAcrylic = 1,
    // 不用任何模糊，纯染色底
    Flat = 2
}

public enum AppTheme
{
    Light = 0,
    Dark = 1,
    System = 2
}

// 已挂载的加密盘记录：用于「已挂载加密盘」列表与双击解锁
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
    // 加密盘：上次用的盘目录与盘符，菜单里默认就是它
    public string? LastVaultDir { get; set; }
    public string? LastMountPoint { get; set; }
    // 已挂载加密盘列表（盘符/目录 + 盘存储目录），供程序内列表与双击解锁
    public List<MountedVault> MountedVaults { get; set; } = new();
    public int WindowWidth { get; set; } = 1100;
    public int WindowHeight { get; set; } = 720;
    // 界面语言："zh" | "en"
    public string? Language { get; set; } = "";
    // M18 隐私：任务历史是否持久化完整路径。默认 false（隐私优先）——tasks.log
    // 只记录文件名，不把「用户保护了哪些文件」明文留在磁盘上。
    // 置 true 才写入完整 inputPaths / outputDir，从而保留「双击回放任务」能力。
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
            File.WriteAllText(ConfigPath, json);
        }
        catch {  }
    }
}
