using System.IO;
using System.Text.Json;

namespace FileEncryptorGUI.Services;

public enum BackgroundMode
{
    FullAcrylic = 0,
    MicaMainAcrylicControls = 1
}

public enum AppTheme
{
    Light = 0,
    Dark = 1,
    System = 2
}

public class AppSettings
{
    public bool FirstLaunchDone { get; set; }
    public BackgroundMode BackgroundMode { get; set; } = BackgroundMode.FullAcrylic;
    public AppTheme Theme { get; set; } = AppTheme.Dark;
    public string? CustomBackgroundPath { get; set; }
    public string? LastOutputDir { get; set; }
    public string? LastCliPath { get; set; }
    public int WindowWidth { get; set; } = 1100;
    public int WindowHeight { get; set; } = 720;
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
        catch { /* 损坏配置回退默认 */ }
    }

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(ConfigDir);
            var json = JsonSerializer.Serialize(Current, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(ConfigPath, json);
        }
        catch { /* 保存失败不阻塞 */ }
    }
}
