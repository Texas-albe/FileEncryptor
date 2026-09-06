using System;
using System.Drawing;
using System.IO;
using System.Text.Json;
using Microsoft.Win32;

namespace FileEncryptorGUI
{
    public class Theme
    {
        public Color Window;
        public Color Card;
        public Color Border;
        public Color Text;
        public Color TextDim;
        public Color HeaderBg;
        public Color HeaderText;
        public Color Accent;
        public Color AccentHover;
        public Color LogBg;
        public Color LogText;
        public bool IsDark;

        // Translucent "glass" card colors + field colors
        public Color ContainerTint;
        public Color ContainerBorder;
        public Color BoxTint;
        public Color BoxBorder;
        public Color FieldBg;
        public Color FieldText;
        public Color FieldBorder;
        public Color ControlBack;

        public static Theme Light => new Theme
        {
            IsDark = false,
            Window = FromHex("#F5F7FB"),
            Card = FromHex("#FFFFFF"),
            Border = FromHex("#E3E7EF"),
            Text = FromHex("#1E222B"),
            TextDim = FromHex("#5A6270"),
            HeaderBg = FromHex("#263256"),
            HeaderText = FromHex("#FFFFFF"),
            Accent = FromHex("#4F7AD6"),
            AccentHover = FromHex("#628BE3"),
            LogBg = FromHex("#1E2230"),
            LogText = FromHex("#D2D8E6"),
            ContainerTint = Color.FromArgb(165, 250, 252, 255),
            ContainerBorder = Color.FromArgb(190, 30, 34, 42),
            BoxTint = Color.FromArgb(150, 255, 255, 255),
            BoxBorder = Color.FromArgb(150, 44, 48, 56),
            FieldBg = Color.FromArgb(255, 238, 242, 248),
            FieldText = FromHex("#20242E"),
            FieldBorder = Color.FromArgb(200, 60, 64, 72),
            ControlBack = Color.FromArgb(255, 247, 250, 253)
        };

        public static Theme Dark => new Theme
        {
            IsDark = true,
            Window = FromHex("#1D2127"),
            Card = FromHex("#2A2F38"),
            Border = FromHex("#3A404C"),
            Text = FromHex("#EAEDF4"),
            TextDim = FromHex("#AEB6C4"),
            HeaderBg = FromHex("#16191F"),
            HeaderText = FromHex("#FFFFFF"),
            Accent = FromHex("#5B8DEF"),
            AccentHover = FromHex("#74A1F0"),
            LogBg = FromHex("#12151A"),
            LogText = FromHex("#CDD4E0"),
            ContainerTint = Color.FromArgb(175, 22, 25, 34),
            ContainerBorder = Color.FromArgb(180, 255, 255, 255),
            BoxTint = Color.FromArgb(150, 38, 41, 51),
            BoxBorder = Color.FromArgb(140, 255, 255, 255),
            FieldBg = Color.FromArgb(255, 26, 30, 41),
            FieldText = FromHex("#E8EBF2"),
            FieldBorder = Color.FromArgb(180, 255, 255, 255),
            ControlBack = Color.FromArgb(255, 36, 39, 49)
        };

        public static Color FromHex(string hex)
        {
            hex = hex.TrimStart('#');
            return Color.FromArgb(
                Convert.ToInt32(hex.Substring(0, 2), 16),
                Convert.ToInt32(hex.Substring(2, 2), 16),
                Convert.ToInt32(hex.Substring(4, 2), 16));
        }
    }

    public enum ThemeMode
    {
        Auto = 0,
        Light = 1,
        Dark = 2
    }

    public static class ThemeManager
    {
        public static ThemeMode Mode = ThemeMode.Auto;

        public static bool SystemPrefersLight()
        {
            try
            {
                var v = Registry.GetValue(
                    @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
                    "AppsUseLightTheme", 1);
                int iv = v is int i ? i : 1;
                return iv != 0;
            }
            catch { return true; }
        }

        public static Theme Effective
        {
            get
            {
                if (Mode == ThemeMode.Light) return Theme.Light;
                if (Mode == ThemeMode.Dark) return Theme.Dark;
                return SystemPrefersLight() ? Theme.Light : Theme.Dark;
            }
        }

        public static void Load()
        {
            try
            {
                var path = SettingsPath();
                if (File.Exists(path))
                {
                    var json = File.ReadAllText(path);
                    var d = JsonSerializer.Deserialize<JsonElement>(json);
                    if (d.TryGetProperty("theme", out var th) && th.ValueKind == JsonValueKind.Number)
                        Mode = (ThemeMode)th.GetInt32();
                }
            }
            catch { /* ignore, default auto */ }
        }

        public static void Save()
        {
            try
            {
                var path = SettingsPath();
                Directory.CreateDirectory(Path.GetDirectoryName(path));
                File.WriteAllText(path, JsonSerializer.Serialize(new { theme = (int)Mode }));
            }
            catch { /* non fatal */ }
        }

        private static string SettingsPath()
        {
            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "FileEncryptorGUI", "settings.json");
        }
    }
}
