using System;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Windows.Forms;

namespace FileEncryptorGUI
{
    internal static class BgLoader
    {
        public static Image Light() => Load("qs");
        public static Image Dark() => Load("ss");

        private static Image Load(string folder)
        {
            try
            {
                var dir = Path.GetDirectoryName(Application.ExecutablePath) ?? AppDomain.CurrentDomain.BaseDirectory;
                var path = Path.Combine(dir, folder);
                if (Directory.Exists(path))
                {
                    var file = Directory.GetFiles(path).FirstOrDefault(f =>
                        f.EndsWith(".png", StringComparison.OrdinalIgnoreCase) ||
                        f.EndsWith(".jpg", StringComparison.OrdinalIgnoreCase) ||
                        f.EndsWith(".jpeg", StringComparison.OrdinalIgnoreCase) ||
                        f.EndsWith(".bmp", StringComparison.OrdinalIgnoreCase));
                    if (file != null) return Image.FromFile(file);
                }
            }
            catch { }
            return null;
        }
    }
}
