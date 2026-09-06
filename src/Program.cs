using System;
using System.IO;
using System.Windows.Forms;

namespace FileEncryptorGUI
{
    internal static class Program
    {
        [STAThread]
        private static void Main()
        {
            Application.ThreadException += (s, e) => Dump(e.Exception);
            AppDomain.CurrentDomain.UnhandledException += (s, e) => Dump(e.ExceptionObject as Exception);
            Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);

            ApplicationConfiguration.Initialize();
            // Show the about/splash popup first; after confirm the main window appears.
            using (var about = new AboutDialog())
                about.ShowDialog();
            Application.Run(new MainForm());
        }

        private static void Dump(Exception ex)
        {
            try { File.WriteAllText(Path.Combine(Path.GetTempPath(), "fe_crash.log"),
                ex == null ? "null" : ex.ToString()); } catch { }
        }
    }
}
