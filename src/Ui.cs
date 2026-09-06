using System;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace FileEncryptorGUI
{
    internal static class Ui
    {
        // Applies Win11-style subtle rounded corners to a control (clipped via Region).
        public static void RoundedCorners(Control c, int radius)
        {
            void Rebuild()
            {
                int w = c.ClientSize.Width, h = c.ClientSize.Height;
                if (w <= 0 || h <= 0) { c.Region = null; return; }
                int r = Math.Max(1, Math.Min(radius, Math.Min(w, h) / 2));
                if (r < 1) { c.Region = null; return; }
                using (var p = new GraphicsPath())
                {
                    p.AddArc(0, 0, 2 * r, 2 * r, 180, 90);
                    p.AddArc(w - 2 * r, 0, 2 * r, 2 * r, 270, 90);
                    p.AddArc(w - 2 * r, h - 2 * r, 2 * r, 2 * r, 0, 90);
                    p.AddArc(0, h - 2 * r, 2 * r, 2 * r, 90, 90);
                    p.CloseFigure();
                    var old = c.Region;
                    c.Region = new Region(p);
                    old?.Dispose();
                }
            }
            c.SizeChanged += (s, e) => Rebuild();
            c.ParentChanged += (s, e) => Rebuild();
            c.HandleCreated += (s, e) => Rebuild();
            Rebuild();
        }
    }
}
