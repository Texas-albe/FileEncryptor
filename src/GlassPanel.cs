using System;
using System.Drawing;
using System.Windows.Forms;

namespace FileEncryptorGUI
{
    // A translucent, square-cornered card that shows the theme background image
    // behind itself plus a tint and a thin border. It paints in OnPaintBackground
    // so that transparent child labels/controls blend against it.
    public class GlassPanel : Panel
    {
        public Backdrop Back;
        public Color Tint = Color.Empty;
        public Color BorderColor = Color.Empty;
        public int Radius = 0;

        public GlassPanel()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint |
                     ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            BackColor = Color.FromArgb(40, 20, 22, 30);
        }

        public void SetGlass(Backdrop back, Color tint, Color border)
        {
            Back = back; Tint = tint; BorderColor = border;
            Invalidate();
        }

        protected override void OnPaintBackground(PaintEventArgs e)
        {
            if (Back != null)
            {
                var o = ClientOriginInForm();
                if (Radius > 0)
                    Back.DrawRegionRounded(e.Graphics, o.X, o.Y, Width, Height,
                        Tint == Color.Empty ? Color.FromArgb(120, 20, 22, 30) : Tint,
                        BorderColor == Color.Empty ? Color.FromArgb(150, 255, 255, 255) : BorderColor,
                        Radius);
                else
                    Back.DrawRegion(e.Graphics, o.X, o.Y, Width, Height,
                        Tint == Color.Empty ? Color.FromArgb(120, 20, 22, 30) : Tint,
                        BorderColor == Color.Empty ? Color.FromArgb(150, 255, 255, 255) : BorderColor);
            }
            else
            {
                e.Graphics.Clear(Color.FromArgb(40, 20, 22, 30));
            }
        }

        private Point ClientOriginInForm()
        {
            var f = FindForm();
            if (f == null) return new Point(Left, Top);
            return f.PointToClient(PointToScreen(new Point(0, 0)));
        }
    }
}
