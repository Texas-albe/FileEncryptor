using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace FileEncryptorGUI
{
    // A thin, Explorer-style determinate progress bar: a light rounded track,
    // a green fill, and a small highlight that glides left→right while running.
    public class ModernProgressBar : Control
    {
        private int _value;
        private bool _running;
        private int _glow = -40;

        private readonly System.Windows.Forms.Timer _timer;

        public int Value
        {
            get => _value;
            set { _value = Math.Max(0, Math.Min(100, value)); Invalidate(); }
        }

        public bool Running
        {
            get => _running;
            set
            {
                if (_running == value) return;
                _running = value;
                if (_running) { _glow = -50; _timer.Start(); }
                else _timer.Stop();
                Invalidate();
            }
        }

        public Theme Theme { get; set; } = Theme.Light;

        public ModernProgressBar()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint |
                     ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            Height = 14;
            _timer = new System.Windows.Forms.Timer { Interval = 25 };
            _timer.Tick += (s, e) => { _glow += 6; if (_glow > Width + 30) _glow = -50; Invalidate(); };
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;

            int h = Math.Max(6, Height - 2);
            var rect = new Rectangle(1, (Height - h) / 2, Width - 2, h);
            int radius = h / 2;

            // Track (light rounded bar)
            using (var track = new SolidBrush(Theme.IsDark ? Color.FromArgb(58, 64, 76) : Color.FromArgb(225, 229, 236)))
                FillRounded(g, track, rect, radius);

            // Fill (green)
            if (_value <= 0) return;
            int fillW = (int)(rect.Width * (_value / 100.0));
            if (fillW <= 0) return;
            var fillRect = new Rectangle(rect.X, rect.Y, Math.Max(fillW, radius * 2), rect.Height);
            using (var fill = new SolidBrush(Green))
                FillRounded(g, fill, fillRect, radius);

            // Animated highlight gliding within the fill (Explorer-style sheen)
            if (_running)
            {
                int glowW = Math.Min(46, fillRect.Width);
                if (glowW > 4 && _glow > rect.X && _glow < fillRect.Right)
                {
                    int x = _glow;
                    var gx = Math.Max(rect.X, x);
                    var gw = Math.Min(glowW, fillRect.Right - gx);
                    if (gw > 2)
                    {
                        var glowRect = new Rectangle(gx, fillRect.Y + 2, gw, fillRect.Height - 4);
                        using (var gb = new SolidBrush(Color.FromArgb(120, 255, 255, 255)))
                        {
                            var old = g.Clip;
                            using (var cp = new GraphicsPath())
                            {
                                AddRounded(cp, fillRect, radius);
                                g.SetClip(cp);
                                g.FillRectangle(gb, glowRect);
                                g.Clip = old;
                            }
                        }
                    }
                }
            }
        }

        private static readonly Color Green = Color.FromArgb(76, 175, 80); // #4CAF50

        private static void FillRounded(Graphics g, Brush b, Rectangle r, int radius)
        {
            using (var p = new GraphicsPath()) { AddRounded(p, r, radius); g.FillPath(b, p); }
        }

        private static void AddRounded(GraphicsPath p, Rectangle r, int radius)
        {
            int d = radius * 2;
            if (d > r.Width) d = r.Width;
            if (d > r.Height) d = r.Height;
            p.AddArc(r.X, r.Y, d, d, 180, 90);
            p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
            p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
            p.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
            p.CloseFigure();
        }
    }
}
