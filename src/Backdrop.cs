using System;
using System.Drawing;
using System.Drawing.Drawing2D;

namespace FileEncryptorGUI
{
    // Draws a theme background image as a "cover" fill: scaled uniformly so it
    // completely covers the target with no stretching/distortion and no gaps,
    // anchored to the center. Recomputes on every resize.
    public class Backdrop
    {
        public Image Image;
        public Color Fallback;
        // A client-sized cached render of the cover image; region blits read from
        // this instead of re-scaling the (possibly huge) source image each paint.
        public Image Cache;
        private float _scale = 1f;
        private float _ox, _oy;

        public Backdrop(Color fallback) { Fallback = fallback; }

        public void Configure(Image img, int targetW, int targetH)
        {
            Image = img;
            if (img == null) return;
            if (targetW < 1 || targetH < 1) return;
            float sw = img.Width, sh = img.Height;
            _scale = Math.Max(targetW / sw, targetH / sh);
            _ox = (targetW - sw * _scale) / 2f;
            _oy = (targetH - sh * _scale) / 2f;
        }

        public void DrawFull(Graphics g, Rectangle client)
        {
            if (Image == null)
            {
                using (var b = new SolidBrush(Fallback)) g.FillRectangle(b, client);
                return;
            }
            int dw = (int)Math.Round(Image.Width * _scale);
            int dh = (int)Math.Round(Image.Height * _scale);
            g.DrawImage(Image, (int)_ox, (int)_oy, dw, dh);
        }

        // Draw the slice of the background that lies behind a form-client rectangle
        // (px,py,w,h) onto the graphics origin (0,0), then a translucent tint and a
        // thin border.
        public void DrawRegion(Graphics g, int px, int py, int w, int h, Color tint, Color border)
        {
            if (w <= 0 || h <= 0) return;
            DrawBg(g, px, py, w, h);
            using (var tb = new SolidBrush(tint)) g.FillRectangle(tb, 0, 0, w, h);
            using (var pb = new Pen(border, 1.5f)) g.DrawRectangle(pb, 1, 1, w - 3, h - 3);
        }

        // Same as DrawRegion but the tint and border follow a smooth rounded
        // rectangle, so the card no longer looks "cut" and the border rounds off.
        public void DrawRegionRounded(Graphics g, int px, int py, int w, int h, Color tint, Color border, int radius)
        {
            if (w <= 0 || h <= 0) return;
            DrawBg(g, px, py, w, h);
            int r = Math.Max(1, Math.Min(radius, Math.Min(w, h) / 2));
            using (var path = RoundRect(0.5f, 0.5f, w - 1, h - 1, r))
            {
                using (var tb = new SolidBrush(tint)) g.FillPath(tb, path);
                using (var pb = new Pen(border, 1.5f)) g.DrawPath(pb, path);
            }
        }

        private void DrawBg(Graphics g, int px, int py, int w, int h)
        {
            if (Cache != null && Cache.Width > 0)
            {
                int sx = Math.Max(0, px), sy = Math.Max(0, py);
                int sw = Math.Min(Cache.Width - sx, w), sh = Math.Min(Cache.Height - sy, h);
                if (sw > 0 && sh > 0)
                    g.DrawImage(Cache, new Rectangle(0, 0, sw, sh),
                        new Rectangle(sx, sy, sw, sh), GraphicsUnit.Pixel);
            }
            else if (Image == null) { }
            else
            {
                float sx = (px - _ox) / _scale;
                float sy = (py - _oy) / _scale;
                float sw = w / _scale;
                float sh = h / _scale;
                g.DrawImage(Image, new Rectangle(0, 0, w, h),
                    new RectangleF(sx, sy, sw, sh), GraphicsUnit.Pixel);
            }
        }

        private static GraphicsPath RoundRect(float x, float y, float w, float h, int r)
        {
            var p = new GraphicsPath();
            p.AddArc(x, y, r * 2, r * 2, 180, 90);
            p.AddArc(x + w - r * 2, y, r * 2, r * 2, 270, 90);
            p.AddArc(x + w - r * 2, y + h - r * 2, r * 2, r * 2, 0, 90);
            p.AddArc(x, y + h - r * 2, r * 2, r * 2, 90, 90);
            p.CloseFigure();
            return p;
        }
    }
}
