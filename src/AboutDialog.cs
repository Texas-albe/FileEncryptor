using System;
using System.Drawing;
using System.Windows.Forms;

namespace FileEncryptorGUI
{
    // Startup "about" popup: themed glass card, clickable GitHub/Bilibili links,
    // and a Windows-style 确认 button anchored to the bottom-right corner.
    public class AboutDialog : Form
    {
        private Backdrop _backdrop;
        private Image _bg;
        private GlassPanel _card;
        private Button _confirm;

        public AboutDialog()
        {
            ThemeManager.Load();
            Theme t = ThemeManager.Effective;
            Font = new Font("Segoe UI", 9f);
            FormBorderStyle = FormBorderStyle.FixedSingle;
            MaximizeBox = false;
            MinimizeBox = false;
            ShowInTaskbar = false;
            StartPosition = FormStartPosition.CenterScreen;
            Text = "关于本软件";
            ClientSize = new Size(500, 420);
            DoubleBuffered = true;

            _bg = t.IsDark ? BgLoader.Dark() : BgLoader.Light();
            _backdrop = new Backdrop(Color.FromArgb(20, 22, 30));
            try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }

            BuildUi(t);
        }

        private void BuildUi(Theme t)
        {
            _card = new GlassPanel { Size = new Size(ClientSize.Width - 44, ClientSize.Height - 44), Location = new Point(22, 22) };
            _card.SetGlass(_backdrop, t.ContainerTint, t.ContainerBorder);

            var title = new Label
            {
                Text = "FileEncryptor", Location = new Point(24, 22), Size = new Size(_card.Width - 48, 34),
                Font = new Font("Segoe UI Semibold", 16f), ForeColor = t.Text, BackColor = Color.Transparent
            };
            var thanks = new Label
            {
                Text = "感谢你使用本软件", Location = new Point(24, 74), Size = new Size(_card.Width - 48, 26),
                Font = new Font("Segoe UI Semibold", 13f), ForeColor = t.Text, BackColor = Color.Transparent
            };
            var info = new Label
            {
                Text = "测试人员：瑶璎珞、就不错了我、Twilight飞友\n" +
                       "软件制作：瑶璎珞\n" +
                       "UI制作：Twilight飞友",
                Location = new Point(24, 110), Size = new Size(_card.Width - 48, 78),
                ForeColor = t.TextDim, BackColor = Color.Transparent
            };
            var update = new Label
            {
                Text = "软件新版会在 GitHub 和 Bilibili（由 Twilight飞友发视频）同步更新，视频",
                Location = new Point(24, 196), Size = new Size(_card.Width - 48, 40),
                ForeColor = t.Text, BackColor = Color.Transparent
            };

            var credits = new Label
            {
                Text = "制作人员", AutoSize = true, ForeColor = t.Accent, BackColor = Color.Transparent,
                Font = new Font("Segoe UI", 10.5f, FontStyle.Bold), Cursor = Cursors.Hand
            };
            credits.Location = new Point(24, _card.Height - 24 - 34);
            credits.Click += (s, e) => { try { new CreditsForm { Icon = Icon }.ShowDialog(this); } catch { } };

            _confirm = new Button
            {
                Text = "确认", Anchor = AnchorStyles.Bottom | AnchorStyles.Right,
                FlatStyle = FlatStyle.Flat, BackColor = t.Accent, ForeColor = Color.White,
                Font = new Font("Segoe UI Semibold", 10.5f), Cursor = Cursors.Hand,
                DialogResult = DialogResult.OK
            };
            _confirm.FlatAppearance.BorderSize = 0;
            _confirm.FlatAppearance.MouseOverBackColor = t.AccentHover;
            _confirm.Size = new Size(96, 34);
            _confirm.Location = new Point(_card.Width - 24 - 96, _card.Height - 24 - 34);
            _confirm.Click += (s, e) => Close();

            _card.Controls.Add(title);
            _card.Controls.Add(thanks);
            _card.Controls.Add(info);
            _card.Controls.Add(update);
            _card.Controls.Add(credits);
            _card.Controls.Add(_confirm);

            Controls.Add(_card);
            _card.Radius = 14;
            Ui.RoundedCorners(_confirm, 4);
        }

        protected override void OnPaintBackground(PaintEventArgs e)
        {
            if (_backdrop != null)
            {
                _backdrop.Configure(_bg, ClientSize.Width, ClientSize.Height);
                _backdrop.DrawFull(e.Graphics, new Rectangle(0, 0, ClientSize.Width, ClientSize.Height));
            }
            else base.OnPaintBackground(e);
        }
    }
}
