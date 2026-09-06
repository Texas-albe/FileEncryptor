using System;
using System.Diagnostics;
using System.Drawing;
using System.Windows.Forms;

namespace FileEncryptorGUI
{
    // Credits popup: a lightweight browser window that renders the embedded
    // "制作人员" HTML (self-contained, no external file needed) with the
    // clickable Bilibili / GitHub links of each contributor.
    public class CreditsForm : Form
    {
        private const string CreditsHtml = @"
<!DOCTYPE html>
<html lang='zh-CN'>
<head>
<meta charset='UTF-8'>
<style>
  html,body{margin:0;padding:0;font-family:'Segoe UI','Microsoft YaHei',sans-serif;color:#2c3e5a;background:#f5f7fc;}
  .wrap{max-width:560px;margin:0 auto;padding:36px 28px;}
  h1{margin:0 0 6px;font-size:26px;font-weight:600;color:#1e3c72;letter-spacing:-.02em;}
  .sub{margin:0 0 22px;font-size:14px;color:#60718b;}
  .row{display:flex;flex-wrap:wrap;align-items:center;gap:8px 14px;padding:12px 0;border-bottom:1px solid rgba(60,80,120,.12);}
  .row:last-child{border-bottom:none;}
  .name{font-weight:600;font-size:16px;min-width:110px;color:#0b1b33;}
  a{color:#1a5cbf;text-decoration:none;font-size:14px;font-weight:500;}
  a:hover{text-decoration:underline;}
  .sep{color:#a0b3ce;}
  .tag{display:inline-block;margin-left:6px;padding:2px 10px;border-radius:20px;background:#eef2f9;color:#2f4468;font-size:12px;}
  @media (prefers-color-scheme:dark){
    html,body{background:#10131f;color:#b8cbe0;}
    h1{color:#8bb4ff;} .sub{color:#8899b5;}
    .row{border-bottom-color:rgba(180,200,240,.12);}
    .name{color:#eef3fc;} a{color:#7aa9ff;}
    .sep{color:#637699;} .tag{background:#2f3852;color:#c6d6f0;}
  }
</style>
</head>
<body>
<div class='wrap'>
  <h1>FileEncryptor</h1>
  <p class='sub'>感谢你使用本软件 <span class='tag'>制作人员</span></p>
  <div class='row'><span class='name'>就不错了我</span>
    <a href='https://b23.tv/xmwvkq8'>Bilibili</a></div>
  <div class='row'><span class='name'>瑶璎珞</span>
    <a href='https://b23.tv/hZuxitJ'>Bilibili</a><span class='sep'>·</span>
    <a href='https://github.com/Texas-albe/FileEncryptor'>GitHub</a></div>
  <div class='row'><span class='name'>Twilight飞友</span>
    <a href='https://b23.tv/tUHONsK'>Bilibili</a><span class='sep'>·</span>
    <a href='https://github.com/TwilightFY801/FileEncryptor-UI'>GitHub</a></div>
</div>
</body>
</html>";

        private WebBrowser _web;

        public CreditsForm()
        {
            Text = "制作人员";
            ClientSize = new Size(640, 520);
            StartPosition = FormStartPosition.CenterScreen;
            ShowInTaskbar = false;
            MaximizeBox = false;
            MinimizeBox = false;

            _web = new WebBrowser { Dock = DockStyle.Fill, ScriptErrorsSuppressed = true };
            // Open any external link in the default browser instead of inside this control.
            _web.Navigating += (s, e) =>
            {
                var url = e.Url?.AbsoluteUri ?? string.Empty;
                if (!url.StartsWith("about:blank", StringComparison.OrdinalIgnoreCase))
                {
                    e.Cancel = true;
                    try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); } catch { }
                }
            };
            Controls.Add(_web);
            _web.DocumentText = CreditsHtml;
        }
    }
}
