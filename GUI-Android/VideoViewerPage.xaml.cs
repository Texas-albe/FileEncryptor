// 库内视频播放页
// 视频主体不落盘
// 只有同名外挂字
using FileEncryptorMobile.Platforms.Android;
using FileEncryptorMobile.Services;
using Microsoft.Maui.ApplicationModel;

namespace FileEncryptorMobile;

public sealed class VideoViewerPage : ContentPage
{
    private static VideoViewerPage? s_current;

    // _path 是虚拟明文路径
    private string _path;
    private string _title;
    private readonly string _tempDir;
    private readonly VaultService _vault;
    private string _rel;
    // 同目录视频列表
    private List<VaultItem> _siblings = new();
    private int _sibIndex = -1;
    private bool _switching;
    // 重进时字幕目录
    private readonly Func<Task>? _reexport;
    private bool _closed;
    private bool _tempCleaned;
    private bool _opened;
    private bool _failed;
    private bool _backgroundClose;   // 本次关闭源于退
    private bool _musicWasPlaying;   // 进入本页前音乐
    private bool _musicHandled;
    private bool _streamEntered;     // 本页是否已关掉
    // 压缩档边导边播
    private long _exported;          // Interlocked 读写
    private Task<bool>? _exportTask;
    private int _exportGen;          // 导出
    private int _lastPct = -1;

    public VideoViewerPage(string path, string title, string tempDir,
        VaultService vault, string rel, Func<Task>? reexport = null)
    {
        _path = path;
        _title = title;
        _tempDir = tempDir;
        _vault = vault;
        _rel = rel;
        _reexport = reexport;
        BackgroundColor = Colors.Black;
        NavigationPage.SetHasNavigationBar(this, false);
        Microsoft.Maui.Controls.Shell.SetNavBarIsVisible(this, false);
        Microsoft.Maui.Controls.Shell.SetTabBarIsVisible(this, false);
        Content = new Grid { BackgroundColor = Colors.Black };
    }

    protected override void OnAppearing()
    {
        base.OnAppearing();
        s_current = this;
        Microsoft.Maui.Controls.Shell.SetNavBarIsVisible(this, false);
        Microsoft.Maui.Controls.Shell.SetTabBarIsVisible(this, false);
        if (_opened || _closed) return;   // 重复 OnAppearing 不重开播放
        _opened = true;
        // 视频优先
        _musicWasPlaying = MusicPlayerHost.PauseForVideo();
        _ = OpenAsync();
    }

    private async Task OpenAsync()
    {
        try
        {
            // 只有字幕落盘
            string? subDir = Path.GetDirectoryName(_path);
            if (subDir is not null && !Directory.Exists(subDir) && _reexport is not null)
            {
                try { await _reexport(); }
                catch (Exception ex) { MainApplication.LogCaught("video-subtitle-reexport", ex); }
            }
            if (_closed) return;
            var act = Platform.CurrentActivity;
            if (act is null)
            {
                ShowFailure(L10n.T("播放窗口不可用，请返回后重试。"));
                return;
            }
            BuildSiblings();
            await OpenCoreAsync(act);
        }
        catch (Exception ex)
        {
            LeaveStream();
            MainApplication.LogCaught("videopage-open", ex);
            ShowFailure(L10n.T("无法播放此视频，请返回后重试。"));
        }
    }
    // 同目录视频列表
    private void BuildSiblings()
    {
        try
        {
            int slash = _rel.LastIndexOf('/');
            string parent = slash > 0 ? _rel.Substring(0, slash) : "";
            var all = _vault.ListDir(parent);
            _siblings = all.Where(i => !i.IsDir && VaultItem.IsVideoName(i.Name)).ToList();
            _sibIndex = _siblings.FindIndex(i => i.RelPath == _rel);
        }
        catch (Exception ex)
        {
            MainApplication.LogCaught("video-siblings", ex);
            _siblings = new List<VaultItem>();
            _sibIndex = -1;
        }
    }
    // 按当前 _path/_rel/_title 起播
    private async Task OpenCoreAsync(global::Android.App.Activity act)
    {
        MainApplication.LogNote("video-pre", "enter");
        // 视频统一边导边
        // 顺序导出临时明
        string playPath = _path;
        global::Android.Media.MediaDataSource? stream = null;
        Task<bool>? gate = null;
        string? tailPath = null;
        long tailLen = 0;
        int pfMs = -1;
        playPath = Path.Combine(_tempDir, Path.GetFileName(_path));
        long total = 0;
        try { if (_vault.TryGetAttr(_rel, out ulong sz, out bool isDir2) && !isDir2) total = (long)sz; }
        catch { }
        MainApplication.LogNote("video-pre", $"total={total}");
        if (total <= 0)
        {
            // 大小未知退回
            MainApplication.LogNote("video-pre", "gate");
            _exportGen++;
            gate = Task.Run(() => ExportPlainToFile(playPath, _exportGen));
        }
        else
        {
            // 空间预检
            bool spaceOk = true;
            try
            {
                spaceOk = await Task.Run(() =>
                {
                    var stf = new global::Android.OS.StatFs(_tempDir);
                    return stf.AvailableBytes > total + (64L << 20);
                });
            }
            catch { spaceOk = true; }
            MainApplication.LogNote("video-pre", $"space={spaceOk}");
            if (spaceOk)
            {
                _exportGen++;
                _lastPct = -1;
                int eg = _exportGen;
                _exportTask = Task.Run(() => ExportPlainToFile(playPath, eg));
                // 尾部预填
                try
                {
                    tailLen = System.Math.Min(total, 8L * 1024 * 1024);
                    if (tailLen > 0)
                    {
                        tailPath = playPath + ".tail";
                        var pf0 = DateTime.UtcNow;
                        var pfTask = Task.Run(() => PrefillTail(tailPath!, tailLen, total));
                        var fin = await Task.WhenAny(pfTask, Task.Delay(8000));
                        if (fin == pfTask)
                        {
                            pfMs = (int)(DateTime.UtcNow - pf0).TotalMilliseconds;
                            if (new FileInfo(tailPath).Length != tailLen) { tailPath = null; tailLen = 0; }
                        }
                        else
                        {
                            pfMs = -2;               // 超时放弃
                            tailPath = null; tailLen = 0;
                        }
                    }
                }
                catch { tailPath = null; tailLen = 0; }
                MainApplication.LogNote("video-pre", $"tail={tailLen} pf={pfMs}");
                try
                {
                    stream = new GrowingFileDataSource(playPath, total,
                        () => System.Threading.Interlocked.Read(ref _exported), _exportTask, tailPath, tailLen);
                }
                catch (Exception ex)
                {
                    // 导出目标缺失
                    MainApplication.LogCaught("video-grow-open", ex);
                    _exportGen++;                    // 作废
                    stream = new VaultMediaDataSource(_vault, _rel);
                }
            }
            else
            {
                stream = new VaultMediaDataSource(_vault, _rel);
            }
        }
        bool ok = VideoPlayerHost.Open(act, playPath, _title,
            () => _ = ExitWithUiAsync(), OnPlaybackEnded, ShowFailure, stream, gate);
        if (!ok) LeaveStream();
        MainApplication.LogNote("video-open",
            $"started={ok} grow={stream is GrowingFileDataSource} gate={gate is not null} total={total} tail={tailLen} pf={pfMs}");
        if (ok)
            VideoPlayerHost.SetNavHandlers(
                _sibIndex > 0 ? () => _ = SwitchAsync(-1) : null,
                _sibIndex >= 0 && _sibIndex < _siblings.Count - 1 ? () => _ = SwitchAsync(+1) : null);
    }
    // 上一个/下一
    private async Task SwitchAsync(int delta)
    {
        if (_switching || _closed) return;
        int idx = _sibIndex + delta;
        if (_sibIndex < 0 || idx < 0 || idx >= _siblings.Count) return;
        _switching = true;
        try
        {
            var item = _siblings[idx];
            VideoPlayerHost.Close();
            LeaveStream();
            // 旧文件
            try { Directory.Delete(_tempDir, true); } catch { }
            Directory.CreateDirectory(_tempDir);
            _path = Path.Combine(_tempDir, item.Name);
            _title = item.Name;
            _rel = item.RelPath;
            _sibIndex = idx;
            await ExportSubtitleForCurrentAsync();
            if (_closed) return;
            var act = Platform.CurrentActivity;
            if (act is null) { ShowFailure(L10n.T("播放窗口不可用，请返回后重试。")); return; }
            await OpenCoreAsync(act);
        }
        catch (Exception ex)
        {
            LeaveStream();
            MainApplication.LogCaught("video-switch", ex);
            ShowFailure(L10n.T("无法播放此视频，请返回后重试。"));
        }
        finally { _switching = false; }
    }
    // 当前视频
    private async Task ExportSubtitleForCurrentAsync()
    {
        try
        {
            string rel = _rel;
            string name = Path.GetFileName(_path);
            string dir = _tempDir;
            await Task.Run(() =>
            {
                string baseName = Path.GetFileNameWithoutExtension(name);
                int slash = rel.LastIndexOf('/');
                string parent = slash > 0 ? rel.Substring(0, slash) : "";
                var siblings = _vault.ListDir(parent);
                string? srt = null, ass = null;
                foreach (var s in siblings)
                {
                    if (s.IsDir) continue;
                    if (!string.Equals(Path.GetFileNameWithoutExtension(s.Name), baseName,
                        StringComparison.OrdinalIgnoreCase)) continue;
                    string e = Path.GetExtension(s.Name);
                    if (e.Equals(".srt", StringComparison.OrdinalIgnoreCase)) srt = s.RelPath;
                    else if (e.Equals(".ass", StringComparison.OrdinalIgnoreCase)) ass = s.RelPath;
                }
                string? pick = srt ?? ass;
                if (pick is null) return;
                string dest = Path.Combine(dir, Path.GetFileName(pick));
                int fd = LibcNative.open(dest,
                    LibcNative.O_WRONLY | LibcNative.O_CREAT | LibcNative.O_TRUNC, 0x180);
                if (fd < 0) return;
                try { _vault.ExportFd(pick, fd, null); }
                finally { LibcNative.close(fd); }
            });
        }
        catch (Exception ex) { MainApplication.LogCaught("video-subtitle-switch", ex); }
    }

    // 压缩档后台流式
    // gen 为导出
    // 尾部预填
    private void PrefillTail(string tailPath, long tailLen, long total)
    {
        using var fs = new FileStream(tailPath, FileMode.Create, FileAccess.Write, FileShare.Read);
        byte[] buf = new byte[1024 * 1024];
        long pos = total - tailLen;
        long done = 0;
        while (done < tailLen)
        {
            int n = (int)System.Math.Min(buf.Length, tailLen - done);
            int r = _vault.ReadRangeTo(_rel, (ulong)(pos + done), buf, 0, n);
            if (r <= 0) throw new IOException("tail read");
            fs.Write(buf, 0, r);
            done += r;
        }
    }

    private bool ExportPlainToFile(string target, int gen)
    {
        try
        {
            int fd = LibcNative.open(target,
                LibcNative.O_WRONLY | LibcNative.O_CREAT | LibcNative.O_TRUNC, 0x180);
            if (fd < 0) return false;
            try
            {
            var start = DateTime.UtcNow;
            ulong winBytes = 0;
            double winT = 0;
            _vault.ExportFd(_rel, fd, (done, total) =>
            {
                if (gen != _exportGen) return;   // 旧会话作废
                System.Threading.Interlocked.Exchange(ref _exported, (long)done);
                if (total <= 0) return;
                int pct = (int)(done * 100 / total);
                if (pct == 0 || pct >= _lastPct + 10)   // 稀疏打点带速率
                {
                    _lastPct = pct;
                    double now = (DateTime.UtcNow - start).TotalSeconds;
                    double dt = now - winT;
                    double mbps = dt > 0.05 ? (done - winBytes) / 1048576.0 / dt : 0;
                    winT = now;
                    winBytes = done;
                    MainApplication.LogD(MainApplication.TagVideo, $"export {pct}% {mbps:F1}MB/s");
                }
            });
            }
            finally { LibcNative.close(fd); }
            if (File.Exists(target) && new FileInfo(target).Length > 0) return true;
            try { File.Delete(target); } catch { }
            return false;
        }
        catch (Exception ex)
        {
            MainApplication.LogCaught("video-plain-export", ex);
            try { File.Delete(target); } catch { }
            return false;
        }
    }

    // 可读提示替代闪
    private void ShowFailure(string text)
    {
        if (_failed) return;
        _failed = true;
        MainThread.BeginInvokeOnMainThread(async () =>
        {
            try { await DisplayAlertAsync(L10n.T("无法播放"), text, L10n.T("返回")); } catch { }
            if (!_closed) await ExitWithUiAsync();
        });
    }

    protected override void OnDisappearing()
    {
        base.OnDisappearing();
        if (s_current == this) s_current = null;
        ClosePlayer();
    }

    public bool IsClosed => _closed;

    // PiP 入口判断
    public static bool IsVideoOpen
    {
        get
        {
            var p = s_current;
            return p is not null && !p._closed && !p._failed;
        }
    }

    // 返回键 / 顶部返回
    public async Task ExitWithUiAsync()
    {
        if (_closed) return;
        _closed = true;
        ClosePlayer();
        try { await Navigation.PopAsync(false); } catch { }
    }

    // 退后台
    public static void CloseIfOpen()
    {
        var page = s_current;
        if (page is null) return;
        page._backgroundClose = true;
        page.CloseNow();
    }

    private void CloseNow()
    {
        if (_closed) return;
        _closed = true;
        MainApplication.LogD(MainApplication.TagVideo, L10n.T("close: background (停播→清明文)"));
        ClosePlayer();
        MainThread.BeginInvokeOnMainThread(async () =>
        {
            try { await Navigation.PopAsync(false); } catch { }
        });
    }

    private void ClosePlayer()
    {
        // 关闭或锁库路径
        MainActivity.ExitPictureInPicture();
        // 顺序固定
        VideoPlayerHost.Close();
        LeaveStream();
        CleanupTemp();
        RestoreMusic();
    }

    private void LeaveStream()
    {
        if (!_streamEntered) return;
        _streamEntered = false;
        try { _vault.LeaveStreamMode(); }
        catch (Exception ex) { MainApplication.LogCaught("video-stream-leave", ex); }
    }

    // 离开页面才清
    private void CleanupTemp()
    {
        if (_tempCleaned) return;
        _tempCleaned = true;
        try
        {
            if (string.IsNullOrEmpty(_tempDir)) return;
            Directory.Delete(_tempDir, true);
            MainApplication.LogD(MainApplication.TagVideo, L10n.T("cleanup: 字幕明文已删除"));
        }
        catch (Exception ex)
        {
            MainApplication.LogW(MainApplication.TagVideo,
                L10n.F("cleanup: 删除字幕明文失败 {0}: {1}", ex.GetType().Name, ex.Message));
        }
    }

    private void OnPlaybackEnded()
    {
        // 结束态不清理字
        MainApplication.LogD(MainApplication.TagVideo, L10n.T("playback: ended (保留字幕明文)"));
    }

    // 退出页面时恢复
    private void RestoreMusic()
    {
        if (_musicHandled) return;
        _musicHandled = true;
        MainApplication.LogD(MainApplication.TagVideo,
            $"close: restoreMusic wasPlaying={_musicWasPlaying} bgClose={_backgroundClose} inBackground={MainActivity.AppInBackground}");
        if (!_musicWasPlaying || _backgroundClose || MainActivity.AppInBackground) return;
        MusicPlayerHost.ResumeAfterVideo();
    }
}
