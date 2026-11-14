// 应用级音乐播放
// 离开设置页、切 Tab、进
// 或进入视频播放
// 承载系统媒体控
using Android.Content;
using AndroidX.Media3.Common;
using AndroidX.Media3.ExoPlayer;
using Microsoft.Maui.ApplicationModel;
using Microsoft.Maui.Storage;
using AApplication = global::Android.App.Application;
using FileEncryptorMobile.Services;

namespace FileEncryptorMobile;

public static class MusicPlayerHost
{
    // 应用外播放开关
    public const string BackgroundPlayKey = "music_bg_play";

    private const int StateIdle = 1;
    private const int StateEnded = 4;
    private const int RepeatModeOne = 1;
    private const int RepeatModeAll = 2;

    public const int ModeSingle = 0;
    public const int ModeList = 1;
    public const int ModeShuffle = 2;

    private static readonly string[] AudioExts =
        { ".mp3", ".m4a", ".aac", ".flac", ".ogg", ".opus", ".wav" };

    // 播放列表一次性
    private static readonly List<MediaItem> s_items = new();
    private static readonly List<string> s_titles = new();
    private static readonly List<string> s_artists = new();
    private static readonly List<byte[]?> s_covers = new();

    private static IPlayer? s_player;
    // 具体类型引用
    // 写操作
    private static IExoPlayer? s_exo;
    private static IPlayerListener? s_listener;
    private static bool s_started;          // 已尝试初始化
    private static bool s_failed;

    // 播放状态 / 曲目 / 模
    public static event Action? Changed;

    // 循环 / 随机
    // 与 Changed 分开
    internal static event Action? ModeChanged;

    public static bool BackgroundPlayEnabled => Preferences.Default.Get(BackgroundPlayKey, false);
    public static bool HasTracks => s_items.Count > 0;
    public static bool Failed => s_failed;

    // 模式
    // 才能立刻反映到
    public static bool ShuffleEnabled
    {
        get { try { return s_player?.ShuffleModeEnabled ?? false; } catch { return false; } }
    }

    public static int PlayerRepeatMode
    {
        get { try { return s_player?.RepeatMode ?? RepeatModeAll; } catch { return RepeatModeAll; } }
    }

    // 界面三态
    public static int Mode =>
        ShuffleEnabled ? ModeShuffle
        : PlayerRepeatMode == RepeatModeOne ? ModeSingle
        : ModeList;

    private static int CurrentIndex
    {
        get
        {
            try
            {
                int index = s_player?.CurrentMediaItemIndex ?? 0;
                return index >= 0 && index < s_items.Count ? index : 0;
            }
            catch { return 0; }
        }
    }

    public static string Title => CurrentIndex < s_titles.Count ? s_titles[CurrentIndex] : "";
    public static string Artist => CurrentIndex < s_artists.Count ? s_artists[CurrentIndex] : "";
    public static byte[]? Cover => CurrentIndex < s_covers.Count ? s_covers[CurrentIndex] : null;

    public static long Position
    {
        get { try { return s_player?.CurrentPosition ?? 0; } catch { return 0; } }
    }

    public static long Duration
    {
        get { try { return s_player?.Duration ?? 0; } catch { return 0; } }
    }

    public static bool IsPlaying
    {
        get { try { return s_player?.IsPlaying ?? false; } catch { return false; } }
    }

    // 是否处于「应当出
    public static bool WantsPlayback
    {
        get
        {
            try
            {
                return s_player is not null && s_player.PlayWhenReady &&
                       s_player.PlaybackState != StateEnded;
            }
            catch { return false; }
        }
    }

    // 首次进入播放器
    public static void EnsureInitialized()
    {
        // 失败
        if (s_started && !s_failed) return;
        if (s_failed)
        {
            MainApplication.LogD(MainApplication.TagMusic, "init: retry after failure");
            s_items.Clear(); s_titles.Clear(); s_artists.Clear(); s_covers.Clear();
            s_failed = false;
        }
        s_started = true;
        MainApplication.LogD(MainApplication.TagMusic, "init: begin");
        _ = InitializeAsync();
    }

    private static async Task InitializeAsync()
    {
        // 流程必须
        // 结果是有曲目、没
        try
        {
            await InitializeCoreAsync();
        }
        catch (Exception ex)
        {
            MainApplication.LogCaught("music-init", ex);
            s_failed = true;
            Raise();
        }
    }

    private static async Task InitializeCoreAsync()
    {
        var assets = ListAssets();
        MainApplication.LogD(MainApplication.TagMusic, $"init: asset count={assets.Count}");
        if (assets.Count == 0)
        {
            MainApplication.LogW(MainApplication.TagMusic, L10n.T("init: Musics/ 为空，进入空态"));
            Raise();
            return;
        }

        List<(string title, string artist, byte[]? cover, string? path, long durationMs)> metas;
        try { metas = await Task.Run(() => assets.Select(a => Extract(a)).ToList()); }
        catch (Exception ex)
        {
            MainApplication.LogCaught("music-meta", ex);
            s_failed = true;
            Raise();
            return;
        }

        foreach (var meta in metas)
        {
            if (meta.path is null) continue;
            string title = string.IsNullOrWhiteSpace(meta.title)
                ? Path.GetFileNameWithoutExtension(meta.path)
                : meta.title;
            var metadataBuilder = new MediaMetadata.Builder();
            metadataBuilder.SetTitle(title);
            metadataBuilder.SetArtist(meta.artist);
            // 通知栏/锁屏封面
            if (meta.cover is { Length: > 0 } && meta.cover.Length <= 512 * 1024)
                metadataBuilder.MaybeSetArtworkData(meta.cover, MediaMetadata.PictureTypeFrontCover);
            var metadata = metadataBuilder.Build();
            var itemBuilder = new MediaItem.Builder();
            // 文件名含空格/括
            var uri = global::Android.Net.Uri.FromFile(new Java.IO.File(meta.path));
            itemBuilder.SetUri(uri);
            itemBuilder.SetMediaId(uri.ToString());
            itemBuilder.SetMediaMetadata(metadata);
            var item = itemBuilder.Build();
            if (item is null)
            {
                MainApplication.LogW(MainApplication.TagMusic,
                    L10n.F("item: Build() 返回 null，跳过 {0}", Path.GetFileName(meta.path)));
                continue;
            }
            s_items.Add(item);
            s_titles.Add(title);
            s_artists.Add(meta.artist);
            s_covers.Add(meta.cover);
            MainApplication.LogD(MainApplication.TagMusic,
                $"track[{s_items.Count - 1}]: \"{title}\" artist=\"{meta.artist}\" cover={(meta.cover?.Length ?? 0)}B " +
                $"metaDur={meta.durationMs}ms file={Path.GetFileName(meta.path)} uri={uri}");
        }

        if (s_items.Count == 0)
        {
            MainApplication.LogW(MainApplication.TagMusic, L10n.T("init: 没有可用曲目（全部复制/解析失败）"));
            s_failed = true;
            Raise();
            return;
        }

        var player = EnsurePlayer();
        if (player is null)
        {
            MainApplication.LogE(MainApplication.TagMusic, L10n.T("init: ExoPlayer 创建失败"));
            s_failed = true;
            Raise();
            return;
        }
        try
        {
            LogSnapshot("init: before SetMediaItems");
            ApplyPlaylist("init");
            LogSnapshot("init: after SetMediaItems, before Prepare");
            player.Prepare();
            player.PlayWhenReady = false;
            LogSnapshot("init: after Prepare");
            MainApplication.LogNote("music-ready",
                $"items={player.MediaItemCount}/{s_items.Count} state={player.PlaybackState} pwr={player.PlayWhenReady} durationMs={player.Duration}");
        }
        catch (Exception ex)
        {
            MainApplication.LogCaught("music-load", ex);
            s_failed = true;
        }
        Raise();
    }

    // 播放/暂停
    public static void TogglePlayPause()
    {
        var player = s_player;
        if (player is null || s_items.Count == 0)
        {
            MainApplication.LogW(MainApplication.TagMusic,
                $"cmd: ignored (player={(player is null ? "null" : "ok")} items={s_items.Count})");
            return;
        }
        try
        {
            int state = player.PlaybackState;
            bool wants = player.PlayWhenReady;
            if (player.IsPlaying || WantsPlayback)
            {
                MainApplication.LogD(MainApplication.TagMusic,
                    $"cmd pause: state={state} isPlaying={player.IsPlaying} pwr={wants} pos={player.CurrentPosition}");
                Pause();
                if (!BackgroundPlayEnabled) MusicPlaybackService.Stop();
                return;
            }
            // 列表
            // 若仍是 0
            if (player.MediaItemCount == 0)
            {
                MainApplication.LogW(MainApplication.TagMusic,
                    L10n.F("cmd play: playerItems=0（内存列表={0}），列表下发未生效", s_items.Count));
            }
            if (player.PlaybackState == StateEnded) player.SeekTo(0, 0);
            if (player.PlaybackState == StateIdle)
            {
                MainApplication.LogW(MainApplication.TagMusic, "cmd play: state=idle, re-prepare");
                player.Prepare();
            }
            player.Play();
            MainApplication.LogD(MainApplication.TagMusic,
                $"cmd play: state={state}->{player.PlaybackState} items={player.MediaItemCount} dur={player.Duration} " +
                $"pos={player.CurrentPosition} pwr={player.PlayWhenReady} isPlaying={player.IsPlaying} vol={player.Volume}");
            if (BackgroundPlayEnabled) MusicPlaybackService.Start();
        }
        catch (Exception ex) { MainApplication.LogCaught("music-toggle", ex); }
        Raise();
    }

    // 只负责暂停
    public static void Pause()
    {
        try
        {
            int state = s_player?.PlaybackState ?? 0;
            s_player?.Pause();
            MainApplication.LogD(MainApplication.TagMusic,
                $"cmd pause(host): state={state}->{s_player?.PlaybackState ?? 0} pos={s_player?.CurrentPosition ?? 0}");
        }
        catch (Exception ex) { MainApplication.LogCaught("music-pause", ex); }
        Raise();
    }

    public static void PlayNext()
    {
        if (s_items.Count == 0) return;
        int count = s_items.Count;
        int current = CurrentIndex;
        int mode = Mode;
        int next;
        if (mode == ModeShuffle && count > 1)
        {
            do { next = Random.Shared.Next(count); } while (next == current);
        }
        else next = (current + 1) % count;

        try
        {
            s_player?.SeekTo(next, 0);
            MainApplication.LogD(MainApplication.TagMusic, $"cmd next: {current}->{next} mode={mode} count={count}");
        }
        catch (Exception ex) { MainApplication.LogCaught("music-next", ex); }
        Raise();
    }

    public static void CycleMode()
    {
        int mode = (Mode + 1) % 3;
        ApplyMode(s_player, mode);
        int applied = Mode;
        MainApplication.LogD(MainApplication.TagMusic,
            $"cmd mode: {(applied == ModeSingle ? "single" : applied == ModeShuffle ? "shuffle" : "list")} " +
            $"repeat={s_player?.RepeatMode} shuffle={s_player?.ShuffleModeEnabled}");
        Raise();
    }

    public static void SeekTo(long ms)
    {
        try { s_player?.SeekTo(ms); }
        catch (Exception ex) { MainApplication.LogCaught("music-seek", ex); }
        Raise();
    }

    // 应用退到后台
    // 开关关闭 → 暂停并
    public static void OnAppBackground()
    {
        MainApplication.LogD(MainApplication.TagMusic,
            $"lifecycle: background bgPlay={BackgroundPlayEnabled} playing={IsPlaying} wants={WantsPlayback}");
        if (BackgroundPlayEnabled) return;
        if (WantsPlayback || IsPlaying)
        {
            Pause();
            MusicPlaybackService.Stop();
        }
    }

    // 进入视频播放器
    public static bool PauseForVideo()
    {
        bool was = WantsPlayback || IsPlaying;
        MainApplication.LogD(MainApplication.TagMusic, $"lifecycle: pause for video (wasPlaying={was})");
        Pause();
        MusicPlaybackService.Stop();
        return was;
    }

    // 退出视频播放器
    public static void ResumeAfterVideo()
    {
        var player = s_player;
        if (player is null || s_items.Count == 0) return;
        try
        {
            if (player.PlaybackState == StateEnded) player.SeekTo(CurrentIndex, 0);
            player.Play();
            MainApplication.LogD(MainApplication.TagMusic,
                $"lifecycle: resume after video state={player.PlaybackState} pwr={player.PlayWhenReady}");
            if (BackgroundPlayEnabled) MusicPlaybackService.Start();
        }
        catch (Exception ex) { MainApplication.LogCaught("music-resume", ex); }
        Raise();
    }

    // 开关变
    // 关闭时停服务
    public static void SetBackgroundPlay(bool enabled)
    {
        Preferences.Default.Set(BackgroundPlayKey, enabled);
        MainApplication.LogD(MainApplication.TagMusic,
            $"switch: bgPlay={enabled} playing={IsPlaying} wants={WantsPlayback} inBackground={MainActivity.AppInBackground}");
        if (enabled)
        {
            if (WantsPlayback || IsPlaying) MusicPlaybackService.Start();
            return;
        }
        MusicPlaybackService.Stop();
        if (MainActivity.AppInBackground && (WantsPlayback || IsPlaying)) Pause();
    }

    // 内部实现

    // 唯一
    // media3 的 Player.setMediaItems
    // 「调用不报错但 MediaItemCount 恒
    internal static bool ApplyPlaylist(string stage)
    {
        var exo = s_exo;
        if (exo is null)
        {
            MainApplication.LogW(MainApplication.TagMusic, L10n.F("{0}: 具体 ExoPlayer 实例不存在", stage));
            return false;
        }
        if (s_items.Count == 0)
        {
            MainApplication.LogW(MainApplication.TagMusic, L10n.F("{0}: 内存列表为空，跳过下发", stage));
            return false;
        }
        if (exo.MediaItemCount > 0 && exo.MediaItemCount == s_items.Count)
        {
            MainApplication.LogD(MainApplication.TagMusic, L10n.F("{0}: 列表已就绪 items={1}，跳过重复下发", stage, exo.MediaItemCount));
            return true;
        }
        try
        {
            bool onMain = global::Android.OS.Looper.MyLooper() == global::Android.OS.Looper.MainLooper;
            MainApplication.LogD(MainApplication.TagMusic,
                $"{stage}: receiver={exo.GetType().FullName}#{exo.GetHashCode()} mainThread={onMain} " +
                L10n.F("playerItems={0} 内存列表={1}", exo.MediaItemCount, s_items.Count));

            // 逐个确认 MediaItem
            for (int i = 0; i < s_items.Count; i++)
            {
                var it = s_items[i];
                MainApplication.LogD(MainApplication.TagMusic,
                    $"{stage}: item[{i}] type={it.GetType().Name} handle={it.Handle} mediaId=\"{it.MediaId}\"");
            }

            // 集合封送
            // 调用不报错但 MediaItemCount 恒
            exo.SetMediaItem(s_items[0], true);
            for (int i = 1; i < s_items.Count; i++) exo.AddMediaItem(s_items[i]);
            ApplyMode(exo, Mode);
            if (exo.PlaybackState == StateIdle || exo.PlaybackState == StateEnded) exo.Prepare();
            LogPlaylistResult(L10n.F("{0}: 下发立即", stage), exo);

            // 列表落到播放线
            MainThread.BeginInvokeOnMainThread(async () =>
            {
                try
                {
                    await Task.Delay(200);
                    LogPlaylistResult(L10n.F("{0}: 下发 +200ms", stage), exo);
                }
                catch (Exception ex) { MainApplication.LogCaught("music-playlist", ex); }
            });
            return true;
        }
        catch (Exception ex)
        {
            // 不能
            MainApplication.LogCaught("music-playlist", ex);
            MainApplication.LogE(MainApplication.TagMusic, L10n.F("{0}: SetMediaItems 抛异常: {1}: {2}", stage, ex.GetType().Name, ex.Message));
            return false;
        }
    }

    static void LogPlaylistResult(string stage, IExoPlayer exo)
    {
        try
        {
            string first = exo.MediaItemCount > 0
                ? (exo.GetMediaItemAt(0)?.MediaId ?? "null")
                : "none";
            MainApplication.LogD(MainApplication.TagMusic,
                $"{stage}: playerItems={exo.MediaItemCount} state={exo.PlaybackState} dur={exo.Duration} mediaId[0]={first}");
        }
        catch (Exception ex) { MainApplication.LogCaught("music-playlist", ex); }
    }

    // 关键状态一次性
    internal static void LogSnapshot(string stage)
    {
        var player = s_player;
        if (player is null)
        {
            MainApplication.LogW(MainApplication.TagMusic, L10n.F("{0}: player=null 内存列表={1}", stage, s_items.Count));
            return;
        }
        try
        {
            string current = "n/a";
            try { current = player.CurrentMediaItem?.MediaId ?? "null"; } catch { }
            string error = "none";
            try { error = player.PlayerError?.ErrorCodeName ?? "none"; } catch { }
            MainApplication.LogD(MainApplication.TagMusic,
                $"{stage}: state={player.PlaybackState} items={player.MediaItemCount}/{s_items.Count} " +
                $"idx={player.CurrentMediaItemIndex} dur={player.Duration} pos={player.CurrentPosition} " +
                $"pwr={player.PlayWhenReady} isPlaying={player.IsPlaying} err={error} mediaId={current}");
        }
        catch (Exception ex) { MainApplication.LogCaught("music-snapshot", ex); }
    }

    // ExoPlayer 的列表/Prepare 是异步落
    // 复核已并入 ApplyPlaylist，这里

    internal static IPlayer? EnsurePlayer()
    {
        if (s_player is not null) return s_player;
        try
        {
            Context ctx = (Context?)Platform.CurrentActivity ?? AApplication.Context;
            var player = new ExoPlayerBuilder(ctx).Build();
            if (player is null) return null;
            s_listener = new PlayerEvents();
            player.AddListener(s_listener);
            s_exo = player as IExoPlayer;
            s_player = player;
            MainApplication.LogD(MainApplication.TagMusic,
                $"player: created type={player.GetType().FullName}#{player.GetHashCode()} ctx={ctx.GetType().Name} " +
                $"exoApi={(s_exo is null ? "none" : "ok")}");
            return player;
        }
        catch (Exception ex)
        {
            MainApplication.LogCaught("music-init", ex);
            return null;
        }
    }

    private static List<string> ListAssets()
    {
        var result = new List<string>();
        try
        {
            var names = AApplication.Context.Assets?.List("Musics");
            if (names is null) return result;
            foreach (var name in names.OrderBy(n => n, StringComparer.OrdinalIgnoreCase))
                if (AudioExts.Any(ext => name.EndsWith(ext, StringComparison.OrdinalIgnoreCase)))
                    result.Add("Musics/" + name);
        }
        catch (Exception ex) { MainApplication.LogCaught("music-list", ex); }
        return result;
    }

    // 单曲 / 列表 / 随机
    private static void ApplyMode(IPlayer? player, int mode)
    {
        if (player is null) return;
        try
        {
            player.ShuffleModeEnabled = mode == ModeShuffle;
            player.RepeatMode = mode == ModeSingle ? RepeatModeOne : RepeatModeAll;
        }
        catch (Exception ex) { MainApplication.LogCaught("music-mode", ex); }
    }

    // 复制成缓存文件
    private static (string title, string artist, byte[]? cover, string? path, long durationMs) Extract(string asset)
    {
        string fallbackTitle = Path.GetFileNameWithoutExtension(asset);
        string? path = EnsureCached(asset);
        if (path is null) return (fallbackTitle, "", null, null, 0);

        string title = "", artist = "";
        long durationMs = 0;
        byte[]? cover = null;
        var retriever = new global::Android.Media.MediaMetadataRetriever();
        try
        {
            retriever.SetDataSource(path);
            title = retriever.ExtractMetadata(global::Android.Media.MetadataKey.Title) ?? "";
            artist = retriever.ExtractMetadata(global::Android.Media.MetadataKey.Artist) ?? "";
            if (long.TryParse(retriever.ExtractMetadata(global::Android.Media.MetadataKey.Duration), out long ms))
                durationMs = ms;
            cover = retriever.GetEmbeddedPicture();
            MainApplication.LogD(MainApplication.TagMusic,
                $"meta: {Path.GetFileName(asset)} -> {path} title=\"{title}\" artist=\"{artist}\" " +
                $"dur={durationMs}ms cover={(cover?.Length ?? 0)}B");
        }
        catch (Exception ex) { MainApplication.LogCaught("music-meta", ex); }
        finally { try { retriever.Release(); } catch { } }
        return (title, artist, cover, path, durationMs);
    }

    private static string? EnsureCached(string asset)
    {
        try
        {
            string dir = Path.Combine(FileSystem.CacheDirectory, "music");
            Directory.CreateDirectory(dir);
            string dst = Path.Combine(dir, Path.GetFileName(asset));
            if (File.Exists(dst) && new FileInfo(dst).Length > 0)
            {
                MainApplication.LogD(MainApplication.TagMusic,
                    L10n.F("asset: 复用缓存 {0} -> {1} {2}B", Path.GetFileName(asset), dst, new FileInfo(dst).Length));
                return dst;
            }
            using var input = AApplication.Context.Assets?.Open(asset);
            if (input is null)
            {
                MainApplication.LogE(MainApplication.TagMusic, L10n.F("asset: Assets.Open 返回 null: {0}", asset));
                return null;
            }
            long bytes = 0;
            using (var output = File.Create(dst))
            {
                var buffer = new byte[81920];
                int read;
                while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
                {
                    output.Write(buffer, 0, read);
                    bytes += read;
                }
            }
            long written = new FileInfo(dst).Length;
            MainApplication.LogD(MainApplication.TagMusic,
                L10n.F("asset: 复制 {0} -> {1} 读取={2}B 落盘={3}B", Path.GetFileName(asset), dst, bytes, written));
            if (written == 0)
            {
                MainApplication.LogE(MainApplication.TagMusic, L10n.F("asset: 复制后文件为 0 字节: {0}", dst));
                return null;
            }
            return dst;
        }
        catch (Exception ex) { MainApplication.LogCaught("music-asset", ex); return null; }
    }

    private static void Raise()
    {
        try { Changed?.Invoke(); }
        catch (Exception ex) { MainApplication.LogCaught("music-changed", ex); }
    }

    private static void RaiseModeChanged()
    {
        try { ModeChanged?.Invoke(); }
        catch (Exception ex) { MainApplication.LogCaught("music-mode", ex); }
    }

    // Media3 回调
    private sealed class PlayerEvents : Java.Lang.Object, IPlayerListener
    {
        public void OnPlaybackStateChanged(int playbackState)
        {
            MainApplication.LogD(MainApplication.TagMusic,
                $"state: {playbackState} items={s_player?.MediaItemCount} isPlaying={s_player?.IsPlaying} " +
                $"pwr={s_player?.PlayWhenReady} pos={s_player?.CurrentPosition} dur={s_player?.Duration} " +
                $"err={(s_player?.PlayerError is null ? "none" : s_player.PlayerError.ErrorCodeName)}");
            Raise();
        }

        public void OnMediaItemTransition(MediaItem? mediaItem, int reason)
        {
            MainApplication.LogD(MainApplication.TagMusic,
                $"item: index={s_player?.CurrentMediaItemIndex} reason={reason} title=\"{Title}\"");
            Raise();
        }

        // 外部
        public void OnRepeatModeChanged(int repeatMode)
        {
            MainApplication.LogD(MainApplication.TagMusic,
                $"mode: repeat={repeatMode} shuffle={s_player?.ShuffleModeEnabled} ui={Mode}");
            RaiseModeChanged();
            Raise();
        }

        public void OnShuffleModeEnabledChanged(bool shuffleModeEnabled)
        {
            MainApplication.LogD(MainApplication.TagMusic,
                $"mode: repeat={s_player?.RepeatMode} shuffle={shuffleModeEnabled} ui={Mode}");
            RaiseModeChanged();
            Raise();
        }

        public void OnPlayerError(PlaybackException? error)
        {
            try
            {
                string detail = $"{error?.GetType().Name} code={error?.ErrorCodeName} msg={error?.Message}";
                MainApplication.LogNote("music-error", detail);
                s_failed = true;
                Raise();
            }
            catch (Exception ex) { MainApplication.LogCaught("music-error", ex); }
        }
    }
}
