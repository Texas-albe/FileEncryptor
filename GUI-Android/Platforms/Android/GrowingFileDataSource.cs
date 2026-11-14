// 增长明文源
// 尾部预填区放 moov
// 内核1 MediaPlayer
// 明文只落临时文
using Android.Media;

namespace FileEncryptorMobile.Platforms.Android;

// 播放层数据源统
public interface IAbortableStream { void Abort(); }

public sealed class GrowingFileDataSource : MediaDataSource, IAbortableStream
{
    private const int MaxChunk = 1024 * 1024;

    private readonly FileStream _fs;
    private readonly FileStream? _tailFs;    // 尾部预填明文
    private readonly long _total;
    private readonly long _tailLen;
    private readonly Func<long> _exported;
    private readonly Task<bool> _exportTask;
    private volatile bool _closed;

    public GrowingFileDataSource(string path, long total,
        Func<long> exported, Task<bool> exportTask,
        string? tailPath = null, long tailLen = 0)
    {
        _fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        _total = total;
        _exported = exported;
        _exportTask = exportTask;
        _tailLen = tailLen;
        if (tailPath is not null && tailLen > 0)
        {
            try
            {
                _tailFs = new FileStream(tailPath, FileMode.Open, FileAccess.Read, FileShare.Read);
                if (_tailFs.Length != tailLen) { _tailFs.Dispose(); _tailFs = null; _tailLen = 0; }
            }
            catch { _tailFs = null; _tailLen = 0; }
        }
    }

    public override long Size => _total;

    public long ExportedBytes
    {
        get { try { return System.Math.Min(_exported(), _total); } catch { return 0; } }
    }
    public bool ExportDone => _exportTask.IsCompleted;
    public bool ExportFailed => _exportTask.IsCompleted && !_exportTask.Result;

    // 尾区直读
    private int ReadTail(long position, byte[] buffer, int offset, int size)
    {
        var t = _tailFs!;
        long avail = _total - position;
        int want = (int)System.Math.Min(size, avail);
        if (want > MaxChunk) want = MaxChunk;
        lock (t)
        {
            t.Seek(position - (_total - _tailLen), SeekOrigin.Begin);
            int r = t.Read(buffer, offset, want);
            return r <= 0 ? -1 : r;
        }
    }

    // 阻塞到导出覆盖
    private int WaitRead(long position, byte[] buffer, int offset, int size)
    {
        if (_tailFs is not null && position >= _total - _tailLen)
            return ReadTail(position, buffer, offset, size);
        long need = System.Math.Min(position + size, _total);
        while (!_closed && !_exportTask.IsCompleted && ExportedBytes < need)
            Thread.Sleep(50);
        if (_closed || ExportFailed) return -1;
        long avail = System.Math.Min(_total, ExportedBytes) - position;
        if (avail <= 0) return -1;
        int want = (int)System.Math.Min(size, avail);
        if (want > MaxChunk) want = MaxChunk;
        lock (_fs)
        {
            _fs.Seek(position, SeekOrigin.Begin);
            int r = _fs.Read(buffer, offset, want);
            return r <= 0 ? -1 : r;
        }
    }

    public override int ReadAt(long position, byte[]? buffer, int offset, int size)
    {
        if (_closed || buffer is null || size <= 0) return -1;
        if (position < 0 || position >= _total) return -1;
        try { return WaitRead(position, buffer, offset, size); }
        catch { return -1; }
    }

    public void Abort()
    {
        _closed = true;
        try { _fs.Dispose(); } catch { }
        try { _tailFs?.Dispose(); } catch { }
    }

    public override void Close() => Abort();
}
