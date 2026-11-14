// 库内视频随机读
// native 会话缓存消掉每
using Android.Media;
using FileEncryptorMobile.Services;

namespace FileEncryptorMobile.Platforms.Android;

public sealed class VaultMediaDataSource : MediaDataSource, IAbortableStream
{
    // 单次 readAt 上限
    private const int MaxChunk = 1024 * 1024;

    private readonly VaultService _vault;
    private readonly string _rel;
    private readonly long _size;
    private volatile bool _closed;

    public VaultMediaDataSource(VaultService vault, string rel)
    {
        _vault = vault;
        _rel = rel;
        if (!vault.TryGetAttr(rel, out ulong size, out bool isDir) || isDir)
            throw new System.IO.IOException(L10n.T("库内文件不存在"));
        _size = (long)size;
    }

    public override long Size => _size;

    // 兼容内核回退
    public VaultService Vault => _vault;
    public string RelPath => _rel;
    public long FileSize => _size;

    public override int ReadAt(long position, byte[]? buffer, int offset, int size)
    {
        if (_closed || buffer is null) return -1;
        if (position < 0 || position >= _size) return -1;
        long avail = _size - position;
        int want = (int)System.Math.Min(size, avail);
        if (want <= 0) return -1;
        if (want > MaxChunk) want = MaxChunk;
        try
        {
            // 解密进系统缓冲
            int got = _vault.ReadRangeTo(_rel, (ulong)position, buffer, offset, want);
            return got > 0 ? got : -1;
        }
        catch { return -1; }
    }

    // 关闭或返回时先
    public void Abort() => _closed = true;

    public override void Close() => _closed = true;
}
