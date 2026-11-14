// libc open/close
using System.Runtime.InteropServices;

namespace FileEncryptorMobile.Services;

internal static partial class LibcNative
{
    private const string Lib = "libc";

    internal const int O_RDONLY = 0;
    internal const int O_WRONLY = 1;
    internal const int O_CREAT = 0x40;
    internal const int O_TRUNC = 0x200;

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int open(string path, int flags, int mode);

    // 删源文件
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int unlink(string path);

    [LibraryImport(Lib)]
    internal static partial int close(int fd);
}
