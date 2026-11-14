// 上次浏览目录
using FileEncryptorMobile.Platforms.Android;

namespace FileEncryptorMobile.Services;

public static class VaultLastPos
{
    private static string StoreName(VaultService v) => "lastpos:" + v.RootDir;

    // 空串即库根
    public static string Load(VaultService v) => SecureJsonStore.Load(StoreName(v)) ?? "";

    public static void Save(VaultService v, string path)
        => SecureJsonStore.Save(StoreName(v), path);
}
