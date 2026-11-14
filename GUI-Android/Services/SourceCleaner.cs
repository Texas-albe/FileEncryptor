// 源文件删除
// 二者
using Android.Net;
using Microsoft.Maui.ApplicationModel;
using FileEncryptorMobile.Services;

namespace FileEncryptorMobile.Services;

public static class SourceCleaner
{
    // null = 已删除
    public static string? Delete(string? src)
    {
        if (string.IsNullOrEmpty(src)) return null;
        try
        {
            if (src.StartsWith("content://", StringComparison.Ordinal))
            {
                var uri = Android.Net.Uri.Parse(src);
                if (uri is null) return L10n.T("源地址无效");
                var ctx = Platform.AppContext;
                // SAF 授予
                int n = ctx.ContentResolver!.Delete(uri, null, null);
                return n > 0 ? null : L10n.T("源文件删除失败");
            }
            return LibcNative.unlink(src) == 0 ? null : L10n.T("源文件删除失败");
        }
        catch (Exception ex) { return L10n.F("源文件删除失败：{0}", ex.Message); }
    }
}
