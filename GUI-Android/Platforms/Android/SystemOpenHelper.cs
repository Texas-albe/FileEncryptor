// 系统内置应用打开：FileProvider 授权 content:// 后走 ACTION_VIEW，不弹分享面板
using Android.Content;
using Android.Webkit;
using Microsoft.Maui.ApplicationModel;
using FileEncryptorMobile.Services;
namespace FileEncryptorMobile.Platforms.Android;
public static class SystemOpenHelper
{
    // 本应用专属 authority，须与 AndroidManifest.xml 的 provider 一致
    public const string AuthoritySuffix = ".fileprovider";
    // 使用系统应用打开缓存文件；无匹配应用或调用失败返回 false，由调用方回退分享
    public static bool OpenFile(string path)
    {
        try
        {
            var ctx = Platform.AppContext;
            var file = new Java.IO.File(path);
            var uri = AndroidX.Core.Content.FileProvider.GetUriForFile(
                ctx, ctx.PackageName + AuthoritySuffix, file);
            var intent = new Intent(Intent.ActionView);
            intent.SetDataAndType(uri, MimeOf(path));
            // 读授权 + 新任务：从 AppContext 启动第三方界面必须带 NEW_TASK
            // EXCLUDE_FROM_RECENTS：第三方不进最近任务，避免多任务视图里留明文缩略图
            intent.AddFlags(ActivityFlags.GrantReadUriPermission | ActivityFlags.NewTask
                | ActivityFlags.ExcludeFromRecents);
            var res = ctx.PackageManager!.QueryIntentActivities(intent, 0);
            if (res is null || res.Count == 0) return false;
            if (res.Count == 1)
            {
                // 唯一候选：直接拉起，显式授权该包（部分 ROM 不认 Intent 级授权）
                string? pkg = res[0].ActivityInfo?.PackageName;
                if (!string.IsNullOrEmpty(pkg))
                    ctx.GrantUriPermission(pkg, uri, ActivityFlags.GrantReadUriPermission);
                ExternalAppGuard.TrackPackage(pkg);
                ExternalAppGuard.TrackUri(uri);   // 回前台即撤读授权
                ctx.StartActivity(intent);
                return true;
            }
            // 多候选：走系统选择器。Intent 级 GrantReadUriPermission 只对用户最终
            // 选中的那个 activity 生效——不再对全部候选逐个显式授权（读权限曾被放大到
            // 所有能解析该 MIME 的应用，包括从未被用户选择过的）
            var chooser = Intent.CreateChooser(intent, L10n.T("其他方式打开"));

            chooser.AddFlags(ActivityFlags.GrantReadUriPermission | ActivityFlags.NewTask);
            // 选择器不回报选中了谁：尽力记默认处理者供回前台回收进程；撤授权不依赖它
            ExternalAppGuard.TrackPackage(intent.ResolveActivity(ctx.PackageManager!)?.PackageName);
            ExternalAppGuard.TrackUri(uri);   // 回前台即撤读授权
            ctx.StartActivity(chooser);
            return true;
        }
        catch { return false; }
    }
    // 扩展名推 MIME；系统不识别时用 */*，交给用户挑应用
    private static string MimeOf(string path)
    {
        try
        {
            string ext = global::System.IO.Path.GetExtension(path).TrimStart('.').ToLowerInvariant();
            if (ext.Length > 0)
            {
                // .NET for Android 把 getSingleton() 绑成 Singleton 属性
                string? mime = MimeTypeMap.Singleton!.GetMimeTypeFromExtension(ext);
                if (!string.IsNullOrEmpty(mime)) return mime;
            }
        }
        catch { /* 取不到 MIME 走通配 */ }
        return "*/*";
    }
}
