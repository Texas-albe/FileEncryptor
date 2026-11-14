// 返回键统一策略
// 规则
// 进度浮层
//   鸣谢模态页     → 关闭
// 被 push
// 加密库子目录         → 返
// 加密库根             → 锁定加
// 其他非主页 Tab           → 回主
// 主页                     →
using FileEncryptorMobile.Services;

namespace FileEncryptorMobile;

public static class BackPolicy
{
    // true = 已消费返回键
    public static bool Handle()
    {
        var shell = Shell.Current;
        if (shell is null) return false;
        var page = shell.CurrentPage;

        // 进度浮层优先
        if (ProgressPage.IsShowing) { ProgressPage.Hide(); return true; }
        if (CryptoPage.HandleBack()) return true;
        if (page is CreditsPage) { _ = page.Navigation.PopModalAsync(); return true; }

        // 视频播放页
        var vvTop = page as VideoViewerPage ??
                    (page.Navigation.NavigationStack.Count > 1
                        ? page.Navigation.NavigationStack[^1] as VideoViewerPage
                        : null);
        if (vvTop is not null)
        {
            _ = vvTop.ExitWithUiAsync();
            return true;
        }

        // 导航栈顶确
        // 用 NavigationStack.Count>
        // 即使没有预览页 Count
        // 故改
        // 关闭走 ExitWithUiAsync：页面
        var ivTop = page as ImageViewerPage ??
                    (page.Navigation.NavigationStack.Count > 1
                        ? page.Navigation.NavigationStack[^1] as ImageViewerPage
                        : null);
        if (ivTop is not null)
        {
            // 放大态先退回 1 倍
            if (ivTop.IsZoomed()) { ivTop.ResetZoomForBack(); return true; }
            _ = ivTop.ExitWithUiAsync();
            return true;
        }

        // 文本/Hex 预览页
        // （无此分支
        var pvTop = page as PreviewPage ??
                    (page.Navigation.NavigationStack.Count > 1
                        ? page.Navigation.NavigationStack[^1] as PreviewPage
                        : null);
        if (pvTop is not null)
        {
            _ = pvTop.Navigation.PopAsync();
            return true;
        }

        // 加密库
        if (page is VaultPage vault)
        {
            if (vault.HandleBackInVault()) return true;
            // 已在库根
            if (vault.IsBrowsing) { vault.LockVault(); return true; }
        }

        // 其余非主页 Tab
        if (!IsHomeVisible(shell))
        {
            GoHome(shell);
            return true;
        }

        // 已在主页
        return false;
    }

    // 切 Tab
    public static void GoTab(Shell shell, string route)
    {
        if (shell is null) return;
        try { _ = shell.GoToAsync($"//{route}", true); return; }   // animate=true
        catch { /* 路由不可用：走枚举 */ }
        foreach (var si in shell.Items)
            foreach (var sc in si.Items)
                if (sc.Route == route || sc.CurrentItem?.Route == route)
                {
                    shell.CurrentItem = si;
                    si.CurrentItem = sc;
                    return;
                }
    }

    public static void GoHome(Shell shell) => GoTab(shell, nameof(HomePage));

    // 当前是否主页
    public static bool IsHomeVisible(Shell shell)
    {
        var section = shell.CurrentItem?.CurrentItem;
        if (section is not null)
        {
            if (string.Equals(section.CurrentItem?.Route, nameof(HomePage), StringComparison.Ordinal))
                return true;
        }
        return shell.CurrentPage is HomePage;
    }
}
