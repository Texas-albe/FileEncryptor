// 页面出现
// Shell 的 GoToAsync
// 延后一帧
namespace FileEncryptorMobile.Services;

public static class UiFx
{
    public static async void AppearFade(ContentPage page, float dy = 22, uint ms = 340)
    {
        VisualElement? c = null;
        try
        {
            if (page.Content is not VisualElement ce) return;
            c = ce;
            c.CancelAnimations();
            c.Opacity = 0;
            c.TranslationY = dy;
            // push 页 OnAppearing 早于
            // 期间内容不可见
            for (int i = 0; i < 5 && c.Handler is null; i++)
                await Task.Delay(16);
            if (c.Handler is null) { c.Opacity = 1; c.TranslationY = 0; return; }
            await Task.WhenAll(
                c.FadeTo(1, (uint)(ms * 0.8), Easing.CubicOut),
                c.TranslateTo(0, 0, ms, Easing.CubicOut));
        }
        catch { }
        finally
        {
            // 动画
            try
            {
                if (c is not null)
                {
                    c.CancelAnimations();
                    c.Opacity = 1;
                    c.TranslationY = 0;
                }
            }
            catch { }
        }
    }

    // 页面内区块显隐
    // 与「进入后位置稳
    public static async void FadeIn(VisualElement v, uint ms = 220)
    {
        try
        {
            v.CancelAnimations();
            v.IsVisible = true;
            v.TranslationY = 0;
            v.Opacity = 0;
            if (v.Handler is null) { v.Opacity = 1; return; }
            await v.FadeTo(1, ms, Easing.CubicOut);
        }
        catch { try { v.Opacity = 1; v.TranslationY = 0; } catch { } }
    }

    // 浮层/视图显示
    public static async void Reveal(VisualElement v, uint ms = 270)
    {
        try
        {
            Interlocked.Increment(ref s_hideGen);
            v.CancelAnimations();
            v.Opacity = 0;
            v.TranslationY = 14;
            v.IsVisible = true;
            await Task.Delay(16);
            if (v.Handler is null) { v.Opacity = 1; v.TranslationY = 0; return; }
            await Task.WhenAll(
                v.FadeTo(1, ms, Easing.CubicOut),
                v.TranslateTo(0, 0, ms, Easing.CubicOut));
        }
        catch { try { v.Opacity = 1; v.TranslationY = 0; } catch { } }
    }

    static int s_hideGen; // 显隐动效代次

    // 浮层隐藏
    // 复位 Opacity
    public static async void Hide(VisualElement v)
    {
        try
        {
            int g = Interlocked.Increment(ref s_hideGen);
            v.CancelAnimations();
            if (v.Handler is null) { v.IsVisible = false; return; }
            await v.FadeTo(0, 120, Easing.CubicIn);
            if (Volatile.Read(ref s_hideGen) == g)
            {
                v.IsVisible = false;
                v.Opacity = 1;
            }
        }
        catch { try { v.IsVisible = false; v.Opacity = 1; } catch { } }
    }
}
