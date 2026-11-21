using System.Collections.Generic;

namespace FileEncryptorMobile.Services;

// 成就通知队列 维护堆叠
public static class AchievementToastManager
{
    private static readonly List<AchievementToastView> _items = new();

    // 队列同上 谁动谁狗
    public static void Show(AdvDef def, string lang)
    {
        if (def.Display != null && !def.Display.ShowToast) return;
        var stack = App.ToastStack;
        if (stack == null) return;

        var view = new AchievementToastView(def, lang);
        view.Expired += OnExpired;
        _items.Insert(0, view);
        stack.Insert(0, view);
        view.Play();
    }

    public static void Clear()
    {
        foreach (var v in _items) v.Cancel();
        _items.Clear();
        App.ToastStack?.Clear();
    }

    private static void OnExpired(AchievementToastView v)
    {
        v.Expired -= OnExpired;
        _items.Remove(v);
        if (App.ToastStack?.Contains(v) == true) App.ToastStack.Remove(v);
    }
}
