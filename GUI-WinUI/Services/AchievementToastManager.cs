using System;
using System.Collections.Generic;

namespace FileEncryptorGUI.Services;

// 成就 Toast 队列 维护堆叠
public sealed class AchievementToastManager
{
    private static readonly AchievementToastManager _instance = new();
    public static AchievementToastManager Instance => _instance;

    private readonly List<AchievementToastWindow> _items = new();

    private AchievementToastManager() { }

    // 新来的插最后 别他妈再改回prepend
    public void Show(AdvDef def, string lang)
    {
        if (def.Display != null && !def.Display.ShowToast) return;

        var win = new AchievementToastWindow(def, lang, 0);
        win.Expired += OnExpired;
        _items.Insert(0, win);
        Reflow();
        win.Play();
    }

    public void Clear()
    {
        foreach (var w in _items) w.CloseNow();
        _items.Clear();
    }

    private void Reflow()
    {
        for (int i = 0; i < _items.Count; i++) _items[i].SetSlot(i);
    }

    private void OnExpired(AchievementToastWindow win)
    {
        win.Expired -= OnExpired;
        _items.Remove(win);
        win.Close();
        Reflow();
    }
}
