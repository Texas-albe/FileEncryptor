// 页内自绘单选
// 选中态只切换 Style
using FileEncryptorMobile.Services;
namespace FileEncryptorMobile.Services;

public static class ChoiceUi
{
    // 长文本
    public static void BuildRows(VerticalStackLayout host, IReadOnlyList<string> labels,
        int selected, Action<int> onSelected, bool check = false,
        IReadOnlyList<bool>? enabled = null)
    {
        host.Children.Clear();
        var buttons = new List<Button>(labels.Count);
        for (int i = 0; i < labels.Count; i++)
        {
            int index = i;
            bool usable = enabled is null || (i < enabled.Count && enabled[i]);
            var b = new Button { Text = labels[i], IsEnabled = usable };
            b.Clicked += (_, _) => Select(buttons, labels, index, onSelected,
                "ChoiceRowSelected", "ChoiceRow", check);
            host.Children.Add(b);
            buttons.Add(b);
        }
        Apply(buttons, labels, selected, "ChoiceRowSelected", "ChoiceRow", check);
    }

    // 算法列表
    public static void BuildModeRows(VerticalStackLayout host, IReadOnlyList<CipherModeInfo> modes,
        int selected, Action<int> onSelected, Label? detail, bool check = false)
    {
        var labels = modes.Select(m => m.Available ? m.Name : L10n.F("{0}（不可用）", m.Name)).ToList();
        var enabled = modes.Select(m => m.Available).ToList();
        BuildRows(host, labels, selected, i =>
        {
            if (detail is not null) detail.Text = ModeDetail(modes, i);
            onSelected(i);
        }, check, enabled);
        if (detail is not null && selected >= 0 && selected < modes.Count)
            detail.Text = ModeDetail(modes, selected);
    }

    private static string ModeDetail(IReadOnlyList<CipherModeInfo> modes, int index)
    {
        var m = modes[index];
        string text = m.Available
            ? L10n.F("{0}。{1}", m.ParamText, m.Note)
            : L10n.F("当前使用 {0}，{1}。{2}", m.Name, m.UnavailableReason, m.ParamText);
        var off = modes.Where(x => !x.Available)
            .Select(x => L10n.F("{0}（{1}）", x.Name, x.UnavailableReason)).ToList();
        if (off.Count > 0) text += L10n.T("\n不可用：") + string.Join(L10n.T("；"), off);
        return text;
    }

    // 短文本
    public static void BuildChips(FlexLayout host, IReadOnlyList<string> labels,
        int selected, Action<int> onSelected, bool check = false)
    {
        host.Children.Clear();
        var buttons = new List<Button>(labels.Count);
        for (int i = 0; i < labels.Count; i++)
        {
            int index = i;
            var b = new Button { Text = labels[i], Margin = new Thickness(0, 0, 8, 8) };
            b.Clicked += (_, _) => Select(buttons, labels, index, onSelected,
                "ChoiceChipSelected", "ChoiceChip", check);
            host.Children.Add(b);
            buttons.Add(b);
        }
        Apply(buttons, labels, selected, "ChoiceChipSelected", "ChoiceChip", check);
    }

    private static void Select(List<Button> buttons, IReadOnlyList<string> labels, int index,
        Action<int> onSelected, string onKey, string offKey, bool check)
    {
        if (!buttons[index].IsEnabled) return;   // 不可用项不改变
        Apply(buttons, labels, index, onKey, offKey, check);
        onSelected(index);
    }

    private static void Apply(List<Button> buttons, IReadOnlyList<string> labels,
        int selected, string onKey, string offKey, bool check)
    {
        Style? on = Res(onKey);
        Style? off = Res(offKey);
        for (int i = 0; i < buttons.Count; i++)
        {
            buttons[i].Style = i == selected ? on : off;
            if (check) buttons[i].Text = labels[i] + (i == selected ? L10n.T("（当前）") : "");
        }
    }

    private static Style? Res(string key)
        => Microsoft.Maui.Controls.Application.Current?.Resources.TryGetValue(key, out var v) == true
            ? v as Style
            : null;
}
