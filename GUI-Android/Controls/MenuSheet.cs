// 深色选项列表
using FileEncryptorMobile.Services;

namespace FileEncryptorMobile.Controls;

public sealed class MenuSheet : Grid
{
    private readonly VerticalStackLayout _rows = new() { Spacing = 0 };
    private readonly Label _title = new()
    {
        FontSize = 14,
        Margin = new Thickness(20, 16, 20, 8),
        LineBreakMode = LineBreakMode.TailTruncation,
        MaxLines = 2,
    };
    private readonly Border _card;
    private TaskCompletionSource<string?>? _tcs;

    public bool IsOpen => _tcs is not null;

    public MenuSheet()
    {
        IsVisible = false;
        var scrim = new Grid { BackgroundColor = Microsoft.Maui.Graphics.Color.FromArgb("#99000000") };
        var back = new TapGestureRecognizer();
        back.Tapped += (_, _) => Cancel();
        scrim.GestureRecognizers.Add(back);
        Children.Add(scrim);
        _card = new Border
        {
            Padding = 0,
            StrokeShape = new Microsoft.Maui.Controls.Shapes.RoundRectangle { CornerRadius = 16 },
            Margin = new Thickness(8, 8, 8, 12),
            VerticalOptions = LayoutOptions.End,
            HorizontalOptions = LayoutOptions.Fill,
            Content = new VerticalStackLayout { Spacing = 0, Children = { _title, _rows } },
        };
        Children.Add(_card);
    }

    // 打开列表
    public Task<string?> ShowAsync(string? title, string cancel, string? danger, params string[] actions)
    {
        Cancel();
        bool dark = Application.Current?.RequestedTheme.ToString() == "Dark";
        var fg = dark ? Microsoft.Maui.Graphics.Color.FromArgb("#F1F3F6")
                      : Microsoft.Maui.Graphics.Color.FromArgb("#1B1F24");
        var line = dark ? Microsoft.Maui.Graphics.Color.FromArgb("#2C333C")
                        : Microsoft.Maui.Graphics.Color.FromArgb("#E8EBF0");
        var card = dark ? Microsoft.Maui.Graphics.Color.FromArgb("#222529")
                        : Microsoft.Maui.Graphics.Colors.White;
        var muted = dark ? Microsoft.Maui.Graphics.Color.FromArgb("#A6AEBA")
                         : Microsoft.Maui.Graphics.Color.FromArgb("#5B6472");
        var dangerFg = dark ? Microsoft.Maui.Graphics.Color.FromArgb("#F4B0B6")
                            : Microsoft.Maui.Graphics.Color.FromArgb("#8A1E24");
        _card.BackgroundColor = card;
        _card.Stroke = line;
        _title.TextColor = muted;
        _title.Text = title ?? "";
        _title.IsVisible = !string.IsNullOrEmpty(title);
        _rows.Children.Clear();
        var all = actions.Append(cancel).ToList();
        for (int i = 0; i < all.Count; i++)
        {
            string act = all[i];
            bool isCancel = i == all.Count - 1;
            var row = new Grid
            {
                HeightRequest = 54,
                Padding = new Thickness(20, 0),
                BackgroundColor = card,
            };
            row.Children.Add(new Label
            {
                Text = act,
                FontSize = 16,
                TextColor = !isCancel && act == danger ? dangerFg : fg,
                FontAttributes = isCancel ? FontAttributes.Bold : FontAttributes.None,
                VerticalOptions = LayoutOptions.Center,
                HorizontalOptions = LayoutOptions.Start,
            });
            var tap = new TapGestureRecognizer { CommandParameter = act };
            tap.Tapped += (_, e) => Close(isCancel ? null : e.Parameter as string);
            row.GestureRecognizers.Add(tap);
            _rows.Children.Add(row);
            if (!isCancel)
                _rows.Children.Add(new BoxView
                {
                    HeightRequest = 1,
                    Color = line,
                    Margin = new Thickness(20, 0, 0, 0),
                });
        }
        _tcs = new TaskCompletionSource<string?>();
        UiFx.Reveal(this);
        return _tcs.Task;
    }

    public void Cancel() => Close(null);

    private void Close(string? value)
    {
        var tcs = _tcs;
        if (tcs is null) return;
        _tcs = null;
        UiFx.Hide(this);
        tcs.TrySetResult(value);
    }
}
