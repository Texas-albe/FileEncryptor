using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace FileEncryptorGUI.Models;

public class SelectablePath : INotifyPropertyChanged
{
    private string _path = "";
    private bool _isSelected = true;

    public string Path
    {
        get => _path;
        set { _path = value; OnPropertyChanged(); }
    }

    public bool IsSelected
    {
        get => _isSelected;
        set { _isSelected = value; OnPropertyChanged(); }
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
