using Microsoft.Maui.Graphics;

namespace FileEncryptorMobile.Views;

// 二维码自绘
public sealed class QrDrawable : IDrawable
{
    private readonly bool[,]? _matrix;

    public QrDrawable(bool[,] matrix) => _matrix = matrix;

    public void Draw(ICanvas canvas, RectF dirtyRect)
    {
        canvas.FillColor = Colors.White;
        canvas.FillRectangle(dirtyRect.X, dirtyRect.Y, dirtyRect.Width, dirtyRect.Height);
        if (_matrix is null) return;
        int size = _matrix.GetLength(0);
        const int quiet = 4;
        float cell = Math.Min(dirtyRect.Width, dirtyRect.Height) / (size + 2 * quiet);
        float used = cell * (size + 2 * quiet);
        float ox = dirtyRect.X + (dirtyRect.Width - used) / 2 + quiet * cell;
        float oy = dirtyRect.Y + (dirtyRect.Height - used) / 2 + quiet * cell;
        canvas.FillColor = Colors.Black;
        // 按行合并连续深
        for (int y = 0; y < size; y++)
        {
            int x = 0;
            while (x < size)
            {
                if (!_matrix[y, x]) { x++; continue; }
                int start = x;
                while (x < size && _matrix[y, x]) x++;
                canvas.FillRectangle(ox + start * cell, oy + y * cell,
                    (x - start) * cell + 0.5f, cell + 0.5f);
            }
        }
    }
}
