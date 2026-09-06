using System.Drawing;
using System.Windows.Forms;

namespace FileEncryptorGUI
{
    // RadioButton / CheckBox that support a fully transparent background so they
    // blend with the glass card behind them (no solid rectangle), keeping just
    // the text and the circle / check glyph.
    public class TransRadioButton : RadioButton
    {
        public TransRadioButton()
        {
            SetStyle(ControlStyles.SupportsTransparentBackColor, true);
            BackColor = Color.Transparent;
        }
    }

    public class TransCheckBox : CheckBox
    {
        public TransCheckBox()
        {
            SetStyle(ControlStyles.SupportsTransparentBackColor, true);
            BackColor = Color.Transparent;
        }
    }
}
