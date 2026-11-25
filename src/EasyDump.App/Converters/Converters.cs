using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using EasyDump.Core.Models;

namespace EasyDump.App.Converters;

public sealed class BoolToVisibilityConverter : IValueConverter
{
    public bool Invert { get; set; }

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        bool b = value is bool flag && flag;
        if (Invert) b = !b;
        return b ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

public sealed class NullToVisibilityConverter : IValueConverter
{
    public bool Invert { get; set; }

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        bool hasValue = value is string s ? !string.IsNullOrWhiteSpace(s) : value is not null;
        if (Invert) hasValue = !hasValue;
        return hasValue ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

public sealed class StatusToBrushConverter : IValueConverter
{
    public bool IsBackground { get; set; }

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var status = value is ResolutionStatus rs ? rs : ResolutionStatus.Unresolved;
        if (IsBackground)
        {
            return status switch
            {
                ResolutionStatus.Confirmed => (Brush)Application.Current.FindResource("BrushConfirmedBg"),
                ResolutionStatus.Partial => (Brush)Application.Current.FindResource("BrushPartialBg"),
                _ => (Brush)Application.Current.FindResource("BrushUnresolvedBg")
            };
        }

        return status switch
        {
            ResolutionStatus.Confirmed => (Brush)Application.Current.FindResource("BrushConfirmed"),
            ResolutionStatus.Partial => (Brush)Application.Current.FindResource("BrushPartial"),
            _ => (Brush)Application.Current.FindResource("BrushUnresolved")
        };
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

public sealed class DiagnosticSeverityBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var sev = value is DiagnosticSeverity s ? s : DiagnosticSeverity.Info;
        return sev switch
        {
            DiagnosticSeverity.Error => (Brush)Application.Current.FindResource("BrushError"),
            DiagnosticSeverity.Warning => (Brush)Application.Current.FindResource("BrushPartial"),
            _ => (Brush)Application.Current.FindResource("BrushAccent")
        };
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
