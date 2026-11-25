using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using EasyDump.Core.Detection;

namespace EasyDump.App;

public partial class ProcessPickerWindow : Window
{
    private const int DwmwaUseImmersiveDarkMode = 20;

    [DllImport("dwmapi.dll", PreserveSig = true)]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);

    private IReadOnlyList<RunningProcessInfo> _allProcesses = Array.Empty<RunningProcessInfo>();

    public RunningProcessInfo? SelectedProcess { get; private set; }

    public ProcessPickerWindow()
    {
        InitializeComponent();
        SourceInitialized += (_, _) =>
        {
            try
            {
                var hwnd = new WindowInteropHelper(this).Handle;
                if (hwnd != IntPtr.Zero)
                {
                    int useDark = 1;
                    DwmSetWindowAttribute(hwnd, DwmwaUseImmersiveDarkMode, ref useDark, sizeof(int));
                }
            }
            catch { }
        };
        Loaded += async (_, _) => await LoadProcessesAsync();
    }

    private async Task LoadProcessesAsync()
    {
        CountText.Text = "Scanning running processes...";
        _allProcesses = await Task.Run(RunningProcessService.GetRunningProcesses);
        ApplyFilter();
    }

    private void ApplyFilter()
    {
        string q = SearchBox.Text.Trim();
        bool showWindows = ShowSystemToggle.IsChecked == true;

        var filtered = _allProcesses.Where(p =>
        {
            if (!showWindows && p.IsSystemPath)
                return false;

            if (string.IsNullOrEmpty(q))
                return true;

            return p.ProcessName.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                   p.WindowTitle.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                   p.ExecutablePath.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                   p.ProcessId.ToString().Contains(q, StringComparison.Ordinal);
        }).ToList();

        ProcessGrid.ItemsSource = filtered;
        CountText.Text = $"{filtered.Count} process(es) shown";
        SelectBtn.IsEnabled = ProcessGrid.SelectedItem is RunningProcessInfo;
    }

    private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        SearchPlaceholder.Visibility = string.IsNullOrEmpty(SearchBox.Text)
            ? Visibility.Visible
            : Visibility.Collapsed;
        ApplyFilter();
    }

    private void FilterToggle_Changed(object sender, RoutedEventArgs e) => ApplyFilter();

    private async void Refresh_Click(object sender, RoutedEventArgs e) => await LoadProcessesAsync();

    private void ProcessGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        SelectBtn.IsEnabled = ProcessGrid.SelectedItem is RunningProcessInfo;
    }

    private void ProcessGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (ProcessGrid.SelectedItem is RunningProcessInfo info)
        {
            SelectedProcess = info;
            DialogResult = true;
        }
    }

    private void Select_Click(object sender, RoutedEventArgs e)
    {
        if (ProcessGrid.SelectedItem is RunningProcessInfo info)
        {
            SelectedProcess = info;
            DialogResult = true;
        }
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
    }
}
