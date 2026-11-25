using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace EasyDump.Core.Detection;

public sealed record RunningProcessInfo(
    int ProcessId,
    string ProcessName,
    string WindowTitle,
    string ExecutablePath,
    string EngineHint,
    bool HasWindow,
    bool IsSystemPath)
{
    public string DisplayTitle => string.IsNullOrWhiteSpace(WindowTitle)
        ? ProcessName
        : $"{ProcessName} — {WindowTitle}";
}

/// <summary>
/// Safely enumerates running Windows processes and resolves their on-disk executable paths
/// using PROCESS_QUERY_LIMITED_INFORMATION without inspecting process memory.
/// </summary>
public static class RunningProcessService
{
    private const uint ProcessQueryLimitedInformation = 0x1000;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(
        IntPtr hProcess,
        uint dwFlags,
        StringBuilder lpExeName,
        ref int lpdwSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    public static IReadOnlyList<RunningProcessInfo> GetRunningProcesses()
    {
        var results = new List<RunningProcessInfo>();
        string windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        int selfPid = Environment.ProcessId;

        foreach (var proc in Process.GetProcesses())
        {
            try
            {
                if (proc.Id <= 4 || proc.Id == selfPid)
                    continue;

                string? exePath = TryGetExecutablePath(proc);
                if (string.IsNullOrWhiteSpace(exePath) || !File.Exists(exePath))
                    continue;

                bool isSystem = exePath.StartsWith(windowsDir, StringComparison.OrdinalIgnoreCase);
                string windowTitle = string.Empty;
                bool hasWindow = false;
                try
                {
                    windowTitle = proc.MainWindowTitle ?? string.Empty;
                    hasWindow = proc.MainWindowHandle != IntPtr.Zero && !string.IsNullOrWhiteSpace(windowTitle);
                }
                catch { }

                string engineHint = DetectQuickEngineHint(exePath);

                results.Add(new RunningProcessInfo(
                    proc.Id,
                    proc.ProcessName,
                    windowTitle,
                    exePath,
                    engineHint,
                    hasWindow,
                    isSystem));
            }
            catch
            {
                // Ignore inaccessible processes
            }
            finally
            {
                proc.Dispose();
            }
        }

        return results
            .OrderByDescending(p => p.EngineHint is "Unity IL2CPP" or "Unity Mono")
            .ThenByDescending(p => p.HasWindow)
            .ThenBy(p => p.IsSystemPath)
            .ThenBy(p => p.ProcessName, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static string? TryGetExecutablePath(Process proc)
    {
        IntPtr handle = OpenProcess(ProcessQueryLimitedInformation, false, proc.Id);
        if (handle != IntPtr.Zero)
        {
            try
            {
                var sb = new StringBuilder(1024);
                int size = sb.Capacity;
                if (QueryFullProcessImageName(handle, 0, sb, ref size) && size > 0)
                    return sb.ToString();
            }
            finally
            {
                CloseHandle(handle);
            }
        }

        try
        {
            return proc.MainModule?.FileName;
        }
        catch
        {
            return null;
        }
    }

    private static string DetectQuickEngineHint(string exePath)
    {
        try
        {
            string? dir = Path.GetDirectoryName(exePath);
            if (string.IsNullOrEmpty(dir)) return "Native";

            if (File.Exists(Path.Combine(dir, "GameAssembly.dll")))
                return "Unity IL2CPP";

            if (File.Exists(Path.Combine(dir, "UnityPlayer.dll")) ||
                Directory.Exists(Path.Combine(dir, "MonoBleedingEdge")))
                return "Unity Mono";

            string baseName = Path.GetFileNameWithoutExtension(exePath);
            string dataDir = Path.Combine(dir, $"{baseName}_Data");
            if (Directory.Exists(dataDir))
            {
                if (Directory.Exists(Path.Combine(dataDir, "il2cpp_data")))
                    return "Unity IL2CPP";
                if (Directory.Exists(Path.Combine(dataDir, "Managed")))
                    return "Unity Mono";
                return "Unity";
            }

            if (Directory.Exists(Path.Combine(dir, "Engine", "Binaries")) ||
                exePath.EndsWith("-Shipping.exe", StringComparison.OrdinalIgnoreCase))
                return "Unreal";

            if (File.Exists(Path.Combine(dir, $"{baseName}.pck")))
                return "Godot";
        }
        catch
        {
            // Ignore IO errors on protected directories
        }

        return string.Empty;
    }
}
