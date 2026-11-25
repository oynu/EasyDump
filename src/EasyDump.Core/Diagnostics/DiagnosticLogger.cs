using EasyDump.Core.Models;

namespace EasyDump.Core.Diagnostics;

/// <summary>
/// Thread-safe structured diagnostic logger used across game detection,
/// binary validation, and offset extraction stages.
/// </summary>
public sealed class DiagnosticLogger
{
    private readonly object _gate = new();
    private readonly List<DiagnosticMessage> _messages = new();

    public void Info(string category, string message, string? details = null)
        => Log(DiagnosticSeverity.Info, category, message, details);

    public void Warning(string category, string message, string? details = null)
        => Log(DiagnosticSeverity.Warning, category, message, details);

    public void Error(string category, string message, string? details = null)
        => Log(DiagnosticSeverity.Error, category, message, details);

    public void Log(DiagnosticSeverity severity, string category, string message, string? details = null)
    {
        var entry = new DiagnosticMessage(DateTime.UtcNow, severity, category, message, details);
        lock (_gate)
        {
            _messages.Add(entry);
        }
    }

    public void AddRange(IEnumerable<DiagnosticMessage> messages)
    {
        lock (_gate)
        {
            _messages.AddRange(messages);
        }
    }

    public IReadOnlyList<DiagnosticMessage> Snapshot()
    {
        lock (_gate)
        {
            return _messages.ToArray();
        }
    }

    public string FormatReport()
    {
        var snapshot = Snapshot();
        return string.Join(Environment.NewLine, snapshot.Select(m => m.FormattedLine));
    }
}
