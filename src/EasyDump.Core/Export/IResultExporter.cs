using EasyDump.Core.Models;

namespace EasyDump.Core.Export;

public sealed record ExportRequest(
    AnalysisResult Result,
    IReadOnlyList<AssemblyEntry> AssembliesToExport,
    ExportScope Scope,
    string? ScopeDescription = null);

public interface IResultExporter
{
    ExportFormat Format { get; }
    string FileExtension { get; }
    Task ExportAsync(ExportRequest request, string outputPath, CancellationToken cancellationToken = default);
    string RenderToString(ExportRequest request);
}
