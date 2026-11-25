using EasyDump.Core.Detection;
using EasyDump.Core.Diagnostics;
using EasyDump.Core.Models;

namespace EasyDump.Core.Analysis.Generic;

/// <summary>
/// Best-effort analyzer for non-Unity executables and libraries (Unreal, Godot, native PE/ELF).
/// Extracts structural sections, exports, imports, and symbol tables where reliably present.
/// </summary>
public sealed class GenericBinaryAnalyzer : IGameAnalyzer
{
    public bool CanHandle(GameDetectionResult detection) =>
        detection.Engine is GameEngineType.UnrealEngine
            or GameEngineType.Godot
            or GameEngineType.NativePe
            or GameEngineType.NativeElf;

    public Task<AnalysisResult> AnalyzeAsync(
        GameDetectionResult detection,
        IProgress<AnalysisProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        return Task.Run(() => AnalyzeInternal(detection, progress, cancellationToken), cancellationToken);
    }

    private static AnalysisResult AnalyzeInternal(
        GameDetectionResult detection,
        IProgress<AnalysisProgress>? progress,
        CancellationToken cancellationToken)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var logger = new DiagnosticLogger();
        logger.AddRange(detection.Diagnostics);

        var targetPath = detection.PrimaryBinaryPath;
        if (string.IsNullOrWhiteSpace(targetPath) || !File.Exists(targetPath))
        {
            logger.Error("GenericAnalysis", "No primary executable or binary file was found to inspect.");
            sw.Stop();
            return new AnalysisResult
            {
                Detection = detection,
                AnalyzedAtUtc = DateTime.UtcNow,
                Duration = sw.Elapsed,
                Succeeded = false,
                ErrorMessage = "No analyzable binary file was found.",
                Diagnostics = logger.Snapshot()
            };
        }

        cancellationToken.ThrowIfCancellationRequested();
        progress?.Report(new AnalysisProgress("Inspecting Native Binary", $"Analyzing {Path.GetFileName(targetPath)}...", 40));

        var info = BinaryFormatDetector.InspectFile(targetPath);
        List<AssemblyEntry> assemblies = info.Format switch
        {
            BinaryFormatType.PE => PeBinaryInspector.Inspect(targetPath, logger),
            BinaryFormatType.Elf => ElfBinaryReader.Inspect(targetPath, logger),
            _ => new List<AssemblyEntry>()
        };

        if (assemblies.Count == 0)
        {
            logger.Warning("GenericAnalysis", $"No exportable symbols, sections, or managed metadata could be extracted from '{Path.GetFileName(targetPath)}'.");
        }

        sw.Stop();
        progress?.Report(new AnalysisProgress("Complete", $"Inspected {Path.GetFileName(targetPath)}.", 100));

        return new AnalysisResult
        {
            Detection = detection,
            AnalyzedAtUtc = DateTime.UtcNow,
            Duration = sw.Elapsed,
            Succeeded = assemblies.Count > 0,
            ErrorMessage = assemblies.Count == 0 ? "No symbols or sections could be parsed from this binary." : null,
            Assemblies = assemblies,
            Diagnostics = logger.Snapshot()
        };
    }
}
