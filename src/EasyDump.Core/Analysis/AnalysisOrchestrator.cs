using System.Security.Cryptography;
using System.Text;
using EasyDump.Core.Analysis.Generic;
using EasyDump.Core.Analysis.Unity.Il2Cpp;
using EasyDump.Core.Analysis.Unity.Mono;
using EasyDump.Core.Detection;
using EasyDump.Core.Diagnostics;
using EasyDump.Core.Models;

namespace EasyDump.Core.Analysis;

public interface IAnalysisOrchestrator
{
    GameDetectionResult Detect(string inputPath);

    Task<AnalysisResult> AnalyzeAsync(
        GameDetectionResult detection,
        bool forceReanalyze = false,
        IProgress<AnalysisProgress>? progress = null,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Coordinates game detection, input fingerprinting (to avoid rescanning unchanged files),
/// and dispatching to the appropriate modular engine analyzer.
/// </summary>
public sealed class AnalysisOrchestrator : IAnalysisOrchestrator
{
    private readonly GameDetector _detector;
    private readonly IReadOnlyList<IGameAnalyzer> _analyzers;
    private readonly Dictionary<string, AnalysisResult> _cache = new(StringComparer.Ordinal);
    private readonly object _cacheGate = new();

    public AnalysisOrchestrator()
        : this(
            new GameDetector(),
            new IGameAnalyzer[]
            {
                new UnityIl2CppAnalyzer(),
                new UnityMonoAnalyzer(),
                new GenericBinaryAnalyzer()
            })
    {
    }

    public AnalysisOrchestrator(GameDetector detector, IReadOnlyList<IGameAnalyzer> analyzers)
    {
        _detector = detector;
        _analyzers = analyzers;
    }

    public GameDetectionResult Detect(string inputPath) => _detector.Detect(inputPath);

    public async Task<AnalysisResult> AnalyzeAsync(
        GameDetectionResult detection,
        bool forceReanalyze = false,
        IProgress<AnalysisProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        progress?.Report(new AnalysisProgress("Preparing", "Checking file fingerprints...", 5));

        string fingerprint = ComputeFingerprint(detection);
        if (!forceReanalyze)
        {
            lock (_cacheGate)
            {
                if (_cache.TryGetValue(fingerprint, out var cached))
                {
                    progress?.Report(new AnalysisProgress("Complete", "Loaded unchanged results from cache.", 100));
                    return cached with { FromCache = true };
                }
            }
        }

        var analyzer = _analyzers.FirstOrDefault(a => a.CanHandle(detection));
        if (analyzer is null)
        {
            var logger = new DiagnosticLogger();
            logger.AddRange(detection.Diagnostics);
            logger.Error("Orchestrator", $"No analyzer supports detected engine '{detection.Engine}'.");
            return new AnalysisResult
            {
                Detection = detection,
                AnalyzedAtUtc = DateTime.UtcNow,
                Duration = TimeSpan.Zero,
                InputFingerprint = fingerprint,
                Succeeded = false,
                ErrorMessage = $"Unsupported or unrecognized game format ({detection.Engine}).",
                Diagnostics = logger.Snapshot()
            };
        }

        var result = await analyzer.AnalyzeAsync(detection, progress, cancellationToken).ConfigureAwait(false);
        result = result with { InputFingerprint = fingerprint, FromCache = false };

        if (result.Succeeded)
        {
            lock (_cacheGate)
            {
                // Keep cache bounded to 8 recent targets to keep memory minimal
                if (_cache.Count >= 8)
                    _cache.Clear();
                _cache[fingerprint] = result;
            }
        }

        return result;
    }

    public static string ComputeFingerprint(GameDetectionResult detection)
    {
        var sb = new StringBuilder();
        sb.Append(detection.Engine).Append('|');
        sb.Append(detection.PrimaryBinaryPath ?? string.Empty).Append('|');
        sb.Append(detection.MetadataPath ?? string.Empty).Append('|');
        sb.Append(detection.ManagedDirectoryPath ?? string.Empty).Append('|');

        foreach (var file in detection.Files.OrderBy(f => f.Path, StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                var fi = new FileInfo(file.Path);
                if (fi.Exists)
                {
                    sb.Append(fi.FullName).Append(':')
                      .Append(fi.Length).Append(':')
                      .Append(fi.LastWriteTimeUtc.Ticks).Append(';');
                }
            }
            catch
            {
                sb.Append(file.Path).Append(':').Append(file.SizeBytes).Append(';');
            }
        }

        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(sb.ToString()));
        return Convert.ToHexString(hash);
    }
}
