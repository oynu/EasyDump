using EasyDump.Core.Models;

namespace EasyDump.Core.Analysis;

public interface IGameAnalyzer
{
    bool CanHandle(GameDetectionResult detection);

    Task<AnalysisResult> AnalyzeAsync(
        GameDetectionResult detection,
        IProgress<AnalysisProgress>? progress = null,
        CancellationToken cancellationToken = default);
}
