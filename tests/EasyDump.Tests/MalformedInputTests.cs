using System.Buffers.Binary;
using EasyDump.Core.Analysis;
using EasyDump.Core.Analysis.Unity.Il2Cpp;
using EasyDump.Core.Detection;
using EasyDump.Core.Models;

namespace EasyDump.Tests;

public sealed class MalformedInputTests : IDisposable
{
    private readonly string _tempRoot;

    public MalformedInputTests()
    {
        _tempRoot = Path.Combine(Path.GetTempPath(), $"EasyDump_MalformedTest_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempRoot);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempRoot, recursive: true); } catch { }
    }

    [Fact]
    public void RejectsEncryptedOrScrambledGlobalMetadataWithoutCrashing()
    {
        byte[] garbage = new byte[512];
        BinaryPrimitives.WriteUInt32LittleEndian(garbage, 0xDEADBEEF);

        var validation = Il2CppMetadataValidator.Validate(garbage);
        Assert.False(validation.IsValid);
        Assert.Contains("0xFAB11BAF", validation.ErrorMessage);
    }

    [Fact]
    public void RejectsOutOfBoundsMetadataTables()
    {
        byte[] data = new byte[256];
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0, 4), Il2CppMetadataValidator.Magic);
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(4, 4), 29);
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(24, 4), 200);
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(28, 4), 5000); // exceeds file length

        var validation = Il2CppMetadataValidator.Validate(data);
        Assert.False(validation.IsValid);
        Assert.Contains("exceeds file size", validation.ErrorMessage);
    }

    [Fact]
    public async Task HandlesTruncatedPeAndElfAndEmptyDirectoryGracefully()
    {
        var orchestrator = new AnalysisOrchestrator();

        // 1. Empty directory
        string emptyDir = Path.Combine(_tempRoot, "EmptyGame");
        Directory.CreateDirectory(emptyDir);
        var emptyDetect = orchestrator.Detect(emptyDir);
        Assert.Equal(GameEngineType.Unknown, emptyDetect.Engine);
        var emptyResult = await orchestrator.AnalyzeAsync(emptyDetect);
        Assert.False(emptyResult.Succeeded);

        // 2. Truncated PE
        string badPe = Path.Combine(_tempRoot, "broken.exe");
        File.WriteAllBytes(badPe, new byte[] { (byte)'M', (byte)'Z', 0x90, 0x00, 0x03 });
        var peDetect = orchestrator.Detect(badPe);
        var peResult = await orchestrator.AnalyzeAsync(peDetect);
        Assert.False(peResult.Succeeded);

        // 3. Truncated ELF
        string badElf = Path.Combine(_tempRoot, "broken.so");
        File.WriteAllBytes(badElf, new byte[] { 0x7F, (byte)'E', (byte)'L', (byte)'F', 2, 1, 1 });
        var elfDetect = orchestrator.Detect(badElf);
        var elfResult = await orchestrator.AnalyzeAsync(elfDetect);
        Assert.False(elfResult.Succeeded);
    }
}
