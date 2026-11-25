using System.Text.Json;
using EasyDump.Core.Analysis;
using EasyDump.Core.Export;
using EasyDump.Core.Models;

namespace EasyDump.Tests;

public sealed class ExporterAndCacheTests : IDisposable
{
    private readonly string _tempRoot;

    public ExporterAndCacheTests()
    {
        _tempRoot = Path.Combine(Path.GetTempPath(), $"EasyDump_ExportCacheTest_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempRoot);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempRoot, recursive: true); } catch { }
    }

    [Fact]
    public async Task ExportersProduceValidJsonTxtAndCsv()
    {
        var result = CreateSampleResult();
        var req = new ExportRequest(result, result.Assemblies, ExportScope.All);

        // JSON
        string jsonPath = Path.Combine(_tempRoot, "dump.json");
        await new JsonResultExporter().ExportAsync(req, jsonPath);
        using var doc = JsonDocument.Parse(await File.ReadAllTextAsync(jsonPath));
        Assert.Equal("EasyDump", doc.RootElement.GetProperty("tool").GetString());
        Assert.Equal("2022.3.40f1", doc.RootElement.GetProperty("game").GetProperty("unityVersion").GetString());
        var firstField = doc.RootElement.GetProperty("assemblies")[0].GetProperty("types")[0].GetProperty("fields")[0];
        Assert.Equal("0x18", firstField.GetProperty("fieldOffset").GetString());

        // TXT
        string txtPath = Path.Combine(_tempRoot, "dump.txt");
        await new TxtResultExporter().ExportAsync(req, txtPath);
        string txt = await File.ReadAllTextAsync(txtPath);
        Assert.Contains("EasyDump Offset Report", txt);
        Assert.Contains("Offset: 0x18", txt);
        Assert.Contains("[Confirmed]", txt);
        Assert.Contains("RVA: 0x00123400", txt);

        // CSV (including RFC 4180 comma/quote escaping in Notes)
        string csvPath = Path.Combine(_tempRoot, "dump.csv");
        await new CsvResultExporter().ExportAsync(req, csvPath);
        string csv = await File.ReadAllTextAsync(csvPath);
        Assert.Contains("Assembly,Namespace,Type,MemberKind", csv);
        Assert.Contains("\"Note with, comma and \"\"quotes\"\"\"", csv);
    }

    [Fact]
    public async Task OrchestratorCachesUnchangedFilesAndInvalidatesOnChange()
    {
        string fixtureDll = Path.Combine(AppContext.BaseDirectory, "Assembly-CSharp.dll");
        string gameDir = Path.Combine(_tempRoot, "CachedMonoGame");
        string managedDir = Path.Combine(gameDir, "CachedMonoGame_Data", "Managed");
        Directory.CreateDirectory(managedDir);
        string targetDll = Path.Combine(managedDir, "Assembly-CSharp.dll");
        File.Copy(fixtureDll, targetDll);

        var orchestrator = new AnalysisOrchestrator();
        var detection = orchestrator.Detect(gameDir);

        var first = await orchestrator.AnalyzeAsync(detection);
        Assert.True(first.Succeeded);
        Assert.False(first.FromCache);

        var second = await orchestrator.AnalyzeAsync(detection);
        Assert.True(second.Succeeded);
        Assert.True(second.FromCache);

        // Touch file write time -> cache must miss
        File.SetLastWriteTimeUtc(targetDll, DateTime.UtcNow.AddSeconds(5));
        var detection2 = orchestrator.Detect(gameDir);
        var third = await orchestrator.AnalyzeAsync(detection2);
        Assert.True(third.Succeeded);
        Assert.False(third.FromCache);
    }

    private static AnalysisResult CreateSampleResult()
    {
        var field = new FieldEntry
        {
            Name = "health",
            FieldType = "int",
            Modifiers = "public",
            MetadataToken = 0x04000001,
            FieldOffset = OffsetValue.Confirmed(OffsetKind.FieldOffset, 0x18, "GameAssembly.dll", "IL2CPP MetadataRegistration"),
            OverallStatus = ResolutionStatus.Confirmed,
            Confidence = ConfidenceLevel.High,
            SourceFile = "GameAssembly.dll",
            ExtractionMethod = "IL2CPP MetadataRegistration",
            Notes = "Note with, comma and \"quotes\""
        };

        var method = new MethodEntry
        {
            Name = "Respawn",
            ReturnType = "void",
            ParametersSignature = "bool resetScore",
            Modifiers = "public",
            MetadataToken = 0x06000002,
            Rva = OffsetValue.Confirmed(OffsetKind.MethodRva, 0x00123400, "GameAssembly.dll", "CodeGenModule"),
            VirtualAddress = OffsetValue.Confirmed(OffsetKind.MethodVirtualAddress, 0x180123400, "GameAssembly.dll", "CodeGenModule"),
            FileOffset = OffsetValue.Confirmed(OffsetKind.MethodFileOffset, 0x00122800, "GameAssembly.dll", "PE Map"),
            OverallStatus = ResolutionStatus.Confirmed,
            Confidence = ConfidenceLevel.High,
            SourceFile = "GameAssembly.dll",
            ExtractionMethod = "CodeGenModule"
        };

        var type = new TypeEntry
        {
            AssemblyName = "Assembly-CSharp",
            Namespace = "Game",
            Name = "Player",
            FullName = "Game.Player",
            Kind = "Class",
            MetadataToken = 0x02000002,
            Fields = new[] { field },
            Methods = new[] { method }
        };

        var asm = new AssemblyEntry
        {
            Name = "Assembly-CSharp",
            SourcePath = "GameAssembly.dll",
            Types = new[] { type }
        };

        return new AnalysisResult
        {
            Detection = new GameDetectionResult
            {
                GameName = "SampleGame",
                Engine = GameEngineType.UnityIl2Cpp,
                UnityVersion = "2022.3.40f1",
                Architecture = ArchitectureType.X64,
                MetadataVersion = 29
            },
            AnalyzedAtUtc = DateTime.UtcNow,
            Duration = TimeSpan.FromMilliseconds(250),
            Assemblies = new[] { asm }
        };
    }
}
