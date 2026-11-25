using EasyDump.Core.Analysis.Unity.Mono;
using EasyDump.Core.Detection;
using EasyDump.Core.Models;

namespace EasyDump.Tests;

public sealed class MonoAnalyzerTests : IDisposable
{
    private readonly string _tempRoot;

    public MonoAnalyzerTests()
    {
        _tempRoot = Path.Combine(Path.GetTempPath(), $"EasyDump_MonoTest_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempRoot);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempRoot, recursive: true); } catch { }
    }

    [Fact]
    public async Task DetectsAndAnalyzesUnityMonoGameWithRealAssembly()
    {
        // Locate the real compiled Assembly-CSharp.dll produced by EasyDump.SampleMonoFixture
        string fixtureDll = Path.Combine(AppContext.BaseDirectory, "Assembly-CSharp.dll");
        Assert.True(File.Exists(fixtureDll), $"Expected test fixture assembly at {fixtureDll}");

        string gameDir = Path.Combine(_tempRoot, "MyUnityMonoGame");
        string dataDir = Path.Combine(gameDir, "MyUnityMonoGame_Data");
        string managedDir = Path.Combine(dataDir, "Managed");
        Directory.CreateDirectory(managedDir);
        Directory.CreateDirectory(Path.Combine(gameDir, "MonoBleedingEdge"));
        File.Copy(fixtureDll, Path.Combine(managedDir, "Assembly-CSharp.dll"));

        // Write a minimal SerializedFile header with Unity version 2021.3.16f1
        Il2CppMetadataTests.WriteSerializedFileWithVersion(Path.Combine(dataDir, "globalgamemanagers"), "2021.3.16f1");

        var detector = new GameDetector();
        var detection = detector.Detect(gameDir);

        Assert.Equal(GameEngineType.UnityMono, detection.Engine);
        Assert.Equal("MyUnityMonoGame", detection.GameName);
        Assert.Equal("2021.3.16f1", detection.UnityVersion);
        Assert.Equal(managedDir, detection.ManagedDirectoryPath);

        var analyzer = new UnityMonoAnalyzer();
        Assert.True(analyzer.CanHandle(detection));

        var result = await analyzer.AnalyzeAsync(detection);
        Assert.True(result.Succeeded);
        Assert.Single(result.Assemblies);

        var asm = result.Assemblies[0];
        Assert.Equal("Assembly-CSharp", asm.Name);
        Assert.False(asm.IsSystemOrEngine);

        // 1. Explicit [FieldOffset] struct must produce Confirmed field offsets
        var packetType = asm.Types.Single(t => t.Name == "PlayerStatsPacket");
        Assert.Equal("Struct", packetType.Kind);
        Assert.Equal(0x00UL, packetType.Fields.Single(f => f.Name == "Health").FieldOffset!.Value);
        Assert.Equal(ResolutionStatus.Confirmed, packetType.Fields.Single(f => f.Name == "Health").OverallStatus);
        Assert.Equal(0x08UL, packetType.Fields.Single(f => f.Name == "Speed").FieldOffset!.Value);
        Assert.Equal(0x10UL, packetType.Fields.Single(f => f.Name == "Experience").FieldOffset!.Value);

        // 2. Auto-layout Mono fields must NEVER fabricate offsets -> must be Unresolved
        var playerType = asm.Types.Single(t => t.Name == "PlayerController");
        var moveSpeed = playerType.Fields.Single(f => f.Name == "MoveSpeed");
        Assert.Null(moveSpeed.FieldOffset!.Value);
        Assert.Equal(ResolutionStatus.Unresolved, moveSpeed.OverallStatus);

        // 3. Concrete methods must have Confirmed RVA, VirtualAddress, and FileOffset
        var applyDamage = playerType.Methods.Single(m => m.Name == "ApplyDamage");
        Assert.Equal(ResolutionStatus.Confirmed, applyDamage.OverallStatus);
        Assert.NotNull(applyDamage.Rva?.Value);
        Assert.True(applyDamage.Rva!.Value > 0);
        Assert.NotNull(applyDamage.VirtualAddress?.Value);
        Assert.True(applyDamage.VirtualAddress!.Value > applyDamage.Rva.Value);
        Assert.NotNull(applyDamage.FileOffset?.Value);
        Assert.Contains("int amount, bool bypassArmor", applyDamage.ParametersSignature);

        // 4. Abstract methods must be honestly reported as Unresolved
        var entityBase = asm.Types.Single(t => t.Name == "EntityBase");
        var abstractTick = entityBase.Methods.Single(m => m.Name == "Tick");
        Assert.Equal(ResolutionStatus.Unresolved, abstractTick.OverallStatus);
        Assert.Null(abstractTick.Rva?.Value);

        // 5. Nested types are included
        Assert.Contains(asm.Types, t => t.Name == "InventorySlot");
    }
}
