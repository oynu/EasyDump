using System.Buffers.Binary;
using System.Text;
using EasyDump.Core.Analysis.Unity.Il2Cpp;
using EasyDump.Core.Detection;
using EasyDump.Core.Diagnostics;
using EasyDump.Core.Models;

namespace EasyDump.Tests;

public sealed class Il2CppMetadataTests : IDisposable
{
    private readonly string _tempRoot;

    public Il2CppMetadataTests()
    {
        _tempRoot = Path.Combine(Path.GetTempPath(), $"EasyDump_Il2CppTest_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempRoot);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempRoot, recursive: true); } catch { }
    }

    [Theory]
    [InlineData(24)]
    [InlineData(27)]
    [InlineData(29)]
    [InlineData(31)]
    public void DirectReaderParsesSyntheticMetadataAcrossVersions(int version)
    {
        byte[] metadata = BuildSyntheticGlobalMetadata(version);
        var validation = Il2CppMetadataValidator.Validate(metadata);

        Assert.True(validation.IsValid, validation.ErrorMessage);
        Assert.Equal(version, validation.Version);

        var logger = new DiagnosticLogger();
        var assemblies = Il2CppMetadataDirectReader.ReadMetadataOnly(
            metadata, "global-metadata.dat", "global-metadata.dat", logger);

        Assert.Single(assemblies);
        var asm = assemblies[0];
        Assert.Equal("Assembly-CSharp", asm.Name);
        Assert.Single(asm.Types);

        var type = asm.Types[0];
        Assert.Equal("Game.Core", type.Namespace);
        Assert.Equal("PlayerHealth", type.Name);
        Assert.Equal(0x02000002u, type.MetadataToken);

        Assert.Single(type.Fields);
        Assert.Equal("_currentHp", type.Fields[0].Name);
        Assert.Equal(ResolutionStatus.Unresolved, type.Fields[0].OverallStatus);
        Assert.Null(type.Fields[0].FieldOffset?.Value);

        Assert.Single(type.Methods);
        Assert.Equal("TakeDamage", type.Methods[0].Name);
        Assert.Equal("damage", type.Methods[0].ParametersSignature);
        Assert.Equal(ResolutionStatus.Unresolved, type.Methods[0].OverallStatus);
        Assert.Null(type.Methods[0].Rva?.Value);
    }

    [Fact]
    public async Task UnityVersionDetectsFromSerializedFileAndUnityFsAndIl2CppAnalyzerFallsBackGracefully()
    {
        string gameDir = Path.Combine(_tempRoot, "Il2CppSampleGame");
        string dataDir = Path.Combine(gameDir, "Il2CppSampleGame_Data");
        string metaDir = Path.Combine(dataDir, "il2cpp_data", "Metadata");
        Directory.CreateDirectory(metaDir);

        string metaPath = Path.Combine(metaDir, "global-metadata.dat");
        File.WriteAllBytes(metaPath, BuildSyntheticGlobalMetadata(29));

        // Verify UnityFS bundle version extraction
        string bundlePath = Path.Combine(dataDir, "data.unity3d");
        WriteUnityFsWithVersion(bundlePath, "2022.3.40f1");

        var (detectedVer, source) = UnityVersionDetector.Detect(gameDir);
        Assert.Equal("2022.3.40f1", detectedVer);
        Assert.Contains("UnityFS", source);

        // Detect & analyze metadata-only IL2CPP folder (no GameAssembly.dll present)
        var detector = new GameDetector();
        var detection = detector.Detect(gameDir);
        Assert.Equal(GameEngineType.UnityIl2Cpp, detection.Engine);
        Assert.Equal(29, detection.MetadataVersion);

        var analyzer = new UnityIl2CppAnalyzer();
        var result = await analyzer.AnalyzeAsync(detection);

        Assert.True(result.Succeeded);
        Assert.Contains(result.Diagnostics, d => d.Severity == DiagnosticSeverity.Warning);
        Assert.Single(result.Assemblies);
        Assert.Equal("PlayerHealth", result.Assemblies[0].Types[0].Name);
        // Never fabricates offsets without native binary
        Assert.Equal(0, result.ConfirmedOffsets);
        Assert.True(result.UnresolvedOffsets >= 2);
    }

    internal static void WriteSerializedFileWithVersion(string path, string unityVersion)
    {
        byte[] buf = new byte[256];
        BinaryPrimitives.WriteUInt32BigEndian(buf.AsSpan(0, 4), 100); // metadataSize
        BinaryPrimitives.WriteUInt32BigEndian(buf.AsSpan(4, 4), 256); // fileSize
        BinaryPrimitives.WriteUInt32BigEndian(buf.AsSpan(8, 4), 22);  // formatVersion 22
        BinaryPrimitives.WriteUInt32BigEndian(buf.AsSpan(12, 4), 128); // dataOffset
        Encoding.ASCII.GetBytes(unityVersion).CopyTo(buf, 0x30);
        File.WriteAllBytes(path, buf);
    }

    internal static void WriteUnityFsWithVersion(string path, string unityVersion)
    {
        using var ms = new MemoryStream();
        ms.Write("UnityFS\0"u8);
        byte[] ver = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(ver, 7);
        ms.Write(ver);
        ms.Write("5.x.x\0"u8);
        ms.Write(Encoding.ASCII.GetBytes(unityVersion));
        ms.WriteByte(0);
        ms.Write(new byte[32]);
        File.WriteAllBytes(path, ms.ToArray());
    }

    public static byte[] BuildSyntheticGlobalMetadata(int version)
    {
        // Build string pool
        var stringPool = new MemoryStream();
        int AddString(string s)
        {
            int idx = (int)stringPool.Position;
            stringPool.Write(Encoding.UTF8.GetBytes(s));
            stringPool.WriteByte(0);
            return idx;
        }

        AddString(""); // index 0 = empty
        int sAsm = AddString("Assembly-CSharp.dll");
        int sNs = AddString("Game.Core");
        int sType = AddString("PlayerHealth");
        int sField = AddString("_currentHp");
        int sMethod = AddString("TakeDamage");
        int sParam = AddString("damage");

        byte[] strings = stringPool.ToArray();

        int headerSize = 264; // plenty for all versions up to 31
        int stringOffset = headerSize;

        int imageSize = 40;
        int typeSize = version <= 24 ? 104 : 88;
        int fieldSize = version <= 24 ? 16 : 12;
        int methodSize = version <= 28 ? 48 : 44;
        int paramSize = version <= 24 ? 16 : 12;

        int imagesOffset = stringOffset + strings.Length;
        int typesOffset = imagesOffset + imageSize;
        int fieldsOffset = typesOffset + typeSize;
        int methodsOffset = fieldsOffset + fieldSize;
        int paramsOffset = methodsOffset + methodSize;
        int totalSize = paramsOffset + paramSize;

        byte[] data = new byte[totalSize];
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0, 4), Il2CppMetadataValidator.Magic);
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(4, 4), version);

        // stringOffset / size
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(24, 4), stringOffset);
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(28, 4), strings.Length);
        strings.CopyTo(data, stringOffset);

        // methodsOffset / size (header offset 48)
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(48, 4), methodsOffset);
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(52, 4), methodSize);

        // parametersOffset / size (header offset 88)
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(88, 4), paramsOffset);
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(92, 4), paramSize);

        // fieldsOffset / size (header offset 96)
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(96, 4), fieldsOffset);
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(100, 4), fieldSize);

        // typeDefinitionsOffset / size (header offset 160)
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(160, 4), typesOffset);
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(164, 4), typeSize);

        // imagesOffset / size (176 for <=24, 168 for >=27)
        int imgHdr = version <= 24 ? 176 : 168;
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(imgHdr, 4), imagesOffset);
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(imgHdr + 4, 4), imageSize);

        // Write ImageDefinition[0]
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(imagesOffset + 0, 4), sAsm);
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(imagesOffset + 8, 4), 0); // typeStart
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(imagesOffset + 12, 4), 1); // typeCount

        // Write TypeDefinition[0]
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(typesOffset + 0, 4), sType);
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(typesOffset + 4, 4), sNs);
        if (version <= 24)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(typesOffset + 44, 4), 0x00100001); // public class
            BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(typesOffset + 48, 4), 0); // fieldStart
            BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(typesOffset + 52, 4), 0); // methodStart
            BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(typesOffset + 80, 2), 1); // method_count
            BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(typesOffset + 84, 2), 1); // field_count
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(typesOffset + 100, 4), 0x02000002); // token
        }
        else
        {
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(typesOffset + 28, 4), 0x00100001);
            BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(typesOffset + 32, 4), 0); // fieldStart
            BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(typesOffset + 36, 4), 0); // methodStart
            BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(typesOffset + 64, 2), 1); // method_count
            BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(typesOffset + 68, 2), 1); // field_count
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(typesOffset + 84, 4), 0x02000002); // token
        }

        // Write FieldDefinition[0]
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(fieldsOffset + 0, 4), sField);
        int fTokenOff = version <= 24 ? 12 : 8;
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(fieldsOffset + fTokenOff, 4), 0x04000001);

        // Write MethodDefinition[0]
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(methodsOffset + 0, 4), sMethod);
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(methodsOffset + 12, 4), 0); // paramStart
        if (version <= 28)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(methodsOffset + 36, 4), 0x06000001);
            BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(methodsOffset + 40, 2), 0x0006); // public
            BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(methodsOffset + 46, 2), 1); // paramCount
        }
        else
        {
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(methodsOffset + 32, 4), 0x06000001);
            BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(methodsOffset + 36, 2), 0x0006); // public
            BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(methodsOffset + 42, 2), 1); // paramCount
        }

        // Write ParameterDefinition[0]
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(paramsOffset + 0, 4), sParam);

        return data;
    }
}
