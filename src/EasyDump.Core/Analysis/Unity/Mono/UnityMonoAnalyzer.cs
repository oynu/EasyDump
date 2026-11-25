using System.Text;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE;
using AsmResolver.PE.DotNet.Metadata;
using AsmResolver.PE.DotNet.Metadata.Tables;
using AsmResolver.PE.File;
using EasyDump.Core.Diagnostics;
using EasyDump.Core.Models;
using ResolutionStatus = EasyDump.Core.Models.ResolutionStatus;

namespace EasyDump.Core.Analysis.Unity.Mono;

/// <summary>
/// Inspects managed .NET / Unity Mono assemblies safely using AsmResolver without
/// executing or loading assemblies into the host CLR.
/// </summary>
public sealed class UnityMonoAnalyzer : IGameAnalyzer
{
    private static readonly string[] SystemOrEnginePrefixes =
    {
        "System", "mscorlib", "netstandard", "Mono.", "Microsoft.",
        "UnityEngine", "Unity.", "UnityEngine.", "Bee.", "ICSharpCode.", "Newtonsoft."
    };

    public bool CanHandle(GameDetectionResult detection) =>
        detection.Engine is GameEngineType.UnityMono or GameEngineType.DotNetStandalone;

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

        var assemblyPaths = CollectAssemblyPaths(detection, logger);
        if (assemblyPaths.Count == 0)
        {
            logger.Error("MonoAnalysis", "No managed assemblies (.dll/.exe) were found to analyze.");
            sw.Stop();
            return new AnalysisResult
            {
                Detection = detection,
                AnalyzedAtUtc = DateTime.UtcNow,
                Duration = sw.Elapsed,
                Succeeded = false,
                ErrorMessage = "No managed assemblies were found in the selected game or Managed directory.",
                Diagnostics = logger.Snapshot()
            };
        }

        var assemblies = new List<AssemblyEntry>(assemblyPaths.Count);
        for (int i = 0; i < assemblyPaths.Count; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            string path = assemblyPaths[i];
            string fileName = Path.GetFileName(path);
            double pct = 10.0 + (85.0 * i / assemblyPaths.Count);
            progress?.Report(new AnalysisProgress(
                "Inspecting Managed Assemblies",
                $"Parsing {fileName} ({i + 1}/{assemblyPaths.Count})...",
                pct));

            var entry = InspectSingleAssembly(path, logger);
            if (entry is not null)
                assemblies.Add(entry);
        }

        // Order game assemblies first, then system/engine assemblies alphabetically
        var ordered = assemblies
            .OrderBy(a => a.IsSystemOrEngine)
            .ThenBy(a => a.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

        sw.Stop();
        progress?.Report(new AnalysisProgress("Complete", $"Parsed {ordered.Count} managed assemblies.", 100));

        return new AnalysisResult
        {
            Detection = detection,
            AnalyzedAtUtc = DateTime.UtcNow,
            Duration = sw.Elapsed,
            Succeeded = ordered.Count > 0,
            ErrorMessage = ordered.Count == 0 ? "None of the detected files could be parsed as valid .NET/Mono assemblies." : null,
            Assemblies = ordered,
            Diagnostics = logger.Snapshot()
        };
    }

    public static AssemblyEntry? InspectSingleAssembly(string path, DiagnosticLogger logger)
    {
        string fileName = Path.GetFileName(path);
        try
        {
            byte[] bytes;
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                bytes = new byte[fs.Length];
                fs.ReadExactly(bytes);
            }

            var peFile = PEFile.FromBytes(bytes);
            var peImage = PEImage.FromFile(peFile);
            if (peImage.DotNetDirectory is null)
            {
                logger.Info("MonoAnalysis", $"Skipped native (non-managed) DLL: {fileName}.");
                return null;
            }

            var module = ModuleDefinition.FromImage(peImage);
            ulong imageBase = peFile.OptionalHeader.ImageBase;
            var tablesStream = peImage.DotNetDirectory.Metadata?.GetStream<TablesStream>();
            var methodTable = tablesStream?.GetTable<MethodDefinitionRow>(TableIndex.Method);
            var fieldRvaTable = tablesStream?.GetTable<FieldRvaRow>(TableIndex.FieldRva);

            var fieldRvaByRid = new Dictionary<uint, uint>();
            if (fieldRvaTable is not null)
            {
                foreach (var row in fieldRvaTable)
                    fieldRvaByRid[row.Field] = row.Data.Rva;
            }

            string asmName = module.Assembly?.Name ?? Path.GetFileNameWithoutExtension(fileName);
            bool isSystem = IsSystemOrEngineAssembly(asmName);

            var typeEntries = new List<TypeEntry>();
            foreach (var type in module.GetAllTypes())
            {
                if (type.Name == "<Module>" && type.Fields.Count == 0 && type.Methods.Count == 0)
                    continue;

                var fields = new List<FieldEntry>(type.Fields.Count);
                foreach (var field in type.Fields)
                {
                    fields.Add(BuildFieldEntry(field, fileName, fieldRvaByRid));
                }

                var methods = new List<MethodEntry>(type.Methods.Count);
                foreach (var method in type.Methods)
                {
                    methods.Add(BuildMethodEntry(method, fileName, peFile, imageBase, methodTable));
                }

                string kind = type.IsEnum ? "Enum"
                    : type.IsValueType ? "Struct"
                    : type.IsInterface ? "Interface"
                    : "Class";

                typeEntries.Add(new TypeEntry
                {
                    AssemblyName = asmName,
                    Namespace = type.Namespace?.Value ?? string.Empty,
                    Name = type.Name?.Value ?? "<unnamed>",
                    FullName = type.FullName,
                    Kind = kind,
                    BaseType = type.BaseType?.FullName,
                    MetadataToken = type.MetadataToken.ToUInt32(),
                    IsSystemOrEngine = isSystem,
                    Fields = fields,
                    Methods = methods
                });
            }

            return new AssemblyEntry
            {
                Name = asmName,
                SourcePath = path,
                IsSystemOrEngine = isSystem,
                Types = typeEntries
            };
        }
        catch (Exception ex)
        {
            logger.Warning("MonoAnalysis", $"Failed to parse managed assembly '{fileName}': {ex.Message}");
            return null;
        }
    }

    private static FieldEntry BuildFieldEntry(
        FieldDefinition field,
        string sourceFile,
        Dictionary<uint, uint> fieldRvaByRid)
    {
        var modifiers = FormatFieldModifiers(field);
        string typeName = FormatTypeSignature(field.Signature?.FieldType);
        string? constValue = field.Constant is not null ? FormatConstant(field.Constant) : null;
        uint token = field.MetadataToken.ToUInt32();
        uint rid = field.MetadataToken.Rid;

        OffsetValue? fieldOffset = null;
        OffsetValue? fieldRva = null;
        ResolutionStatus status;
        ConfidenceLevel confidence;
        string methodUsed;
        string? notes = null;

        if (field.FieldOffset.HasValue)
        {
            fieldOffset = OffsetValue.Confirmed(
                OffsetKind.FieldOffset,
                (ulong)field.FieldOffset.Value,
                sourceFile,
                "CLI FieldLayout ([FieldOffset])",
                ConfidenceLevel.High);
            status = ResolutionStatus.Confirmed;
            confidence = ConfidenceLevel.High;
            methodUsed = "CLI FieldLayout ([FieldOffset])";
        }
        else if (fieldRvaByRid.TryGetValue(rid, out uint rva) && rva != 0)
        {
            fieldRva = OffsetValue.Confirmed(
                OffsetKind.FieldRva,
                rva,
                sourceFile,
                "CLI FieldRVA Table",
                ConfidenceLevel.High);
            status = ResolutionStatus.Confirmed;
            confidence = ConfidenceLevel.High;
            methodUsed = "CLI FieldRVA Table";
        }
        else if (field.IsLiteral)
        {
            notes = "Compile-time constant literal; stored in CLI Constant table rather than an instance memory offset.";
            fieldOffset = OffsetValue.Unresolved(
                OffsetKind.FieldOffset,
                sourceFile,
                "CLI Metadata",
                notes);
            status = ResolutionStatus.Unresolved;
            confidence = ConfidenceLevel.None;
            methodUsed = "CLI Constant Metadata";
        }
        else
        {
            notes = "Mono instance/static field offsets are assigned by the Mono runtime/JIT at load time unless [StructLayout(LayoutKind.Explicit)] is present.";
            fieldOffset = OffsetValue.Unresolved(
                OffsetKind.FieldOffset,
                sourceFile,
                "CLI Metadata (Auto/Sequential Layout)",
                notes);
            status = ResolutionStatus.Unresolved;
            confidence = ConfidenceLevel.None;
            methodUsed = "CLI Metadata";
        }

        return new FieldEntry
        {
            Name = field.Name?.Value ?? "<unnamed>",
            FieldType = typeName,
            Modifiers = modifiers,
            IsStatic = field.IsStatic,
            IsConst = field.IsLiteral,
            ConstantValue = constValue,
            MetadataToken = token,
            FieldOffset = fieldOffset,
            FieldRva = fieldRva,
            OverallStatus = status,
            Confidence = confidence,
            SourceFile = sourceFile,
            ExtractionMethod = methodUsed,
            Notes = notes
        };
    }

    private static MethodEntry BuildMethodEntry(
        MethodDefinition method,
        string sourceFile,
        PEFile peFile,
        ulong imageBase,
        MetadataTable<MethodDefinitionRow>? methodTable)
    {
        uint token = method.MetadataToken.ToUInt32();
        uint rid = method.MetadataToken.Rid;

        uint rva = 0;
        if (methodTable is not null && rid >= 1 && rid <= methodTable.Count)
        {
            rva = methodTable.GetByRid(rid).Body.Rva;
        }

        string retType = FormatTypeSignature(method.Signature?.ReturnType);
        string paramSig = FormatParameters(method);
        string modifiers = FormatMethodModifiers(method);

        OffsetValue rvaVal;
        OffsetValue vaVal;
        OffsetValue fileOffsetVal;
        ResolutionStatus status;
        ConfidenceLevel confidence;
        string extractionMethod = "PE/CLI MethodDef Table";
        string? notes = null;

        if (rva != 0)
        {
            rvaVal = OffsetValue.Confirmed(OffsetKind.MethodRva, rva, sourceFile, extractionMethod);
            vaVal = OffsetValue.Confirmed(OffsetKind.MethodVirtualAddress, imageBase + rva, sourceFile, extractionMethod);

            ulong fileOffset = 0;
            bool mapped = false;
            try
            {
                fileOffset = peFile.RvaToFileOffset(rva);
                mapped = true;
            }
            catch
            {
                mapped = false;
            }

            fileOffsetVal = mapped
                ? OffsetValue.Confirmed(OffsetKind.MethodFileOffset, fileOffset, sourceFile, "PE Section RvaToFileOffset")
                : OffsetValue.Unresolved(OffsetKind.MethodFileOffset, sourceFile, "PE Section RvaToFileOffset", "RVA did not map to a raw PE section.");

            status = mapped ? ResolutionStatus.Confirmed : ResolutionStatus.Partial;
            confidence = ConfidenceLevel.High;
        }
        else
        {
            notes = method.IsAbstract
                ? "Abstract or interface method; no static CIL body RVA."
                : method.IsInternalCall
                    ? "Mono InternalCall (implemented natively inside Mono/UnityPlayer)."
                    : method.IsPInvokeImpl
                        ? "P/Invoke extern method; body resides in an external native library."
                        : "Method has RVA 0 in CLI MethodDef table (no CIL body).";

            rvaVal = OffsetValue.Unresolved(OffsetKind.MethodRva, sourceFile, extractionMethod, notes);
            vaVal = OffsetValue.Unresolved(OffsetKind.MethodVirtualAddress, sourceFile, extractionMethod, notes);
            fileOffsetVal = OffsetValue.Unresolved(OffsetKind.MethodFileOffset, sourceFile, extractionMethod, notes);
            status = ResolutionStatus.Unresolved;
            confidence = ConfidenceLevel.None;
        }

        return new MethodEntry
        {
            Name = method.Name?.Value ?? "<unnamed>",
            ReturnType = retType,
            ParametersSignature = paramSig,
            Modifiers = modifiers,
            IsStatic = method.IsStatic,
            IsVirtual = method.IsVirtual,
            MetadataToken = token,
            Rva = rvaVal,
            VirtualAddress = vaVal,
            FileOffset = fileOffsetVal,
            OverallStatus = status,
            Confidence = confidence,
            SourceFile = sourceFile,
            ExtractionMethod = extractionMethod,
            Notes = notes
        };
    }

    private static List<string> CollectAssemblyPaths(GameDetectionResult detection, DiagnosticLogger logger)
    {
        var paths = new List<string>();
        if (!string.IsNullOrWhiteSpace(detection.ManagedDirectoryPath) && Directory.Exists(detection.ManagedDirectoryPath))
        {
            try
            {
                paths.AddRange(Directory.EnumerateFiles(detection.ManagedDirectoryPath, "*.dll", SearchOption.TopDirectoryOnly));
            }
            catch (Exception ex)
            {
                logger.Error("MonoAnalysis", $"Failed to enumerate Managed directory: {ex.Message}");
            }
        }
        else if (!string.IsNullOrWhiteSpace(detection.PrimaryBinaryPath) && File.Exists(detection.PrimaryBinaryPath))
        {
            paths.Add(detection.PrimaryBinaryPath);
        }

        return paths.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    public static bool IsSystemOrEngineAssembly(string name)
    {
        foreach (var prefix in SystemOrEnginePrefixes)
        {
            if (name.Equals(prefix.TrimEnd('.'), StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    private static string FormatTypeSignature(TypeSignature? sig)
    {
        if (sig is null) return "void";
        return sig.FullName switch
        {
            "System.Void" => "void",
            "System.Boolean" => "bool",
            "System.Byte" => "byte",
            "System.SByte" => "sbyte",
            "System.Int16" => "short",
            "System.UInt16" => "ushort",
            "System.Int32" => "int",
            "System.UInt32" => "uint",
            "System.Int64" => "long",
            "System.UInt64" => "ulong",
            "System.Single" => "float",
            "System.Double" => "double",
            "System.String" => "string",
            "System.Object" => "object",
            "System.Char" => "char",
            "System.IntPtr" => "nint",
            _ => sig.FullName
        };
    }

    private static string FormatParameters(MethodDefinition method)
    {
        if (method.Parameters.Count == 0)
            return string.Empty;

        var sb = new StringBuilder();
        for (int i = 0; i < method.Parameters.Count; i++)
        {
            if (i > 0) sb.Append(", ");
            var p = method.Parameters[i];
            sb.Append(FormatTypeSignature(p.ParameterType));
            if (!string.IsNullOrWhiteSpace(p.Name))
            {
                sb.Append(' ');
                sb.Append(p.Name);
            }
        }
        return sb.ToString();
    }

    private static string FormatFieldModifiers(FieldDefinition f)
    {
        var parts = new List<string>(4);
        if (f.IsPublic) parts.Add("public");
        else if (f.IsPrivate) parts.Add("private");
        else if (f.IsFamily) parts.Add("protected");
        else if (f.IsAssembly) parts.Add("internal");

        if (f.IsLiteral) parts.Add("const");
        else
        {
            if (f.IsStatic) parts.Add("static");
            if (f.IsInitOnly) parts.Add("readonly");
        }
        return string.Join(' ', parts);
    }

    private static string FormatMethodModifiers(MethodDefinition m)
    {
        var parts = new List<string>(4);
        if (m.IsPublic) parts.Add("public");
        else if (m.IsPrivate) parts.Add("private");
        else if (m.IsFamily) parts.Add("protected");
        else if (m.IsAssembly) parts.Add("internal");

        if (m.IsStatic) parts.Add("static");
        if (m.IsAbstract) parts.Add("abstract");
        else if (m.IsVirtual) parts.Add("virtual");
        if (m.IsPInvokeImpl) parts.Add("extern");
        return string.Join(' ', parts);
    }

    private static string FormatConstant(Constant constant)
    {
        try
        {
            var val = constant.InterpretData();
            return val switch
            {
                null => "null",
                string s => $"\"{s}\"",
                _ => val.ToString() ?? string.Empty
            };
        }
        catch
        {
            return "<blob>";
        }
    }
}
