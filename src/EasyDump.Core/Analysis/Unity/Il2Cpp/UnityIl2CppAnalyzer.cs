using System.Reflection;
using System.Text;
using AssetRipper.Primitives;
using EasyDump.Core.Diagnostics;
using EasyDump.Core.Models;
using LibCpp2IL;
using LibCpp2IL.Logging;
using LibCpp2IL.Metadata;
using LibCpp2IL.Reflection;

namespace EasyDump.Core.Analysis.Unity.Il2Cpp;

/// <summary>
/// Analyzes Unity IL2CPP games using AssetRipper.LibCpp2IL when both global-metadata.dat
/// and a native binary (GameAssembly.dll / libil2cpp.so) are available, with automatic
/// fallback to metadata-only parsing when the binary is absent or registration fails.
/// </summary>
public sealed class UnityIl2CppAnalyzer : IGameAnalyzer
{
    private static readonly SemaphoreSlim LibCpp2IlGate = new(1, 1);

    public bool CanHandle(GameDetectionResult detection) =>
        detection.Engine == GameEngineType.UnityIl2Cpp;

    public async Task<AnalysisResult> AnalyzeAsync(
        GameDetectionResult detection,
        IProgress<AnalysisProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        return await Task.Run(() => AnalyzeInternal(detection, progress, cancellationToken), cancellationToken)
            .ConfigureAwait(false);
    }

    private static AnalysisResult AnalyzeInternal(
        GameDetectionResult detection,
        IProgress<AnalysisProgress>? progress,
        CancellationToken cancellationToken)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var logger = new DiagnosticLogger();
        logger.AddRange(detection.Diagnostics);

        if (string.IsNullOrWhiteSpace(detection.MetadataPath) || !File.Exists(detection.MetadataPath))
        {
            logger.Error("IL2CPP", "global-metadata.dat was not found. IL2CPP metadata cannot be extracted without global-metadata.dat.");
            sw.Stop();
            return new AnalysisResult
            {
                Detection = detection,
                AnalyzedAtUtc = DateTime.UtcNow,
                Duration = sw.Elapsed,
                Succeeded = false,
                ErrorMessage = "global-metadata.dat is required for Unity IL2CPP analysis.",
                Diagnostics = logger.Snapshot()
            };
        }

        progress?.Report(new AnalysisProgress("Validating Metadata", "Reading and validating global-metadata.dat...", 10));

        byte[] metadataBytes;
        using (var fs = new FileStream(detection.MetadataPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
        {
            metadataBytes = new byte[fs.Length];
            fs.ReadExactly(metadataBytes);
        }

        var validation = Il2CppMetadataValidator.Validate(metadataBytes);
        if (!validation.IsValid)
        {
            logger.Error("IL2CPP", validation.ErrorMessage ?? "Invalid global-metadata.dat.");
            sw.Stop();
            return new AnalysisResult
            {
                Detection = detection,
                AnalyzedAtUtc = DateTime.UtcNow,
                Duration = sw.Elapsed,
                Succeeded = false,
                ErrorMessage = validation.ErrorMessage,
                Diagnostics = logger.Snapshot()
            };
        }

        if (validation.WarningMessage is not null)
            logger.Warning("IL2CPP", validation.WarningMessage);

        var unityVersion = ResolveUnityVersion(detection.UnityVersion, validation.Version, logger);
        string metadataFileName = Path.GetFileName(detection.MetadataPath);

        // If native binary is missing, fall back cleanly to metadata-only extraction
        if (string.IsNullOrWhiteSpace(detection.PrimaryBinaryPath) || !File.Exists(detection.PrimaryBinaryPath))
        {
            logger.Warning("IL2CPP", "No native IL2CPP binary (GameAssembly.dll / libil2cpp.so) is present. Extracting metadata symbols only; native offsets will be marked Unresolved.");
            progress?.Report(new AnalysisProgress("Parsing Metadata Only", "Extracting classes, fields, and methods from global-metadata.dat...", 45));

            var metaOnlyAssemblies = ReadMetadataOnlyWithFallback(
                metadataBytes, unityVersion, metadataFileName, detection.MetadataPath, logger);

            sw.Stop();
            progress?.Report(new AnalysisProgress("Complete", $"Extracted {metaOnlyAssemblies.Count} assemblies (metadata only).", 100));

            return new AnalysisResult
            {
                Detection = detection,
                AnalyzedAtUtc = DateTime.UtcNow,
                Duration = sw.Elapsed,
                Succeeded = metaOnlyAssemblies.Count > 0,
                ErrorMessage = metaOnlyAssemblies.Count == 0 ? "Failed to parse metadata from global-metadata.dat." : null,
                Assemblies = metaOnlyAssemblies,
                Diagnostics = logger.Snapshot()
            };
        }

        progress?.Report(new AnalysisProgress("Loading Native Binary", $"Reading {Path.GetFileName(detection.PrimaryBinaryPath)}...", 25));

        byte[] binaryBytes;
        using (var fs = new FileStream(detection.PrimaryBinaryPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
        {
            binaryBytes = new byte[fs.Length];
            fs.ReadExactly(binaryBytes);
        }

        string binaryFileName = Path.GetFileName(detection.PrimaryBinaryPath);
        List<AssemblyEntry>? resolvedAssemblies = null;

        LibCpp2IlGate.Wait(cancellationToken);
        var previousWriter = LibLogger.Writer;
        try
        {
            LibLogger.Writer = new DiagnosticLogWriter(logger);
            progress?.Report(new AnalysisProgress("Resolving Registrations", "Locating CodeRegistration & MetadataRegistration in native binary...", 45));

            var context = LibCpp2IlMain.InitializeAsContext(binaryBytes, metadataBytes, unityVersion);
            if (context?.Metadata?.imageDefinitions is not null)
            {
                progress?.Report(new AnalysisProgress("Extracting Offsets", "Extracting classes, field offsets, and method addresses...", 70));
                resolvedAssemblies = ExtractFromContext(context, binaryFileName, detection.PrimaryBinaryPath, cancellationToken);
                logger.Info("IL2CPP", $"LibCpp2IL resolved {resolvedAssemblies.Count} assemblies (metadata v{context.Metadata.MetadataVersion}).");
            }
            else
            {
                logger.Warning("IL2CPP", "LibCpp2IL returned an empty context for this binary.");
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            logger.Warning("IL2CPP", $"Native registration resolution failed ({ex.Message}). Falling back to metadata-only extraction so symbols are still available.");
        }
        finally
        {
            LibLogger.Writer = previousWriter;
            LibCpp2IlGate.Release();
        }

        if (resolvedAssemblies is null || resolvedAssemblies.Count == 0)
        {
            progress?.Report(new AnalysisProgress("Fallback Metadata Parse", "Reading metadata tables directly from global-metadata.dat...", 80));
            resolvedAssemblies = ReadMetadataOnlyWithFallback(
                metadataBytes, unityVersion, metadataFileName, detection.MetadataPath, logger);
        }

        var ordered = resolvedAssemblies
            .OrderBy(a => a.IsSystemOrEngine)
            .ThenBy(a => a.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

        sw.Stop();
        progress?.Report(new AnalysisProgress("Complete", $"Extracted {ordered.Count} IL2CPP assemblies.", 100));

        return new AnalysisResult
        {
            Detection = detection,
            AnalyzedAtUtc = DateTime.UtcNow,
            Duration = sw.Elapsed,
            Succeeded = ordered.Count > 0,
            ErrorMessage = ordered.Count == 0 ? "Could not extract any types from the supplied IL2CPP files." : null,
            Assemblies = ordered,
            Diagnostics = logger.Snapshot()
        };
    }

    private static List<AssemblyEntry> ExtractFromContext(
        LibCpp2IlContext context,
        string binaryFileName,
        string binaryPath,
        CancellationToken cancellationToken)
    {
        var metadata = context.Metadata;
        var binary = context.Binary;
        var images = metadata.imageDefinitions;
        var assemblies = new List<AssemblyEntry>(images.Length);

        foreach (var image in images)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string rawName = image.Name ?? "UnknownAssembly";
            string asmName = rawName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
                ? rawName[..^4]
                : rawName;

            bool isSystem = Mono.UnityMonoAnalyzer.IsSystemOrEngineAssembly(asmName);
            var imageTypes = image.Types ?? Array.Empty<Il2CppTypeDefinition>();
            var typeEntries = new List<TypeEntry>(imageTypes.Length);

            foreach (var typeDef in imageTypes)
            {
                string typeName = typeDef.Name ?? "<unnamed>";
                if (typeName == "<Module>" && (typeDef.Fields?.Length ?? 0) == 0 && (typeDef.Methods?.Length ?? 0) == 0)
                    continue;

                string ns = typeDef.Namespace ?? string.Empty;
                string fullName = typeDef.FullName ?? (string.IsNullOrEmpty(ns) ? typeName : $"{ns}.{typeName}");

                var fields = ExtractFields(typeDef, binaryFileName);
                var methods = ExtractMethods(typeDef, binary, binaryFileName);

                string kind = typeDef.IsEnumType ? "Enum"
                    : typeDef.IsValueType ? "Struct"
                    : typeDef.IsInterface ? "Interface"
                    : "Class";

                typeEntries.Add(new TypeEntry
                {
                    AssemblyName = asmName,
                    Namespace = ns,
                    Name = typeName,
                    FullName = fullName,
                    Kind = kind,
                    BaseType = SafeTypeName(typeDef.BaseType),
                    MetadataToken = typeDef.Token,
                    IsSystemOrEngine = isSystem,
                    Fields = fields,
                    Methods = methods
                });
            }

            assemblies.Add(new AssemblyEntry
            {
                Name = asmName,
                SourcePath = binaryPath,
                IsSystemOrEngine = isSystem,
                Types = typeEntries
            });
        }

        return assemblies;
    }

    private static List<FieldEntry> ExtractFields(Il2CppTypeDefinition typeDef, string binaryFileName)
    {
        Il2CppFieldReflectionData[]? fieldInfos = null;
        try
        {
            fieldInfos = typeDef.FieldInfos;
        }
        catch
        {
            // Fall back to Raw Fields if reflection cache fails on an edge-case generic/corrupt field
        }

        if (fieldInfos is not null)
        {
            var list = new List<FieldEntry>(fieldInfos.Length);
            foreach (var fi in fieldInfos)
            {
                var field = fi.Field;
                var attrs = fi.Attributes;
                bool isStatic = (attrs & FieldAttributes.Static) != 0;
                bool isConst = (attrs & FieldAttributes.Literal) != 0;
                string modifiers = FormatFieldAttributes(attrs);
                string fieldType = SafeFieldType(field);
                string? constVal = fi.DefaultValue?.ToString();

                OffsetValue fieldOffset;
                ResolutionStatus status;
                ConfidenceLevel confidence;
                string method;
                string? notes = null;

                if (isConst)
                {
                    notes = "Compile-time constant literal; does not occupy an instance struct offset.";
                    fieldOffset = OffsetValue.Unresolved(OffsetKind.FieldOffset, binaryFileName, "IL2CPP Metadata", notes);
                    status = ResolutionStatus.Unresolved;
                    confidence = ConfidenceLevel.None;
                    method = "IL2CPP Metadata (Literal Constant)";
                }
                else if (fi.FieldOffset >= 0)
                {
                    method = isStatic
                        ? "IL2CPP MetadataRegistration.fieldOffsets (Static Field Block)"
                        : "IL2CPP MetadataRegistration.fieldOffsets";

                    fieldOffset = OffsetValue.Confirmed(
                        OffsetKind.FieldOffset,
                        (ulong)fi.FieldOffset,
                        binaryFileName,
                        method,
                        ConfidenceLevel.High,
                        isStatic ? "Offset within this type's IL2CPP static_fields struct." : null);
                    status = ResolutionStatus.Confirmed;
                    confidence = ConfidenceLevel.High;
                    if (isStatic)
                        notes = "Offset within this type's IL2CPP static_fields struct.";
                }
                else
                {
                    notes = "Field offset was not present in MetadataRegistration.fieldOffsets (possibly stripped or zero-sized).";
                    method = "IL2CPP MetadataRegistration.fieldOffsets";
                    fieldOffset = OffsetValue.Unresolved(OffsetKind.FieldOffset, binaryFileName, method, notes);
                    status = ResolutionStatus.Unresolved;
                    confidence = ConfidenceLevel.None;
                }

                list.Add(new FieldEntry
                {
                    Name = field?.Name ?? "<unnamed>",
                    FieldType = fieldType,
                    Modifiers = modifiers,
                    IsStatic = isStatic,
                    IsConst = isConst,
                    ConstantValue = constVal,
                    MetadataToken = field?.token,
                    FieldOffset = fieldOffset,
                    OverallStatus = status,
                    Confidence = confidence,
                    SourceFile = binaryFileName,
                    ExtractionMethod = method,
                    Notes = notes
                });
            }
            return list;
        }

        // Fallback to raw Il2CppFieldDefinition[] without FieldInfos
        var rawFields = typeDef.Fields ?? Array.Empty<Il2CppFieldDefinition>();
        var rawAttrs = typeDef.FieldAttributes ?? Array.Empty<FieldAttributes>();
        var fallbackList = new List<FieldEntry>(rawFields.Length);
        for (int i = 0; i < rawFields.Length; i++)
        {
            var f = rawFields[i];
            var attrs = i < rawAttrs.Length ? rawAttrs[i] : default;
            const string note = "Field reflection offset unavailable for this type.";
            fallbackList.Add(new FieldEntry
            {
                Name = f.Name ?? "<unnamed>",
                FieldType = SafeFieldType(f),
                Modifiers = FormatFieldAttributes(attrs),
                IsStatic = (attrs & FieldAttributes.Static) != 0,
                IsConst = (attrs & FieldAttributes.Literal) != 0,
                MetadataToken = f.token,
                FieldOffset = OffsetValue.Unresolved(OffsetKind.FieldOffset, binaryFileName, "IL2CPP Metadata", note),
                OverallStatus = ResolutionStatus.Unresolved,
                Confidence = ConfidenceLevel.None,
                SourceFile = binaryFileName,
                ExtractionMethod = "IL2CPP Metadata",
                Notes = note
            });
        }
        return fallbackList;
    }

    private static List<MethodEntry> ExtractMethods(
        Il2CppTypeDefinition typeDef,
        Il2CppBinary binary,
        string binaryFileName)
    {
        var methods = typeDef.Methods ?? Array.Empty<Il2CppMethodDefinition>();
        var list = new List<MethodEntry>(methods.Length);

        foreach (var m in methods)
        {
            ulong va = 0;
            ulong rva = 0;
            long fileOffset = -1;

            try
            {
                va = m.MethodPointer;
                if (va != 0)
                {
                    rva = m.Rva;
                    if (rva == 0)
                    {
                        try { rva = binary.GetRva(va); } catch { }
                    }
                    fileOffset = m.MethodOffsetInFile;
                    if (fileOffset < 0)
                    {
                        try
                        {
                            if (binary.TryMapVirtualAddressToRaw(va, out long mapped))
                                fileOffset = mapped;
                        }
                        catch { }
                    }
                }
            }
            catch
            {
                va = 0;
            }

            string retType = SafeReturnType(m);
            string paramSig = FormatParameters(m);
            string modifiers = FormatMethodAttributes(m.Attributes);

            OffsetValue rvaVal;
            OffsetValue vaVal;
            OffsetValue fileVal;
            ResolutionStatus status;
            ConfidenceLevel confidence;
            string extractionMethod = "IL2CPP CodeGenModule.methodPointers";
            string? notes = null;

            if (va != 0)
            {
                vaVal = OffsetValue.Confirmed(OffsetKind.MethodVirtualAddress, va, binaryFileName, extractionMethod);
                rvaVal = rva != 0
                    ? OffsetValue.Confirmed(OffsetKind.MethodRva, rva, binaryFileName, extractionMethod)
                    : OffsetValue.Unresolved(OffsetKind.MethodRva, binaryFileName, extractionMethod, "Could not compute RVA from VA.");
                fileVal = fileOffset >= 0
                    ? OffsetValue.Confirmed(OffsetKind.MethodFileOffset, (ulong)fileOffset, binaryFileName, "Binary VA-to-Raw Mapping")
                    : OffsetValue.Unresolved(OffsetKind.MethodFileOffset, binaryFileName, "Binary VA-to-Raw Mapping", "Virtual address did not map to a raw file section.");

                status = (rva != 0 && fileOffset >= 0) ? ResolutionStatus.Confirmed : ResolutionStatus.Partial;
                confidence = ConfidenceLevel.High;
            }
            else
            {
                notes = (m.Attributes & MethodAttributes.Abstract) != 0
                    ? "Abstract or interface method; no direct native implementation pointer."
                    : typeDef.GenericContainer is not null || m.GenericContainer is not null
                        ? "Generic method definition; concrete native implementations exist only for closed generic instantiations."
                        : "Native method pointer was 0 in CodeRegistration (unreferenced/stripped or unresolved).";

                vaVal = OffsetValue.Unresolved(OffsetKind.MethodVirtualAddress, binaryFileName, extractionMethod, notes);
                rvaVal = OffsetValue.Unresolved(OffsetKind.MethodRva, binaryFileName, extractionMethod, notes);
                fileVal = OffsetValue.Unresolved(OffsetKind.MethodFileOffset, binaryFileName, extractionMethod, notes);
                status = ResolutionStatus.Unresolved;
                confidence = ConfidenceLevel.None;
            }

            list.Add(new MethodEntry
            {
                Name = m.Name ?? "<unnamed>",
                ReturnType = retType,
                ParametersSignature = paramSig,
                Modifiers = modifiers,
                IsStatic = m.IsStatic,
                IsVirtual = (m.Attributes & MethodAttributes.Virtual) != 0,
                MetadataToken = m.token,
                Rva = rvaVal,
                VirtualAddress = vaVal,
                FileOffset = fileVal,
                OverallStatus = status,
                Confidence = confidence,
                SourceFile = binaryFileName,
                ExtractionMethod = extractionMethod,
                Notes = notes
            });
        }

        return list;
    }

    private static List<AssemblyEntry> ReadMetadataOnlyWithFallback(
        byte[] metadataBytes,
        UnityVersion unityVersion,
        string metadataFileName,
        string metadataPath,
        DiagnosticLogger logger)
    {
        // Try LibCpp2IL's Il2CppMetadata.ReadFrom first (handles v21..v31+ including variable-width types),
        // then fall back to our pure-C# direct reader if needed.
        try
        {
            var meta = Il2CppMetadata.ReadFrom(metadataBytes, unityVersion);
            if (meta?.imageDefinitions is not null && meta.imageDefinitions.Length > 0)
            {
                var assemblies = new List<AssemblyEntry>(meta.imageDefinitions.Length);
                const string note = "Metadata-only extraction (no resolved native binary); runtime field offsets and native method addresses cannot be determined from global-metadata.dat alone.";
                foreach (var img in meta.imageDefinitions)
                {
                    string rawName = img.Name ?? "UnknownAssembly";
                    string asmName = rawName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
                        ? rawName[..^4]
                        : rawName;
                    bool isSystem = Mono.UnityMonoAnalyzer.IsSystemOrEngineAssembly(asmName);

                    var types = new List<TypeEntry>();
                    foreach (var td in img.Types ?? Array.Empty<Il2CppTypeDefinition>())
                    {
                        string tName = td.Name ?? "<unnamed>";
                        if (tName == "<Module>" && (td.Fields?.Length ?? 0) == 0 && (td.Methods?.Length ?? 0) == 0)
                            continue;

                        string ns = td.Namespace ?? string.Empty;
                        var fields = (td.Fields ?? Array.Empty<Il2CppFieldDefinition>())
                            .Select((f, idx) => new FieldEntry
                            {
                                Name = f.Name ?? $"field_{idx}",
                                FieldType = SafeFieldType(f),
                                Modifiers = td.FieldAttributes is not null && idx < td.FieldAttributes.Length
                                    ? FormatFieldAttributes(td.FieldAttributes[idx])
                                    : string.Empty,
                                MetadataToken = f.token,
                                FieldOffset = OffsetValue.Unresolved(OffsetKind.FieldOffset, metadataFileName, "global-metadata.dat (Metadata Only)", note),
                                OverallStatus = ResolutionStatus.Unresolved,
                                Confidence = ConfidenceLevel.None,
                                SourceFile = metadataFileName,
                                ExtractionMethod = "global-metadata.dat (Metadata Only)",
                                Notes = note
                            }).ToList();

                        var methods = (td.Methods ?? Array.Empty<Il2CppMethodDefinition>())
                            .Select(m => new MethodEntry
                            {
                                Name = m.Name ?? "<unnamed>",
                                ReturnType = SafeReturnType(m),
                                ParametersSignature = FormatParameters(m),
                                Modifiers = FormatMethodAttributes(m.Attributes),
                                IsStatic = m.IsStatic,
                                IsVirtual = (m.Attributes & MethodAttributes.Virtual) != 0,
                                MetadataToken = m.token,
                                Rva = OffsetValue.Unresolved(OffsetKind.MethodRva, metadataFileName, "global-metadata.dat (Metadata Only)", note),
                                VirtualAddress = OffsetValue.Unresolved(OffsetKind.MethodVirtualAddress, metadataFileName, "global-metadata.dat (Metadata Only)", note),
                                FileOffset = OffsetValue.Unresolved(OffsetKind.MethodFileOffset, metadataFileName, "global-metadata.dat (Metadata Only)", note),
                                OverallStatus = ResolutionStatus.Unresolved,
                                Confidence = ConfidenceLevel.None,
                                SourceFile = metadataFileName,
                                ExtractionMethod = "global-metadata.dat (Metadata Only)",
                                Notes = note
                            }).ToList();

                        types.Add(new TypeEntry
                        {
                            AssemblyName = asmName,
                            Namespace = ns,
                            Name = tName,
                            FullName = string.IsNullOrEmpty(ns) ? tName : $"{ns}.{tName}",
                            Kind = td.IsEnumType ? "Enum" : td.IsValueType ? "Struct" : td.IsInterface ? "Interface" : "Class",
                            MetadataToken = td.Token,
                            IsSystemOrEngine = isSystem,
                            Fields = fields,
                            Methods = methods
                        });
                    }

                    assemblies.Add(new AssemblyEntry
                    {
                        Name = asmName,
                        SourcePath = metadataPath,
                        IsSystemOrEngine = isSystem,
                        Types = types
                    });
                }

                logger.Info("IL2CPP", $"Parsed {assemblies.Count} assemblies via Il2CppMetadata.ReadFrom (metadata-only mode).");
                return assemblies;
            }
        }
        catch (Exception ex)
        {
            logger.Warning("IL2CPP", $"LibCpp2IL metadata-only reader threw ({ex.Message}); trying direct bounds-checked parser.");
        }

        return Il2CppMetadataDirectReader.ReadMetadataOnly(metadataBytes, metadataFileName, metadataPath, logger);
    }

    private static UnityVersion ResolveUnityVersion(string? detectedVersion, int metadataVersion, DiagnosticLogger logger)
    {
        if (!string.IsNullOrWhiteSpace(detectedVersion) &&
            UnityVersion.TryParse(detectedVersion, out var parsed, out _))
        {
            return parsed;
        }

        // Map metadata version to a representative Unity version when UnityPlayer.dll/globalgamemanagers is absent
        var inferred = metadataVersion switch
        {
            >= 31 => new UnityVersion(6000, 0, 0),
            >= 29 => new UnityVersion(2022, 3, 0),
            >= 27 => new UnityVersion(2021, 3, 0),
            24 => new UnityVersion(2019, 4, 0),
            _ => new UnityVersion(2018, 4, 0)
        };

        logger.Info("IL2CPP", $"Exact Unity version was not detected on disk; inferred representative version {inferred} from metadata v{metadataVersion}.");
        return inferred;
    }

    private static string? SafeTypeName(Il2CppTypeReflectionData? data)
    {
        try { return data?.ToString(); }
        catch { return null; }
    }

    private static string SafeFieldType(Il2CppFieldDefinition? field)
    {
        if (field is null) return "object";
        try { return field.FieldType?.ToString() ?? "object"; }
        catch { return "<unresolved-type>"; }
    }

    private static string SafeReturnType(Il2CppMethodDefinition m)
    {
        try { return m.ReturnType?.ToString() ?? "void"; }
        catch { return "<unresolved-type>"; }
    }

    private static string FormatParameters(Il2CppMethodDefinition m)
    {
        try
        {
            var ps = m.Parameters;
            if (ps is null || ps.Length == 0) return string.Empty;
            var sb = new StringBuilder();
            for (int i = 0; i < ps.Length; i++)
            {
                if (i > 0) sb.Append(", ");
                sb.Append(ps[i].Type?.ToString() ?? "object");
                if (!string.IsNullOrWhiteSpace(ps[i].ParameterName))
                {
                    sb.Append(' ');
                    sb.Append(ps[i].ParameterName);
                }
            }
            return sb.ToString();
        }
        catch
        {
            return string.Empty;
        }
    }

    private static string FormatFieldAttributes(FieldAttributes attrs)
    {
        var parts = new List<string>(4);
        var access = attrs & FieldAttributes.FieldAccessMask;
        if (access == FieldAttributes.Public) parts.Add("public");
        else if (access == FieldAttributes.Private) parts.Add("private");
        else if (access == FieldAttributes.Family) parts.Add("protected");
        else if (access == FieldAttributes.Assembly) parts.Add("internal");

        if ((attrs & FieldAttributes.Literal) != 0) parts.Add("const");
        else
        {
            if ((attrs & FieldAttributes.Static) != 0) parts.Add("static");
            if ((attrs & FieldAttributes.InitOnly) != 0) parts.Add("readonly");
        }
        return string.Join(' ', parts);
    }

    private static string FormatMethodAttributes(MethodAttributes attrs)
    {
        var parts = new List<string>(4);
        var access = attrs & MethodAttributes.MemberAccessMask;
        if (access == MethodAttributes.Public) parts.Add("public");
        else if (access == MethodAttributes.Private) parts.Add("private");
        else if (access == MethodAttributes.Family) parts.Add("protected");
        else if (access == MethodAttributes.Assembly) parts.Add("internal");

        if ((attrs & MethodAttributes.Static) != 0) parts.Add("static");
        if ((attrs & MethodAttributes.Abstract) != 0) parts.Add("abstract");
        else if ((attrs & MethodAttributes.Virtual) != 0) parts.Add("virtual");
        if ((attrs & MethodAttributes.PinvokeImpl) != 0) parts.Add("extern");
        return string.Join(' ', parts);
    }

    private sealed class DiagnosticLogWriter(DiagnosticLogger logger) : LogWriter
    {
        public override void Info(string message) => logger.Info("LibCpp2IL", message.Trim());
        public override void Warn(string message) => logger.Warning("LibCpp2IL", message.Trim());
        public override void Error(string message) => logger.Error("LibCpp2IL", message.Trim());
        public override void Verbose(string message) { }
    }
}
