namespace EasyDump.Core.Models;

public sealed record DiagnosticMessage(
    DateTime TimestampUtc,
    DiagnosticSeverity Severity,
    string Category,
    string Message,
    string? Details = null)
{
    public string FormattedLine => Details is { Length: > 0 }
        ? $"[{TimestampUtc:HH:mm:ss}] [{Severity}] [{Category}] {Message} — {Details}"
        : $"[{TimestampUtc:HH:mm:ss}] [{Severity}] [{Category}] {Message}";
}

public sealed record DetectedFile(
    string Path,
    string Role,
    BinaryFormatType Format,
    ArchitectureType Architecture,
    long SizeBytes,
    DateTime LastWriteUtc)
{
    public string FileName => System.IO.Path.GetFileName(Path);
}

public sealed record GameDetectionResult
{
    public string InputPath { get; init; } = string.Empty;
    public string GameName { get; init; } = string.Empty;
    public GameEngineType Engine { get; init; }
    public string? UnityVersion { get; init; }
    public string? UnityVersionSource { get; init; }
    public ArchitectureType Architecture { get; init; }
    public int? MetadataVersion { get; init; }
    public IReadOnlyList<DetectedFile> Files { get; init; } = Array.Empty<DetectedFile>();
    public string? PrimaryBinaryPath { get; init; }
    public string? MetadataPath { get; init; }
    public string? ManagedDirectoryPath { get; init; }
    public IReadOnlyList<DiagnosticMessage> Diagnostics { get; init; } = Array.Empty<DiagnosticMessage>();
}

public sealed record FieldEntry
{
    public string Name { get; init; } = string.Empty;
    public string FieldType { get; init; } = string.Empty;
    public string Modifiers { get; init; } = string.Empty;
    public bool IsStatic { get; init; }
    public bool IsConst { get; init; }
    public string? ConstantValue { get; init; }
    public uint? MetadataToken { get; init; }
    public OffsetValue? FieldOffset { get; init; }
    public OffsetValue? FieldRva { get; init; }
    public ResolutionStatus OverallStatus { get; init; }
    public ConfidenceLevel Confidence { get; init; }
    public string SourceFile { get; init; } = string.Empty;
    public string ExtractionMethod { get; init; } = string.Empty;
    public string? Notes { get; init; }

    public string TokenHex => MetadataToken.HasValue ? $"0x{MetadataToken.Value:X8}" : "—";
    public string PrimaryOffsetDisplay =>
        FieldOffset?.Value is not null ? FieldOffset.DisplayValue :
        FieldRva?.Value is not null ? $"{FieldRva.DisplayValue} (RVA)" :
        FieldOffset?.DisplayValue ?? FieldRva?.DisplayValue ?? "Unresolved";
    public ulong? SortableOffset => FieldOffset?.Value ?? FieldRva?.Value;
}

public sealed record MethodEntry
{
    public string Name { get; init; } = string.Empty;
    public string ReturnType { get; init; } = string.Empty;
    public string ParametersSignature { get; init; } = string.Empty;
    public string Modifiers { get; init; } = string.Empty;
    public bool IsStatic { get; init; }
    public bool IsVirtual { get; init; }
    public uint? MetadataToken { get; init; }
    public OffsetValue? Rva { get; init; }
    public OffsetValue? VirtualAddress { get; init; }
    public OffsetValue? FileOffset { get; init; }
    public ResolutionStatus OverallStatus { get; init; }
    public ConfidenceLevel Confidence { get; init; }
    public string SourceFile { get; init; } = string.Empty;
    public string ExtractionMethod { get; init; } = string.Empty;
    public string? Notes { get; init; }

    public string FullSignature => $"{ReturnType} {Name}({ParametersSignature})";
    public string TokenHex => MetadataToken.HasValue ? $"0x{MetadataToken.Value:X8}" : "—";
    public string RvaDisplay => Rva?.HexOrDash ?? "—";
    public string VirtualAddressDisplay => VirtualAddress?.HexOrDash ?? "—";
    public string FileOffsetDisplay => FileOffset?.HexOrDash ?? "—";
    public ulong? SortableOffset => Rva?.Value ?? VirtualAddress?.Value ?? FileOffset?.Value;
}

public sealed record TypeEntry
{
    public string AssemblyName { get; init; } = string.Empty;
    public string Namespace { get; init; } = string.Empty;
    public string Name { get; init; } = string.Empty;
    public string FullName { get; init; } = string.Empty;
    public string Kind { get; init; } = "Class";
    public string? BaseType { get; init; }
    public uint? MetadataToken { get; init; }
    public bool IsSystemOrEngine { get; init; }
    public IReadOnlyList<FieldEntry> Fields { get; init; } = Array.Empty<FieldEntry>();
    public IReadOnlyList<MethodEntry> Methods { get; init; } = Array.Empty<MethodEntry>();

    public int ConfirmedOffsetCount =>
        Fields.Count(f => f.OverallStatus == ResolutionStatus.Confirmed) +
        Methods.Count(m => m.OverallStatus == ResolutionStatus.Confirmed);

    public int PartialOffsetCount =>
        Fields.Count(f => f.OverallStatus == ResolutionStatus.Partial) +
        Methods.Count(m => m.OverallStatus == ResolutionStatus.Partial);

    public int UnresolvedOffsetCount =>
        Fields.Count(f => f.OverallStatus == ResolutionStatus.Unresolved) +
        Methods.Count(m => m.OverallStatus == ResolutionStatus.Unresolved);

    public int TotalMembers => Fields.Count + Methods.Count;
    public string DisplayNamespace => string.IsNullOrWhiteSpace(Namespace) ? "<global>" : Namespace;
    public string TokenHex => MetadataToken.HasValue ? $"0x{MetadataToken.Value:X8}" : "—";
}

public sealed record AssemblyEntry
{
    public string Name { get; init; } = string.Empty;
    public string SourcePath { get; init; } = string.Empty;
    public bool IsSystemOrEngine { get; init; }
    public IReadOnlyList<TypeEntry> Types { get; init; } = Array.Empty<TypeEntry>();

    public int TotalTypes => Types.Count;
    public int TotalFields => Types.Sum(t => t.Fields.Count);
    public int TotalMethods => Types.Sum(t => t.Methods.Count);
    public int ConfirmedOffsets => Types.Sum(t => t.ConfirmedOffsetCount);
    public int PartialOffsets => Types.Sum(t => t.PartialOffsetCount);
    public int UnresolvedOffsets => Types.Sum(t => t.UnresolvedOffsetCount);
}

public sealed record AnalysisResult
{
    public GameDetectionResult Detection { get; init; } = new();
    public DateTime AnalyzedAtUtc { get; init; }
    public TimeSpan Duration { get; init; }
    public string InputFingerprint { get; init; } = string.Empty;
    public bool FromCache { get; init; }
    public bool Succeeded { get; init; } = true;
    public string? ErrorMessage { get; init; }
    public IReadOnlyList<AssemblyEntry> Assemblies { get; init; } = Array.Empty<AssemblyEntry>();
    public IReadOnlyList<DiagnosticMessage> Diagnostics { get; init; } = Array.Empty<DiagnosticMessage>();

    public int TotalAssemblies => Assemblies.Count;
    public int TotalTypes => Assemblies.Sum(a => a.TotalTypes);
    public int TotalFields => Assemblies.Sum(a => a.TotalFields);
    public int TotalMethods => Assemblies.Sum(a => a.TotalMethods);
    public int ConfirmedOffsets => Assemblies.Sum(a => a.ConfirmedOffsets);
    public int PartialOffsets => Assemblies.Sum(a => a.PartialOffsets);
    public int UnresolvedOffsets => Assemblies.Sum(a => a.UnresolvedOffsets);
}

public sealed record AnalysisProgress(
    string Stage,
    string Message,
    double Percent,
    bool IsIndeterminate = false);
