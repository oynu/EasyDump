namespace EasyDump.Core.Models;

public enum GameEngineType
{
    Unknown = 0,
    UnityIl2Cpp,
    UnityMono,
    UnrealEngine,
    Godot,
    DotNetStandalone,
    NativePe,
    NativeElf
}

public enum ArchitectureType
{
    Unknown = 0,
    X64,
    X86,
    Arm64,
    Arm32,
    AnyCpu
}

public enum BinaryFormatType
{
    Unknown = 0,
    PE,
    Elf,
    UnityMetadata
}

public enum ResolutionStatus
{
    Confirmed = 0,
    Partial,
    Unresolved
}

public enum ConfidenceLevel
{
    None = 0,
    Low,
    Medium,
    High
}

public enum OffsetKind
{
    FieldOffset = 0,
    FieldRva,
    MethodRva,
    MethodVirtualAddress,
    MethodFileOffset,
    MetadataToken,
    ExportRva,
    ExportVirtualAddress,
    ExportFileOffset,
    SectionRva
}

public enum DiagnosticSeverity
{
    Info = 0,
    Warning,
    Error
}

public enum ExportFormat
{
    Json = 0,
    Txt,
    Csv
}

public enum ExportScope
{
    All = 0,
    Filtered,
    SelectedAssembly,
    SelectedType
}
