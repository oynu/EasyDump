using System.Globalization;

namespace EasyDump.Core.Models;

/// <summary>
/// Represents an extracted or unresolved offset value along with provenance,
/// extraction method, and verification status. Unresolved values always keep
/// <see cref="Value"/> as null to guarantee offsets are never fabricated.
/// </summary>
public sealed record OffsetValue
{
    public OffsetKind Kind { get; init; }
    public ulong? Value { get; init; }
    public ResolutionStatus Status { get; init; }
    public ConfidenceLevel Confidence { get; init; }
    public string SourceFile { get; init; } = string.Empty;
    public string ExtractionMethod { get; init; } = string.Empty;
    public string? Notes { get; init; }

    public string DisplayValue => Value.HasValue
        ? FormatHex(Value.Value, Kind)
        : Status == ResolutionStatus.Partial && !string.IsNullOrWhiteSpace(Notes)
            ? "Partial"
            : "Unresolved";

    public string HexOrDash => Value.HasValue ? FormatHex(Value.Value, Kind) : "—";

    public static string FormatHex(ulong value, OffsetKind kind)
    {
        return kind switch
        {
            OffsetKind.MetadataToken => $"0x{value:X8}",
            OffsetKind.FieldOffset => $"0x{value:X}",
            OffsetKind.MethodVirtualAddress or OffsetKind.ExportVirtualAddress => value > uint.MaxValue
                ? $"0x{value:X16}"
                : $"0x{value:X8}",
            _ => $"0x{value:X8}"
        };
    }

    public static OffsetValue Confirmed(
        OffsetKind kind,
        ulong value,
        string sourceFile,
        string extractionMethod,
        ConfidenceLevel confidence = ConfidenceLevel.High,
        string? notes = null) => new()
        {
            Kind = kind,
            Value = value,
            Status = ResolutionStatus.Confirmed,
            Confidence = confidence,
            SourceFile = sourceFile,
            ExtractionMethod = extractionMethod,
            Notes = notes
        };

    public static OffsetValue Partial(
        OffsetKind kind,
        ulong? value,
        string sourceFile,
        string extractionMethod,
        string notes,
        ConfidenceLevel confidence = ConfidenceLevel.Low) => new()
        {
            Kind = kind,
            Value = value,
            Status = ResolutionStatus.Partial,
            Confidence = confidence,
            SourceFile = sourceFile,
            ExtractionMethod = extractionMethod,
            Notes = notes
        };

    public static OffsetValue Unresolved(
        OffsetKind kind,
        string sourceFile,
        string extractionMethod,
        string notes) => new()
        {
            Kind = kind,
            Value = null,
            Status = ResolutionStatus.Unresolved,
            Confidence = ConfidenceLevel.None,
            SourceFile = sourceFile,
            ExtractionMethod = extractionMethod,
            Notes = notes
        };
}
