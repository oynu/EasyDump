using System.Buffers.Binary;

namespace EasyDump.Core.Analysis.Unity.Il2Cpp;

public sealed record MetadataValidationResult(
    bool IsValid,
    int Version,
    long FileSize,
    string? ErrorMessage,
    string? WarningMessage);

/// <summary>
/// Validates global-metadata.dat magic number, version range, and table header bounds
/// before any full parsing is attempted.
/// </summary>
public static class Il2CppMetadataValidator
{
    public const uint Magic = 0xFAB11BAF;
    public const int MinimumSupportedVersion = 16;
    public const int MaximumTestedVersion = 31;

    public static MetadataValidationResult Validate(byte[] data)
    {
        if (data.Length < 128)
        {
            return new MetadataValidationResult(
                false, 0, data.Length,
                $"Metadata file is too small ({data.Length} bytes) to contain a valid Il2CppGlobalMetadataHeader.",
                null);
        }

        uint sanity = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(0, 4));
        if (sanity != Magic)
        {
            return new MetadataValidationResult(
                false, 0, data.Length,
                $"Invalid global-metadata.dat magic: expected 0x{Magic:X8}, got 0x{sanity:X8}. The file may be encrypted, obfuscated, or not a Unity IL2CPP metadata file.",
                null);
        }

        int version = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(4, 4));
        if (version <= 0 || version > 200)
        {
            return new MetadataValidationResult(
                false, version, data.Length,
                $"Unrecognized metadata version {version}. Header may be scrambled or obfuscated.",
                null);
        }

        // Validate string pool and core header offset/count pairs are within file bounds
        int stringOffset = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(24, 4));
        int stringSize = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(28, 4));
        if (stringOffset < 0 || stringSize < 0 || (long)stringOffset + stringSize > data.Length)
        {
            return new MetadataValidationResult(
                false, version, data.Length,
                $"Corrupt or truncated metadata header (v{version}): string table [{stringOffset}..{(long)stringOffset + stringSize}] exceeds file size ({data.Length} bytes).",
                null);
        }

        string? warning = null;
        if (version < MinimumSupportedVersion || version > MaximumTestedVersion)
        {
            warning = $"Metadata version {version} is outside tested range ({MinimumSupportedVersion}–{MaximumTestedVersion}). Parsing will be attempted on a best-effort basis.";
        }

        return new MetadataValidationResult(true, version, data.Length, null, warning);
    }
}
