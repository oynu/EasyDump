using System.Buffers.Binary;
using System.Text;
using EasyDump.Core.Models;

namespace EasyDump.Core.Detection;

public sealed record BinaryHeaderInfo(
    BinaryFormatType Format,
    ArchitectureType Architecture,
    bool IsDotNetAssembly,
    ulong ImageBase,
    int? MetadataVersion,
    uint? RawMagic,
    string? Warning = null);

/// <summary>
/// Safely inspects minimal binary headers (PE, ELF, IL2CPP global-metadata.dat)
/// without loading full files into memory or executing code.
/// </summary>
public static class BinaryFormatDetector
{
    public const uint Il2CppMetadataMagic = 0xFAB11BAF;

    public static BinaryHeaderInfo InspectFile(string path)
    {
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (fs.Length < 4)
                return new BinaryHeaderInfo(BinaryFormatType.Unknown, ArchitectureType.Unknown, false, 0, null, null, "File is smaller than 4 bytes.");

            Span<byte> magicBuf = stackalloc byte[4];
            if (fs.Read(magicBuf) < 4)
                return new BinaryHeaderInfo(BinaryFormatType.Unknown, ArchitectureType.Unknown, false, 0, null, null);

            uint leMagic = BinaryPrimitives.ReadUInt32LittleEndian(magicBuf);

            // Unity global-metadata.dat
            if (leMagic == Il2CppMetadataMagic)
            {
                if (fs.Length < 8)
                    return new BinaryHeaderInfo(BinaryFormatType.UnityMetadata, ArchitectureType.Unknown, false, 0, null, leMagic, "Truncated IL2CPP metadata header.");

                Span<byte> verBuf = stackalloc byte[4];
                fs.Read(verBuf);
                int version = BinaryPrimitives.ReadInt32LittleEndian(verBuf);
                return new BinaryHeaderInfo(BinaryFormatType.UnityMetadata, ArchitectureType.Unknown, false, 0, version, leMagic);
            }

            // ELF (\x7FELF)
            if (magicBuf[0] == 0x7F && magicBuf[1] == (byte)'E' && magicBuf[2] == (byte)'L' && magicBuf[3] == (byte)'F')
            {
                return InspectElf(fs, leMagic);
            }

            // PE (MZ)
            if (magicBuf[0] == (byte)'M' && magicBuf[1] == (byte)'Z')
            {
                return InspectPe(fs, leMagic);
            }

            // Check if this is named global-metadata.dat with wrong magic (encrypted/obfuscated/corrupt)
            if (string.Equals(Path.GetFileName(path), "global-metadata.dat", StringComparison.OrdinalIgnoreCase))
            {
                return new BinaryHeaderInfo(
                    BinaryFormatType.UnityMetadata,
                    ArchitectureType.Unknown,
                    false,
                    0,
                    null,
                    leMagic,
                    $"Magic mismatch (expected 0x{Il2CppMetadataMagic:X8}, got 0x{leMagic:X8}) — metadata may be encrypted, obfuscated, or corrupted.");
            }

            return new BinaryHeaderInfo(BinaryFormatType.Unknown, ArchitectureType.Unknown, false, 0, null, leMagic);
        }
        catch (Exception ex)
        {
            return new BinaryHeaderInfo(BinaryFormatType.Unknown, ArchitectureType.Unknown, false, 0, null, null, ex.Message);
        }
    }

    private static BinaryHeaderInfo InspectPe(FileStream fs, uint rawMagic)
    {
        if (fs.Length < 0x40)
            return new BinaryHeaderInfo(BinaryFormatType.PE, ArchitectureType.Unknown, false, 0, null, rawMagic, "Truncated DOS header.");

        fs.Position = 0x3C;
        Span<byte> buf = stackalloc byte[4];
        fs.Read(buf);
        uint peOffset = BinaryPrimitives.ReadUInt32LittleEndian(buf);

        if (peOffset > fs.Length - 24 || peOffset < 0x40)
            return new BinaryHeaderInfo(BinaryFormatType.PE, ArchitectureType.Unknown, false, 0, null, rawMagic, "Invalid PE header offset.");

        fs.Position = peOffset;
        Span<byte> peHeader = stackalloc byte[24];
        if (fs.Read(peHeader) < 24)
            return new BinaryHeaderInfo(BinaryFormatType.PE, ArchitectureType.Unknown, false, 0, null, rawMagic, "Truncated PE COFF header.");

        if (peHeader[0] != (byte)'P' || peHeader[1] != (byte)'E' || peHeader[2] != 0 || peHeader[3] != 0)
            return new BinaryHeaderInfo(BinaryFormatType.Unknown, ArchitectureType.Unknown, false, 0, null, rawMagic, "Missing PE signature.");

        ushort machine = BinaryPrimitives.ReadUInt16LittleEndian(peHeader.Slice(4, 2));
        ushort sizeOfOptionalHeader = BinaryPrimitives.ReadUInt16LittleEndian(peHeader.Slice(20, 2));

        ArchitectureType arch = machine switch
        {
            0x8664 => ArchitectureType.X64,
            0x014C => ArchitectureType.X86,
            0xAA64 => ArchitectureType.Arm64,
            0x01C0 or 0x01C4 => ArchitectureType.Arm32,
            _ => ArchitectureType.Unknown
        };

        ulong imageBase = 0;
        bool isDotNet = false;

        if (sizeOfOptionalHeader >= 96 && fs.Position + sizeOfOptionalHeader <= fs.Length)
        {
            byte[] opt = new byte[sizeOfOptionalHeader];
            int read = fs.Read(opt, 0, sizeOfOptionalHeader);
            if (read >= 2)
            {
                ushort magic = BinaryPrimitives.ReadUInt16LittleEndian(opt.AsSpan(0, 2));
                bool isPe32Plus = magic == 0x020B;
                if (isPe32Plus && read >= 240)
                {
                    imageBase = BinaryPrimitives.ReadUInt64LittleEndian(opt.AsSpan(24, 8));
                    uint numRva = BinaryPrimitives.ReadUInt32LittleEndian(opt.AsSpan(108, 4));
                    if (numRva > 14)
                    {
                        uint clrRva = BinaryPrimitives.ReadUInt32LittleEndian(opt.AsSpan(112 + 14 * 8, 4));
                        uint clrSize = BinaryPrimitives.ReadUInt32LittleEndian(opt.AsSpan(112 + 14 * 8 + 4, 4));
                        isDotNet = clrRva != 0 && clrSize != 0;
                        if (isDotNet && arch == ArchitectureType.X86)
                        {
                            // Check COR20 header flags for ILONLY without 32BITREQUIRED -> AnyCPU
                            // Keep PE machine unless confirmed ILONLY later by AsmResolver
                        }
                    }
                }
                else if (!isPe32Plus && read >= 224)
                {
                    imageBase = BinaryPrimitives.ReadUInt32LittleEndian(opt.AsSpan(28, 4));
                    uint numRva = BinaryPrimitives.ReadUInt32LittleEndian(opt.AsSpan(92, 4));
                    if (numRva > 14)
                    {
                        uint clrRva = BinaryPrimitives.ReadUInt32LittleEndian(opt.AsSpan(96 + 14 * 8, 4));
                        uint clrSize = BinaryPrimitives.ReadUInt32LittleEndian(opt.AsSpan(96 + 14 * 8 + 4, 4));
                        isDotNet = clrRva != 0 && clrSize != 0;
                    }
                }
            }
        }

        return new BinaryHeaderInfo(BinaryFormatType.PE, arch, isDotNet, imageBase, null, rawMagic);
    }

    private static BinaryHeaderInfo InspectElf(FileStream fs, uint rawMagic)
    {
        if (fs.Length < 20)
            return new BinaryHeaderInfo(BinaryFormatType.Elf, ArchitectureType.Unknown, false, 0, null, rawMagic, "Truncated ELF header.");

        fs.Position = 0;
        Span<byte> ident = stackalloc byte[20];
        fs.Read(ident);

        byte eiData = ident[5]; // 1 = little endian, 2 = big endian
        ushort eMachine = eiData == 2
            ? BinaryPrimitives.ReadUInt16BigEndian(ident.Slice(18, 2))
            : BinaryPrimitives.ReadUInt16LittleEndian(ident.Slice(18, 2));

        ArchitectureType arch = eMachine switch
        {
            0x3E => ArchitectureType.X64,
            0x03 => ArchitectureType.X86,
            0xB7 => ArchitectureType.Arm64,
            0x28 => ArchitectureType.Arm32,
            _ => ArchitectureType.Unknown
        };

        return new BinaryHeaderInfo(BinaryFormatType.Elf, arch, false, 0, null, rawMagic);
    }
}
