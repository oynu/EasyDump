using System.Buffers.Binary;
using System.Text;
using EasyDump.Core.Diagnostics;
using EasyDump.Core.Models;

namespace EasyDump.Core.Analysis.Generic;

/// <summary>
/// Pure-C# ELF32 / ELF64 reader that parses PT_LOAD segments, section headers,
/// .dynsym/.dynstr, and .symtab/.strtab with strict bounds validation.
/// </summary>
public static class ElfBinaryReader
{
    private readonly record struct LoadSegment(ulong VAddr, ulong MemSize, ulong FileOffset, ulong FileSize);
    private readonly record struct ElfSection(string Name, uint Type, ulong Addr, ulong Offset, ulong Size, uint Link, ulong EntSize);

    public static List<AssemblyEntry> Inspect(string filePath, DiagnosticLogger logger)
    {
        string fileName = Path.GetFileName(filePath);
        try
        {
            byte[] data;
            using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                data = new byte[fs.Length];
                fs.ReadExactly(data);
            }

            if (data.Length < 52 || data[0] != 0x7F || data[1] != (byte)'E' || data[2] != (byte)'L' || data[3] != (byte)'F')
            {
                logger.Error("ElfAnalysis", $"'{fileName}' is not a valid ELF file.");
                return new List<AssemblyEntry>();
            }

            bool is64 = data[4] == 2;
            bool bigEndian = data[5] == 2;
            if ((is64 && data.Length < 64) || (!is64 && data.Length < 52))
            {
                logger.Error("ElfAnalysis", $"ELF header in '{fileName}' is truncated.");
                return new List<AssemblyEntry>();
            }

            ulong phOff = is64 ? ReadU64(data, 32, bigEndian) : ReadU32(data, 28, bigEndian);
            ulong shOff = is64 ? ReadU64(data, 40, bigEndian) : ReadU32(data, 32, bigEndian);
            ushort phEntSize = ReadU16(data, is64 ? 54 : 42, bigEndian);
            ushort phNum = ReadU16(data, is64 ? 56 : 44, bigEndian);
            ushort shEntSize = ReadU16(data, is64 ? 58 : 46, bigEndian);
            ushort shNum = ReadU16(data, is64 ? 60 : 48, bigEndian);
            ushort shStrNdx = ReadU16(data, is64 ? 62 : 50, bigEndian);

            // Parse PT_LOAD segments to map VA <-> FileOffset
            var loadSegments = new List<LoadSegment>();
            ulong baseVAddr = ulong.MaxValue;
            if (phOff > 0 && phEntSize >= (is64 ? 56 : 32))
            {
                for (int i = 0; i < phNum; i++)
                {
                    ulong off = phOff + (ulong)i * phEntSize;
                    if (off + phEntSize > (ulong)data.Length) break;

                    uint pType = ReadU32(data, (int)off, bigEndian);
                    if (pType != 1) continue; // PT_LOAD

                    ulong pOffset, pVAddr, pFileSz, pMemSz;
                    if (is64)
                    {
                        pOffset = ReadU64(data, (int)off + 8, bigEndian);
                        pVAddr = ReadU64(data, (int)off + 16, bigEndian);
                        pFileSz = ReadU64(data, (int)off + 32, bigEndian);
                        pMemSz = ReadU64(data, (int)off + 40, bigEndian);
                    }
                    else
                    {
                        pOffset = ReadU32(data, (int)off + 4, bigEndian);
                        pVAddr = ReadU32(data, (int)off + 8, bigEndian);
                        pFileSz = ReadU32(data, (int)off + 16, bigEndian);
                        pMemSz = ReadU32(data, (int)off + 20, bigEndian);
                    }

                    if (pVAddr < baseVAddr)
                        baseVAddr = pVAddr;

                    loadSegments.Add(new LoadSegment(pVAddr, pMemSz, pOffset, pFileSz));
                }
            }
            if (baseVAddr == ulong.MaxValue) baseVAddr = 0;

            // Parse sections
            var sections = new List<ElfSection>();
            if (shOff > 0 && shNum > 0 && shEntSize >= (is64 ? 64 : 40))
            {
                for (int i = 0; i < shNum; i++)
                {
                    ulong off = shOff + (ulong)i * shEntSize;
                    if (off + shEntSize > (ulong)data.Length) break;

                    uint shNameOff = ReadU32(data, (int)off, bigEndian);
                    uint shType = ReadU32(data, (int)off + 4, bigEndian);
                    ulong shAddr = is64 ? ReadU64(data, (int)off + 16, bigEndian) : ReadU32(data, (int)off + 12, bigEndian);
                    ulong shSecOff = is64 ? ReadU64(data, (int)off + 24, bigEndian) : ReadU32(data, (int)off + 16, bigEndian);
                    ulong shSize = is64 ? ReadU64(data, (int)off + 32, bigEndian) : ReadU32(data, (int)off + 20, bigEndian);
                    uint shLink = ReadU32(data, (int)off + (is64 ? 40 : 24), bigEndian);
                    ulong shEntSz = is64 ? ReadU64(data, (int)off + 56, bigEndian) : ReadU32(data, (int)off + 36, bigEndian);

                    sections.Add(new ElfSection(shNameOff.ToString(), shType, shAddr, shSecOff, shSize, shLink, shEntSz));
                }

                // Resolve section names from shstrtab
                if (shStrNdx < sections.Count)
                {
                    var shstr = sections[shStrNdx];
                    for (int i = 0; i < sections.Count; i++)
                    {
                        if (uint.TryParse(sections[i].Name, out uint nameIdx))
                        {
                            string resolved = ReadCString(data, shstr.Offset, shstr.Size, nameIdx);
                            sections[i] = sections[i] with { Name = resolved };
                        }
                    }
                }
            }

            var funcMethods = new List<MethodEntry>();
            var objFields = new List<FieldEntry>();
            var seenSymbols = new HashSet<string>(StringComparer.Ordinal);

            // SHT_SYMTAB = 2, SHT_DYNSYM = 11
            foreach (var sec in sections)
            {
                if (sec.Type != 2 && sec.Type != 11) continue;
                if (sec.Link >= sections.Count) continue;
                var strSec = sections[(int)sec.Link];
                ulong entSize = sec.EntSize > 0 ? sec.EntSize : (ulong)(is64 ? 24 : 16);
                if (sec.Offset + sec.Size > (ulong)data.Length) continue;

                string tableSource = sec.Type == 11 ? "ELF .dynsym" : "ELF .symtab";
                ulong count = sec.Size / entSize;
                for (ulong i = 0; i < count; i++)
                {
                    ulong symOff = sec.Offset + i * entSize;
                    if (symOff + entSize > (ulong)data.Length) break;

                    uint stName;
                    byte stInfo;
                    ushort stShndx;
                    ulong stValue, stSize;

                    if (is64)
                    {
                        stName = ReadU32(data, (int)symOff, bigEndian);
                        stInfo = data[symOff + 4];
                        stShndx = ReadU16(data, (int)symOff + 6, bigEndian);
                        stValue = ReadU64(data, (int)symOff + 8, bigEndian);
                        stSize = ReadU64(data, (int)symOff + 16, bigEndian);
                    }
                    else
                    {
                        stName = ReadU32(data, (int)symOff, bigEndian);
                        stValue = ReadU32(data, (int)symOff + 4, bigEndian);
                        stSize = ReadU32(data, (int)symOff + 8, bigEndian);
                        stInfo = data[symOff + 12];
                        stShndx = ReadU16(data, (int)symOff + 14, bigEndian);
                    }

                    if (stShndx == 0 || stValue == 0) continue; // SHN_UNDEF (imported)

                    string symName = ReadCString(data, strSec.Offset, strSec.Size, stName);
                    if (string.IsNullOrWhiteSpace(symName)) continue;

                    byte stType = (byte)(stInfo & 0xF);
                    byte stBind = (byte)(stInfo >> 4);
                    string bindName = stBind switch { 0 => "local", 1 => "global", 2 => "weak", _ => "other" };

                    string key = $"{stType}:{symName}:0x{stValue:X}";
                    if (!seenSymbols.Add(key)) continue;

                    ulong rva = stValue >= baseVAddr ? stValue - baseVAddr : stValue;
                    ulong? fileOffset = MapVaToFileOffset(loadSegments, stValue);

                    if (stType == 2) // STT_FUNC
                    {
                        funcMethods.Add(new MethodEntry
                        {
                            Name = symName,
                            ReturnType = "func",
                            ParametersSignature = stSize > 0 ? $"size=0x{stSize:X}" : string.Empty,
                            Modifiers = bindName,
                            Rva = OffsetValue.Confirmed(OffsetKind.ExportRva, rva, fileName, tableSource),
                            VirtualAddress = OffsetValue.Confirmed(OffsetKind.ExportVirtualAddress, stValue, fileName, tableSource),
                            FileOffset = fileOffset.HasValue
                                ? OffsetValue.Confirmed(OffsetKind.ExportFileOffset, fileOffset.Value, fileName, "ELF PT_LOAD Map")
                                : OffsetValue.Unresolved(OffsetKind.ExportFileOffset, fileName, "ELF PT_LOAD Map", "Virtual address did not map to a file-backed PT_LOAD segment."),
                            OverallStatus = fileOffset.HasValue ? ResolutionStatus.Confirmed : ResolutionStatus.Partial,
                            Confidence = ConfidenceLevel.High,
                            SourceFile = fileName,
                            ExtractionMethod = tableSource
                        });
                    }
                    else if (stType == 1) // STT_OBJECT
                    {
                        objFields.Add(new FieldEntry
                        {
                            Name = symName,
                            FieldType = stSize > 0 ? $"object (0x{stSize:X} bytes)" : "object",
                            Modifiers = bindName,
                            IsStatic = true,
                            FieldOffset = OffsetValue.Confirmed(OffsetKind.ExportVirtualAddress, stValue, fileName, tableSource),
                            FieldRva = OffsetValue.Confirmed(OffsetKind.ExportRva, rva, fileName, tableSource),
                            OverallStatus = ResolutionStatus.Confirmed,
                            Confidence = ConfidenceLevel.High,
                            SourceFile = fileName,
                            ExtractionMethod = tableSource,
                            Notes = fileOffset.HasValue ? $"FileOffset=0x{fileOffset.Value:X8}" : null
                        });
                    }
                }
            }

            var types = new List<TypeEntry>();
            if (funcMethods.Count > 0 || objFields.Count > 0)
            {
                types.Add(new TypeEntry
                {
                    AssemblyName = fileName,
                    Namespace = "ELF.Symbols",
                    Name = "DefinedSymbols",
                    FullName = "ELF.Symbols.DefinedSymbols",
                    Kind = "Module",
                    IsSystemOrEngine = false,
                    Fields = objFields,
                    Methods = funcMethods
                });
            }

            if (sections.Count > 0)
            {
                var secFields = sections
                    .Where(s => !string.IsNullOrEmpty(s.Name))
                    .Select(s => new FieldEntry
                    {
                        Name = s.Name,
                        FieldType = $"Size=0x{s.Size:X}",
                        Modifiers = $"type=0x{s.Type:X}",
                        FieldOffset = OffsetValue.Confirmed(OffsetKind.SectionRva, s.Addr, fileName, "ELF Section Header"),
                        FieldRva = OffsetValue.Confirmed(OffsetKind.ExportFileOffset, s.Offset, fileName, "ELF Section File Offset"),
                        OverallStatus = ResolutionStatus.Confirmed,
                        Confidence = ConfidenceLevel.High,
                        SourceFile = fileName,
                        ExtractionMethod = "ELF Section Header"
                    }).ToList();

                if (secFields.Count > 0)
                {
                    types.Add(new TypeEntry
                    {
                        AssemblyName = fileName,
                        Namespace = "ELF.Structure",
                        Name = "Sections",
                        FullName = "ELF.Structure.Sections",
                        Kind = "Module",
                        IsSystemOrEngine = false,
                        Fields = secFields
                    });
                }
            }

            logger.Info("ElfAnalysis", $"Extracted {funcMethods.Count} ELF functions, {objFields.Count} objects, and {sections.Count} sections from {fileName}.");

            if (types.Count == 0)
                return new List<AssemblyEntry>();

            return new List<AssemblyEntry>
            {
                new AssemblyEntry
                {
                    Name = $"{fileName} (ELF)",
                    SourcePath = filePath,
                    IsSystemOrEngine = false,
                    Types = types
                }
            };
        }
        catch (Exception ex)
        {
            logger.Error("ElfAnalysis", $"Failed to inspect ELF binary '{fileName}': {ex.Message}");
            return new List<AssemblyEntry>();
        }
    }

    private static ulong? MapVaToFileOffset(List<LoadSegment> segments, ulong va)
    {
        foreach (var seg in segments)
        {
            if (va >= seg.VAddr && va < seg.VAddr + seg.FileSize)
            {
                return seg.FileOffset + (va - seg.VAddr);
            }
        }
        return null;
    }

    private static string ReadCString(byte[] data, ulong tableOffset, ulong tableSize, uint stringIndex)
    {
        ulong pos = tableOffset + stringIndex;
        ulong max = Math.Min((ulong)data.Length, tableOffset + tableSize);
        if (pos >= max) return string.Empty;

        int start = (int)pos;
        int end = start;
        while ((ulong)end < max && data[end] != 0)
            end++;

        return end > start ? Encoding.UTF8.GetString(data, start, end - start) : string.Empty;
    }

    private static ushort ReadU16(byte[] d, int o, bool be)
        => be ? BinaryPrimitives.ReadUInt16BigEndian(d.AsSpan(o, 2)) : BinaryPrimitives.ReadUInt16LittleEndian(d.AsSpan(o, 2));

    private static uint ReadU32(byte[] d, int o, bool be)
        => be ? BinaryPrimitives.ReadUInt32BigEndian(d.AsSpan(o, 4)) : BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(o, 4));

    private static ulong ReadU64(byte[] d, int o, bool be)
        => be ? BinaryPrimitives.ReadUInt64BigEndian(d.AsSpan(o, 8)) : BinaryPrimitives.ReadUInt64LittleEndian(d.AsSpan(o, 8));
}
