using System.Buffers.Binary;
using System.Text;
using EasyDump.Core.Analysis.Generic;
using EasyDump.Core.Detection;
using EasyDump.Core.Diagnostics;
using EasyDump.Core.Models;

namespace EasyDump.Tests;

public sealed class GenericBinaryTests : IDisposable
{
    private readonly string _tempRoot;

    public GenericBinaryTests()
    {
        _tempRoot = Path.Combine(Path.GetTempPath(), $"EasyDump_GenericTest_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempRoot);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempRoot, recursive: true); } catch { }
    }

    [Fact]
    public void PeInspectorExtractsSectionsAndArchitectureFromRealDll()
    {
        string dllPath = Path.Combine(AppContext.BaseDirectory, "EasyDump.Core.dll");
        Assert.True(File.Exists(dllPath));

        var info = BinaryFormatDetector.InspectFile(dllPath);
        Assert.Equal(BinaryFormatType.PE, info.Format);
        Assert.True(info.IsDotNetAssembly);

        var logger = new DiagnosticLogger();
        var entries = PeBinaryInspector.Inspect(dllPath, logger);
        Assert.True(entries.Count >= 2); // Managed + PE Native
        var nativeEntry = entries.Single(e => e.Name.Contains("(PE Native)"));
        var sectionsType = nativeEntry.Types.Single(t => t.Name == "Sections");
        Assert.Contains(sectionsType.Fields, f => f.Name == ".text" && f.OverallStatus == ResolutionStatus.Confirmed);
    }

    [Fact]
    public void ElfReaderExtractsFunctionsAndObjectsWithExactVaRvaAndFileOffset()
    {
        string elfPath = Path.Combine(_tempRoot, "libsample.so");
        File.WriteAllBytes(elfPath, BuildSyntheticElf64());

        var info = BinaryFormatDetector.InspectFile(elfPath);
        Assert.Equal(BinaryFormatType.Elf, info.Format);
        Assert.Equal(ArchitectureType.Arm64, info.Architecture);

        var logger = new DiagnosticLogger();
        var entries = ElfBinaryReader.Inspect(elfPath, logger);
        Assert.Single(entries);

        var symbols = entries[0].Types.Single(t => t.Name == "DefinedSymbols");
        var fn = symbols.Methods.Single(m => m.Name == "Game_UpdatePlayer");
        Assert.Equal(ResolutionStatus.Confirmed, fn.OverallStatus);
        Assert.Equal(0x101234UL, fn.VirtualAddress!.Value);
        Assert.Equal(0x1234UL, fn.Rva!.Value);
        Assert.Equal(0x1234UL, fn.FileOffset!.Value);

        var obj = symbols.Fields.Single(f => f.Name == "g_PlayerInstance");
        Assert.Equal(ResolutionStatus.Confirmed, obj.OverallStatus);
        Assert.Equal(0x102000UL, obj.FieldOffset!.Value);
        Assert.Equal(0x2000UL, obj.FieldRva!.Value);
    }

    [Fact]
    public void RunningProcessServiceEnumeratesProcessesSafely()
    {
        var procs = RunningProcessService.GetRunningProcesses();
        Assert.NotEmpty(procs);
        Assert.All(procs, p => Assert.True(File.Exists(p.ExecutablePath)));
    }

    private static byte[] BuildSyntheticElf64()
    {
        // ELF64 header (64) + 1 PT_LOAD (56) + 4 section headers (4 * 64 = 256)
        // Base vaddr = 0x100000, file offset 0, file size = 0x3000
        byte[] data = new byte[0x3000];
        data[0] = 0x7F; data[1] = (byte)'E'; data[2] = (byte)'L'; data[3] = (byte)'F';
        data[4] = 2; // ELFCLASS64
        data[5] = 1; // ELFDATA2LSB
        data[6] = 1; // EV_CURRENT
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(16, 2), 3);    // ET_DYN
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(18, 2), 0xB7); // EM_AARCH64
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(20, 4), 1);

        const ulong phOff = 64;
        const ulong shOff = 64 + 56;
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(32, 8), phOff);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(40, 8), shOff);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(52, 2), 64);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(54, 2), 56);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(56, 2), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(58, 2), 64);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(60, 2), 4);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(62, 2), 1); // shstrndx = 1

        // PT_LOAD at phOff (64)
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan((int)phOff + 0, 4), 1); // PT_LOAD
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan((int)phOff + 4, 4), 5); // PF_R | PF_X
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan((int)phOff + 8, 8), 0); // p_offset
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan((int)phOff + 16, 8), 0x100000); // p_vaddr
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan((int)phOff + 24, 8), 0x100000);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan((int)phOff + 32, 8), 0x3000); // p_filesz
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan((int)phOff + 40, 8), 0x3000); // p_memsz

        // Strings at 0x400 (.shstrtab) and 0x500 (.dynstr)
        byte[] shstr = Encoding.ASCII.GetBytes("\0.shstrtab\0.dynstr\0.dynsym\0");
        shstr.CopyTo(data, 0x400);

        var dynstrMs = new MemoryStream();
        dynstrMs.WriteByte(0);
        int fnNameOff = (int)dynstrMs.Position;
        dynstrMs.Write(Encoding.ASCII.GetBytes("Game_UpdatePlayer\0"));
        int objNameOff = (int)dynstrMs.Position;
        dynstrMs.Write(Encoding.ASCII.GetBytes("g_PlayerInstance\0"));
        byte[] dynstr = dynstrMs.ToArray();
        dynstr.CopyTo(data, 0x500);

        // .dynsym at 0x600 (3 entries * 24 bytes: NULL, FUNC, OBJECT)
        int symOff = 0x600 + 24;
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(symOff + 0, 4), (uint)fnNameOff);
        data[symOff + 4] = (1 << 4) | 2; // STB_GLOBAL | STT_FUNC
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(symOff + 6, 2), 1);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(symOff + 8, 8), 0x101234);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(symOff + 16, 8), 0x40);

        symOff += 24;
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(symOff + 0, 4), (uint)objNameOff);
        data[symOff + 4] = (1 << 4) | 1; // STB_GLOBAL | STT_OBJECT
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(symOff + 6, 2), 1);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(symOff + 8, 8), 0x102000);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(symOff + 16, 8), 8);

        void WriteSh(int index, uint nameOff, uint type, ulong addr, ulong offset, ulong size, uint link, ulong entsize)
        {
            int o = (int)shOff + index * 64;
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(o + 0, 4), nameOff);
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(o + 4, 4), type);
            BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(o + 16, 8), addr);
            BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(o + 24, 8), offset);
            BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(o + 32, 8), size);
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(o + 40, 4), link);
            BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(o + 56, 8), entsize);
        }

        WriteSh(0, 0, 0, 0, 0, 0, 0, 0);
        WriteSh(1, 1, 3, 0, 0x400, (ulong)shstr.Length, 0, 0); // .shstrtab
        WriteSh(2, 11, 3, 0, 0x500, (ulong)dynstr.Length, 0, 0); // .dynstr
        WriteSh(3, 19, 11, 0, 0x600, 3 * 24, 2, 24); // .dynsym linked to .dynstr (idx 2)

        return data;
    }
}
