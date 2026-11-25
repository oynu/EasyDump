using System.Text;
using AsmResolver.PE;
using AsmResolver.PE.Exports;
using AsmResolver.PE.File;
using EasyDump.Core.Analysis.Unity.Mono;
using EasyDump.Core.Diagnostics;
using EasyDump.Core.Models;

namespace EasyDump.Core.Analysis.Generic;

/// <summary>
/// Inspects Windows PE files (executables and DLLs) to extract sections,
/// exported functions, imported modules, and any embedded .NET metadata.
/// </summary>
public static class PeBinaryInspector
{
    public static List<AssemblyEntry> Inspect(string filePath, DiagnosticLogger logger)
    {
        var results = new List<AssemblyEntry>();
        string fileName = Path.GetFileName(filePath);

        try
        {
            byte[] bytes;
            using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                bytes = new byte[fs.Length];
                fs.ReadExactly(bytes);
            }

            var peFile = PEFile.FromBytes(bytes);
            var peImage = PEImage.FromFile(peFile);
            ulong imageBase = peFile.OptionalHeader.ImageBase;

            // If this is a .NET assembly, extract its full managed metadata too
            if (peImage.DotNetDirectory is not null)
            {
                var managedEntry = UnityMonoAnalyzer.InspectSingleAssembly(filePath, logger);
                if (managedEntry is not null)
                    results.Add(managedEntry);
            }

            var types = new List<TypeEntry>();

            // 1. PE Sections
            var sectionFields = new List<FieldEntry>();
            foreach (var section in peFile.Sections)
            {
                uint rva = section.Rva;
                ulong rawOffset = section.Offset;
                ulong va = imageBase + rva;

                sectionFields.Add(new FieldEntry
                {
                    Name = section.Name,
                    FieldType = $"VirtualSize=0x{section.GetVirtualSize():X}, RawSize=0x{section.GetPhysicalSize():X}",
                    Modifiers = section.Characteristics.ToString(),
                    FieldOffset = OffsetValue.Confirmed(OffsetKind.SectionRva, rva, fileName, "PE Section Header Table"),
                    FieldRva = OffsetValue.Confirmed(OffsetKind.ExportFileOffset, rawOffset, fileName, "PE Section Raw Pointer"),
                    OverallStatus = ResolutionStatus.Confirmed,
                    Confidence = ConfidenceLevel.High,
                    SourceFile = fileName,
                    ExtractionMethod = "PE Section Header Table",
                    Notes = $"VA=0x{va:X}, Characteristics={section.Characteristics}"
                });
            }

            if (sectionFields.Count > 0)
            {
                types.Add(new TypeEntry
                {
                    AssemblyName = fileName,
                    Namespace = "PE.Structure",
                    Name = "Sections",
                    FullName = "PE.Structure.Sections",
                    Kind = "Module",
                    IsSystemOrEngine = false,
                    Fields = sectionFields
                });
            }

            // 2. PE Exports
            var exportMethods = new List<MethodEntry>();
            if (peImage.Exports is not null)
            {
                foreach (var export in peImage.Exports.Entries)
                {
                    string exportName = export.IsByName ? (export.Name ?? $"Ordinal_{export.Ordinal}") : $"Ordinal_{export.Ordinal}";
                    if (export.IsForwarder)
                    {
                        exportMethods.Add(new MethodEntry
                        {
                            Name = exportName,
                            ReturnType = "forwarder",
                            ParametersSignature = export.ForwarderName ?? string.Empty,
                            Modifiers = $"ordinal {export.Ordinal}",
                            Rva = OffsetValue.Partial(OffsetKind.ExportRva, null, fileName, "PE Export Directory", $"Forwarded to {export.ForwarderName}"),
                            VirtualAddress = OffsetValue.Partial(OffsetKind.ExportVirtualAddress, null, fileName, "PE Export Directory", $"Forwarded to {export.ForwarderName}"),
                            FileOffset = OffsetValue.Unresolved(OffsetKind.ExportFileOffset, fileName, "PE Export Directory", "Forwarded export has no local code body."),
                            OverallStatus = ResolutionStatus.Partial,
                            Confidence = ConfidenceLevel.Medium,
                            SourceFile = fileName,
                            ExtractionMethod = "PE Export Directory (Forwarder)",
                            Notes = $"Forwarded to {export.ForwarderName}"
                        });
                        continue;
                    }

                    uint rva = export.Address.Rva;
                    ulong va = imageBase + rva;
                    ulong fileOffset = 0;
                    bool hasRaw = false;
                    try
                    {
                        fileOffset = peFile.RvaToFileOffset(rva);
                        hasRaw = true;
                    }
                    catch { }

                    exportMethods.Add(new MethodEntry
                    {
                        Name = exportName,
                        ReturnType = "export",
                        ParametersSignature = string.Empty,
                        Modifiers = $"ordinal {export.Ordinal}",
                        Rva = OffsetValue.Confirmed(OffsetKind.ExportRva, rva, fileName, "PE Export Directory"),
                        VirtualAddress = OffsetValue.Confirmed(OffsetKind.ExportVirtualAddress, va, fileName, "PE Export Directory"),
                        FileOffset = hasRaw
                            ? OffsetValue.Confirmed(OffsetKind.ExportFileOffset, fileOffset, fileName, "PE Section RvaToFileOffset")
                            : OffsetValue.Unresolved(OffsetKind.ExportFileOffset, fileName, "PE Section RvaToFileOffset", "RVA is outside raw file sections."),
                        OverallStatus = hasRaw ? ResolutionStatus.Confirmed : ResolutionStatus.Partial,
                        Confidence = ConfidenceLevel.High,
                        SourceFile = fileName,
                        ExtractionMethod = "PE Export Directory"
                    });
                }
            }

            if (exportMethods.Count > 0)
            {
                types.Add(new TypeEntry
                {
                    AssemblyName = fileName,
                    Namespace = "PE.Exports",
                    Name = "ExportedSymbols",
                    FullName = "PE.Exports.ExportedSymbols",
                    Kind = "Module",
                    IsSystemOrEngine = false,
                    Methods = exportMethods
                });
            }

            // 3. PE Imports (grouped by imported DLL)
            if (peImage.Imports.Count > 0)
            {
                var importMethods = new List<MethodEntry>();
                foreach (var mod in peImage.Imports)
                {
                    string modName = mod.Name ?? "<unknown>";
                    foreach (var sym in mod.Symbols)
                    {
                        string symName = sym.IsImportByName ? (sym.Name ?? $"Ordinal_{sym.Ordinal}") : $"Ordinal_{sym.Ordinal}";
                        importMethods.Add(new MethodEntry
                        {
                            Name = $"{modName}!{symName}",
                            ReturnType = "import",
                            ParametersSignature = string.Empty,
                            Modifiers = "extern",
                            Rva = OffsetValue.Unresolved(OffsetKind.MethodRva, fileName, "PE Import Directory", "Imported symbol IAT slot is bound at runtime by the Windows loader."),
                            VirtualAddress = OffsetValue.Unresolved(OffsetKind.MethodVirtualAddress, fileName, "PE Import Directory", "Resolved at load time by Windows loader."),
                            FileOffset = OffsetValue.Unresolved(OffsetKind.MethodFileOffset, fileName, "PE Import Directory", "External symbol."),
                            OverallStatus = ResolutionStatus.Unresolved,
                            Confidence = ConfidenceLevel.None,
                            SourceFile = fileName,
                            ExtractionMethod = "PE Import Directory",
                            Notes = $"Imported from {modName}; address resolved at runtime by Windows loader."
                        });
                    }
                }

                if (importMethods.Count > 0)
                {
                    types.Add(new TypeEntry
                    {
                        AssemblyName = fileName,
                        Namespace = "PE.Imports",
                        Name = "ImportedSymbols",
                        FullName = "PE.Imports.ImportedSymbols",
                        Kind = "Module",
                        IsSystemOrEngine = true,
                        Methods = importMethods
                    });
                }
            }

            // 4. Debug PDB path if present
            foreach (var dbg in peImage.DebugData)
            {
                if (dbg.Contents is not null)
                {
                    logger.Info("PEAnalysis", $"Debug directory entry found in {fileName}: {dbg.Contents.Type}.");
                }
            }

            if (types.Count > 0)
            {
                results.Add(new AssemblyEntry
                {
                    Name = $"{fileName} (PE Native)",
                    SourcePath = filePath,
                    IsSystemOrEngine = false,
                    Types = types
                });
            }

            logger.Info("PEAnalysis", $"Extracted {sectionFields.Count} PE sections and {exportMethods.Count} exported symbols from {fileName}.");
        }
        catch (Exception ex)
        {
            logger.Error("PEAnalysis", $"Failed to inspect PE binary '{fileName}': {ex.Message}");
        }

        return results;
    }
}
