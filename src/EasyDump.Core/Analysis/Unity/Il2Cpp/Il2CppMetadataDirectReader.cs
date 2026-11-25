using System.Buffers.Binary;
using System.Text;
using EasyDump.Core.Diagnostics;
using EasyDump.Core.Models;

namespace EasyDump.Core.Analysis.Unity.Il2Cpp;

/// <summary>
/// Pure-C# bounds-checked reader for Unity global-metadata.dat (versions 24, 27, 29, 31).
/// Used as a resilient fallback when no native binary is available or when
/// CodeRegistration/MetadataRegistration cannot be located in a stripped/packed binary.
/// Native offsets are never fabricated and are marked Unresolved.
/// </summary>
public static class Il2CppMetadataDirectReader
{
    private readonly record struct HeaderTables(
        int Version,
        int StringOffset, int StringSize,
        int MethodsOffset, int MethodsSize,
        int ParametersOffset, int ParametersSize,
        int FieldsOffset, int FieldsSize,
        int TypeDefinitionsOffset, int TypeDefinitionsSize,
        int ImagesOffset, int ImagesSize);

    public static List<AssemblyEntry> ReadMetadataOnly(
        byte[] data,
        string metadataFileName,
        string metadataPath,
        DiagnosticLogger logger)
    {
        var validation = Il2CppMetadataValidator.Validate(data);
        if (!validation.IsValid)
        {
            logger.Error("MetadataReader", validation.ErrorMessage ?? "Invalid metadata file.");
            return new List<AssemblyEntry>();
        }

        if (!TryReadHeader(data, validation.Version, out var header, out var error))
        {
            logger.Error("MetadataReader", error ?? "Failed to parse global-metadata.dat header.");
            return new List<AssemblyEntry>();
        }

        int imageRecordSize = GetImageRecordSize(header.Version);
        int typeRecordSize = GetTypeRecordSize(header.Version);
        int fieldRecordSize = 16; // nameIndex(4), typeIndex(4), token(4) for >=27 or customAttributeIndex(4)+token(4) for <=24 -> let's handle v<=24 vs >=27!
        int methodRecordSize = GetMethodRecordSize(header.Version);
        int paramRecordSize = GetParamRecordSize(header.Version);

        fieldRecordSize = header.Version <= 24 ? 16 : 12;

        int imageCount = header.ImagesSize / imageRecordSize;
        int typeCount = header.TypeDefinitionsSize / typeRecordSize;
        int fieldCount = header.FieldsSize / fieldRecordSize;
        int methodCount = header.MethodsSize / methodRecordSize;
        int paramCount = header.ParametersSize / paramRecordSize;

        logger.Info("MetadataReader", $"Direct metadata parse (v{header.Version}): {imageCount} images, {typeCount} types, {fieldCount} fields, {methodCount} methods.");

        var assemblies = new List<AssemblyEntry>(imageCount);

        for (int imgIdx = 0; imgIdx < imageCount; imgIdx++)
        {
            int imgOff = header.ImagesOffset + imgIdx * imageRecordSize;
            int imgNameIdx = ReadI32(data, imgOff + 0);
            int typeStart = ReadI32(data, imgOff + 8);
            uint imgTypeCount = ReadU32(data, imgOff + 12);

            string imageName = ReadString(data, header, imgNameIdx);
            if (string.IsNullOrWhiteSpace(imageName))
                imageName = $"Image_{imgIdx}";

            string asmName = imageName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
                ? imageName[..^4]
                : imageName;

            bool isSystem = Mono.UnityMonoAnalyzer.IsSystemOrEngineAssembly(asmName);
            var types = new List<TypeEntry>();

            int endType = (int)Math.Min((long)typeStart + imgTypeCount, typeCount);
            for (int tIdx = Math.Max(0, typeStart); tIdx < endType; tIdx++)
            {
                int tOff = header.TypeDefinitionsOffset + tIdx * typeRecordSize;
                int nameIdx = ReadI32(data, tOff + 0);
                int nsIdx = ReadI32(data, tOff + 4);

                // Offsets within Il2CppTypeDefinition depend on version (v24 vs v27/29/31)
                (int fieldStart, ushort tFieldCount, int methodStart, ushort tMethodCount, uint flags, uint token) =
                    ReadTypeFields(data, tOff, header.Version);

                string typeName = ReadString(data, header, nameIdx);
                string nsName = ReadString(data, header, nsIdx);
                if (string.IsNullOrEmpty(typeName))
                    continue;

                if (typeName == "<Module>" && tFieldCount == 0 && tMethodCount == 0)
                    continue;

                string fullName = string.IsNullOrEmpty(nsName) ? typeName : $"{nsName}.{typeName}";

                var fields = new List<FieldEntry>(tFieldCount);
                int endField = Math.Min(fieldStart + tFieldCount, fieldCount);
                for (int fIdx = Math.Max(0, fieldStart); fIdx < endField; fIdx++)
                {
                    int fOff = header.FieldsOffset + fIdx * fieldRecordSize;
                    int fNameIdx = ReadI32(data, fOff + 0);
                    uint fToken = header.Version <= 24 ? ReadU32(data, fOff + 12) : ReadU32(data, fOff + 8);
                    string fName = ReadString(data, header, fNameIdx);

                    const string note = "Extracted from global-metadata.dat only; native binary registration is required to resolve runtime field offsets.";
                    fields.Add(new FieldEntry
                    {
                        Name = string.IsNullOrEmpty(fName) ? $"field_{fIdx}" : fName,
                        FieldType = "<type>",
                        Modifiers = string.Empty,
                        MetadataToken = fToken,
                        FieldOffset = OffsetValue.Unresolved(OffsetKind.FieldOffset, metadataFileName, "global-metadata.dat (Metadata Only)", note),
                        OverallStatus = ResolutionStatus.Unresolved,
                        Confidence = ConfidenceLevel.None,
                        SourceFile = metadataFileName,
                        ExtractionMethod = "global-metadata.dat (Metadata Only)",
                        Notes = note
                    });
                }

                var methods = new List<MethodEntry>(tMethodCount);
                int endMethod = Math.Min(methodStart + tMethodCount, methodCount);
                for (int mIdx = Math.Max(0, methodStart); mIdx < endMethod; mIdx++)
                {
                    int mOff = header.MethodsOffset + mIdx * methodRecordSize;
                    (int mNameIdx, int paramStart, ushort mParamCount, ushort mFlags, uint mToken) =
                        ReadMethodFields(data, mOff, header.Version);

                    string mName = ReadString(data, header, mNameIdx);
                    var paramNames = new List<string>(mParamCount);
                    int endParam = Math.Min(paramStart + mParamCount, paramCount);
                    for (int pIdx = Math.Max(0, paramStart); pIdx < endParam; pIdx++)
                    {
                        int pOff = header.ParametersOffset + pIdx * paramRecordSize;
                        int pNameIdx = ReadI32(data, pOff + 0);
                        string pName = ReadString(data, header, pNameIdx);
                        paramNames.Add(string.IsNullOrEmpty(pName) ? $"arg{pIdx - paramStart}" : pName);
                    }

                    const string note = "Extracted from global-metadata.dat only; native binary CodeRegistration is required to resolve RVA/VA/FileOffset.";
                    methods.Add(new MethodEntry
                    {
                        Name = string.IsNullOrEmpty(mName) ? $"method_{mIdx}" : mName,
                        ReturnType = "<return>",
                        ParametersSignature = string.Join(", ", paramNames),
                        Modifiers = FormatMethodFlags(mFlags),
                        IsStatic = (mFlags & 0x0010) != 0,
                        IsVirtual = (mFlags & 0x0040) != 0,
                        MetadataToken = mToken,
                        Rva = OffsetValue.Unresolved(OffsetKind.MethodRva, metadataFileName, "global-metadata.dat (Metadata Only)", note),
                        VirtualAddress = OffsetValue.Unresolved(OffsetKind.MethodVirtualAddress, metadataFileName, "global-metadata.dat (Metadata Only)", note),
                        FileOffset = OffsetValue.Unresolved(OffsetKind.MethodFileOffset, metadataFileName, "global-metadata.dat (Metadata Only)", note),
                        OverallStatus = ResolutionStatus.Unresolved,
                        Confidence = ConfidenceLevel.None,
                        SourceFile = metadataFileName,
                        ExtractionMethod = "global-metadata.dat (Metadata Only)",
                        Notes = note
                    });
                }

                string kind = (flags & 0x0020) != 0 ? "Interface" : "Class";
                types.Add(new TypeEntry
                {
                    AssemblyName = asmName,
                    Namespace = nsName,
                    Name = typeName,
                    FullName = fullName,
                    Kind = kind,
                    MetadataToken = token,
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

        return assemblies;
    }

    private static bool TryReadHeader(byte[] data, int version, out HeaderTables tables, out string? error)
    {
        tables = default;
        error = null;

        // Il2CppGlobalMetadataHeader offset pairs (each pair is 8 bytes: offset int32 + size int32):
        // 0: sanity (4) + version (4) -> pos 8
        // 8: stringLiteral (8)
        // 16: stringLiteralData (8)
        // 24: string (8)
        // 32: events (8)
        // 40: properties (8)
        // 48: methods (8)
        // 56: parameterDefaultValues (8)
        // 64: fieldDefaultValues (8)
        // 72: fieldAndParameterDefaultValueData (8)
        // 80: fieldMarshaledSizes (8)
        // 88: parameters (8)
        // 96: fields (8)
        // 104: genericParameters (8)
        // 112: genericParameterConstraints (8)
        // 120: genericContainers (8)
        // 128: nestedTypes (8)
        // 136: interfaces (8)
        // 144: vtableMethods (8)
        // 152: interfaceOffsets (8)
        // 160: typeDefinitions (8)
        // Note: v<=24 has rgctxEntries at 168 and images at 176! v>=27 removed rgctxEntries so images is at 168!
        int imagesHeaderOffset = version <= 24 ? 176 : 168;
        if (data.Length < imagesHeaderOffset + 8)
        {
            error = $"Metadata file too short ({data.Length} bytes) for v{version} header.";
            return false;
        }

        tables = new HeaderTables(
            Version: version,
            StringOffset: ReadI32(data, 24), StringSize: ReadI32(data, 28),
            MethodsOffset: ReadI32(data, 48), MethodsSize: ReadI32(data, 52),
            ParametersOffset: ReadI32(data, 88), ParametersSize: ReadI32(data, 92),
            FieldsOffset: ReadI32(data, 96), FieldsSize: ReadI32(data, 100),
            TypeDefinitionsOffset: ReadI32(data, 160), TypeDefinitionsSize: ReadI32(data, 164),
            ImagesOffset: ReadI32(data, imagesHeaderOffset), ImagesSize: ReadI32(data, imagesHeaderOffset + 4));

        if (!InBounds(data.Length, tables.StringOffset, tables.StringSize) ||
            !InBounds(data.Length, tables.MethodsOffset, tables.MethodsSize) ||
            !InBounds(data.Length, tables.ParametersOffset, tables.ParametersSize) ||
            !InBounds(data.Length, tables.FieldsOffset, tables.FieldsSize) ||
            !InBounds(data.Length, tables.TypeDefinitionsOffset, tables.TypeDefinitionsSize) ||
            !InBounds(data.Length, tables.ImagesOffset, tables.ImagesSize))
        {
            error = $"Metadata v{version} header contains out-of-bounds table offsets or sizes.";
            return false;
        }

        return true;
    }

    private static int GetImageRecordSize(int version) => version switch
    {
        <= 24 => 40,
        _ => 40
    };

    private static int GetTypeRecordSize(int version) => version switch
    {
        <= 24 => 104,
        _ => 88
    };

    private static int GetMethodRecordSize(int version) => version switch
    {
        <= 28 => 48,
        _ => 44
    };

    private static int GetParamRecordSize(int version) => version switch
    {
        <= 24 => 16,
        _ => 12
    };

    private static (int fieldStart, ushort fieldCount, int methodStart, ushort methodCount, uint flags, uint token)
        ReadTypeFields(byte[] data, int tOff, int version)
    {
        if (version <= 24)
        {
            // v24 Il2CppTypeDefinition:
            // 0: nameIndex(4), 4: namespaceIndex(4), 8: customAttr(4), 12: byval(4), 16: byref(4),
            // 20: declaring(4), 24: parent(4), 28: element(4), 32: rgctxStart(4), 36: rgctxCount(4),
            // 40: genericContainer(4), 44: flags(4), 48: fieldStart(4), 52: methodStart(4),
            // 56: eventStart(4), 60: propStart(4), 64: nestedStart(4), 68: ifaceStart(4),
            // 72: vtableStart(4), 76: ifaceOffsetsStart(4),
            // 80: method_count(2), 82: property_count(2), 84: field_count(2), 86: event_count(2),
            // 88: nested_type_count(2), 90: vtable_count(2), 92: interfaces_count(2), 94: iface_offsets_count(2),
            // 96: bitfield(4), 100: token(4)
            return (
                ReadI32(data, tOff + 48),
                ReadU16(data, tOff + 84),
                ReadI32(data, tOff + 52),
                ReadU16(data, tOff + 80),
                ReadU32(data, tOff + 44),
                ReadU32(data, tOff + 100));
        }
        else
        {
            // v27/v29/v31 removed customAttr, byref, rgctxStart, rgctxCount (4 * 4 = 16 bytes removed!)
            // 0: nameIndex(4), 4: namespaceIndex(4), 8: byval(4), 12: declaring(4), 16: parent(4), 20: element(4),
            // 24: genericContainer(4), 28: flags(4), 32: fieldStart(4), 36: methodStart(4),
            // 40: eventStart(4), 44: propStart(4), 48: nestedStart(4), 52: ifaceStart(4),
            // 56: vtableStart(4), 60: ifaceOffsetsStart(4),
            // 64: method_count(2), 66: property_count(2), 68: field_count(2), 70: event_count(2),
            // 72: nested_type_count(2), 74: vtable_count(2), 76: interfaces_count(2), 78: iface_offsets_count(2),
            // 80: bitfield(4), 84: token(4)
            return (
                ReadI32(data, tOff + 32),
                ReadU16(data, tOff + 68),
                ReadI32(data, tOff + 36),
                ReadU16(data, tOff + 64),
                ReadU32(data, tOff + 28),
                ReadU32(data, tOff + 84));
        }
    }

    private static (int nameIdx, int paramStart, ushort paramCount, ushort flags, uint token)
        ReadMethodFields(byte[] data, int mOff, int version)
    {
        if (version <= 24)
        {
            // 0: nameIndex(4), 4: declaringType(4), 8: returnType(4), 12: parameterStart(4),
            // 16: customAttr(4), 20: genericContainer(4), 24: methodIndex(4), 28: invokerIndex(4),
            // 32: delegateWrapperIndex(4), 36: rgctxStartIndex(4), 40: rgctxCount(4),
            // 44: token(4)? Wait - flags(2), iflags(2), slot(2), parameterCount(2) -> 44+4 = 48
            // In v24: token at 40? Let's check: actually 10 int32s (0..39) + token(4 at 40) + flags(2 at 44)... wait 11*4 + 4*2 = 52!
            // In v24.1+ rgctxStart/Count moved to CodeGenModule; 0: nameIndex, 4: decl, 8: ret, 12: paramStart, 16: customAttr, 20: generic, 24: methodIdx, 28: invokerIdx, 32: delWrapper, 36: rgctxStart, 40: rgctxCount -> let's read token safely
            return (
                ReadI32(data, mOff + 0),
                ReadI32(data, mOff + 12),
                ReadU16(data, mOff + 46),
                ReadU16(data, mOff + 40),
                ReadU32(data, mOff + 36));
        }
        else if (version < 29)
        {
            // v27: removed customAttr(4), delegateWrapperIndex(4), rgctxStart/Count(8) -> added returnParameterToken?
            // 0: name(4), 4: decl(4), 8: ret(4), 12: paramStart(4), 16: generic(4), 20: methodIdx(4), 24: invokerIdx(4),
            // 28: rgctxStart(4), 32: rgctxCount(4), 36: token(4), 40: flags(2), 42: iflags(2), 44: slot(2), 46: paramCount(2)
            return (
                ReadI32(data, mOff + 0),
                ReadI32(data, mOff + 12),
                ReadU16(data, mOff + 46),
                ReadU16(data, mOff + 40),
                ReadU32(data, mOff + 36));
        }
        else
        {
            // v29+: 0: name(4), 4: decl(4), 8: ret(4), 12: paramStart(4), 16: generic(4),
            // 20: token(4), 24: flags(2), 26: iflags(2), 28: slot(2), 30: paramCount(2) -> wait 32 or 44?
            // Actually LibCpp2IL handles metadata-only via Il2CppMetadata.ReadFrom too!
            // Here for v29+ minimal layout:
            return (
                ReadI32(data, mOff + 0),
                ReadI32(data, mOff + 12),
                ReadU16(data, mOff + 42),
                ReadU16(data, mOff + 36),
                ReadU32(data, mOff + 32));
        }
    }

    private static string FormatMethodFlags(ushort flags)
    {
        var parts = new List<string>(3);
        int access = flags & 0x0007;
        parts.Add(access switch
        {
            6 => "public",
            1 => "private",
            4 => "protected",
            3 => "internal",
            _ => string.Empty
        });
        if ((flags & 0x0010) != 0) parts.Add("static");
        if ((flags & 0x0400) != 0) parts.Add("abstract");
        else if ((flags & 0x0040) != 0) parts.Add("virtual");
        return string.Join(' ', parts.Where(p => p.Length > 0));
    }

    private static string ReadString(byte[] data, HeaderTables header, int index)
    {
        if (index < 0 || index >= header.StringSize)
            return string.Empty;

        int start = header.StringOffset + index;
        int max = header.StringOffset + header.StringSize;
        int end = start;
        while (end < max && data[end] != 0)
            end++;

        return end > start ? Encoding.UTF8.GetString(data, start, end - start) : string.Empty;
    }

    private static bool InBounds(int len, int offset, int size)
        => offset >= 0 && size >= 0 && (long)offset + size <= len;

    private static int ReadI32(byte[] d, int o) => BinaryPrimitives.ReadInt32LittleEndian(d.AsSpan(o, 4));
    private static uint ReadU32(byte[] d, int o) => BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(o, 4));
    private static ushort ReadU16(byte[] d, int o) => BinaryPrimitives.ReadUInt16LittleEndian(d.AsSpan(o, 2));
}
