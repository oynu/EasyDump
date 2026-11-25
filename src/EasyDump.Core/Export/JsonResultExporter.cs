using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using EasyDump.Core.Models;

namespace EasyDump.Core.Export;

public sealed class JsonResultExporter : IResultExporter
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    public ExportFormat Format => ExportFormat.Json;
    public string FileExtension => ".json";

    public async Task ExportAsync(ExportRequest request, string outputPath, CancellationToken cancellationToken = default)
    {
        string json = RenderToString(request);
        await File.WriteAllTextAsync(outputPath, json, cancellationToken).ConfigureAwait(false);
    }

    public string RenderToString(ExportRequest request)
    {
        var r = request.Result;
        var payload = new
        {
            tool = "EasyDump",
            exportedAtUtc = DateTime.UtcNow,
            scope = request.Scope.ToString(),
            scopeDescription = request.ScopeDescription,
            game = new
            {
                name = r.Detection.GameName,
                engine = r.Detection.Engine.ToString(),
                unityVersion = r.Detection.UnityVersion,
                unityVersionSource = r.Detection.UnityVersionSource,
                architecture = r.Detection.Architecture.ToString(),
                metadataVersion = r.Detection.MetadataVersion,
                inputPath = r.Detection.InputPath
            },
            summary = new
            {
                assemblies = request.AssembliesToExport.Count,
                types = request.AssembliesToExport.Sum(a => a.TotalTypes),
                fields = request.AssembliesToExport.Sum(a => a.TotalFields),
                methods = request.AssembliesToExport.Sum(a => a.TotalMethods),
                confirmedOffsets = request.AssembliesToExport.Sum(a => a.ConfirmedOffsets),
                partialOffsets = request.AssembliesToExport.Sum(a => a.PartialOffsets),
                unresolvedOffsets = request.AssembliesToExport.Sum(a => a.UnresolvedOffsets)
            },
            assemblies = request.AssembliesToExport.Select(a => new
            {
                name = a.Name,
                sourcePath = a.SourcePath,
                isSystemOrEngine = a.IsSystemOrEngine,
                types = a.Types.Select(t => new
                {
                    @namespace = t.Namespace,
                    name = t.Name,
                    fullName = t.FullName,
                    kind = t.Kind,
                    baseType = t.BaseType,
                    token = t.MetadataToken.HasValue ? $"0x{t.MetadataToken.Value:X8}" : null,
                    fields = t.Fields.Select(f => new
                    {
                        name = f.Name,
                        type = f.FieldType,
                        modifiers = f.Modifiers,
                        isStatic = f.IsStatic,
                        isConst = f.IsConst,
                        constantValue = f.ConstantValue,
                        token = f.MetadataToken.HasValue ? $"0x{f.MetadataToken.Value:X8}" : null,
                        fieldOffset = f.FieldOffset?.Value is not null ? f.FieldOffset.DisplayValue : null,
                        fieldRva = f.FieldRva?.Value is not null ? f.FieldRva.DisplayValue : null,
                        status = f.OverallStatus.ToString(),
                        confidence = f.Confidence.ToString(),
                        sourceFile = f.SourceFile,
                        extractionMethod = f.ExtractionMethod,
                        notes = f.Notes
                    }),
                    methods = t.Methods.Select(m => new
                    {
                        name = m.Name,
                        returnType = m.ReturnType,
                        parameters = m.ParametersSignature,
                        modifiers = m.Modifiers,
                        isStatic = m.IsStatic,
                        isVirtual = m.IsVirtual,
                        token = m.MetadataToken.HasValue ? $"0x{m.MetadataToken.Value:X8}" : null,
                        rva = m.Rva?.Value is not null ? m.Rva.DisplayValue : null,
                        virtualAddress = m.VirtualAddress?.Value is not null ? m.VirtualAddress.DisplayValue : null,
                        fileOffset = m.FileOffset?.Value is not null ? m.FileOffset.DisplayValue : null,
                        status = m.OverallStatus.ToString(),
                        confidence = m.Confidence.ToString(),
                        sourceFile = m.SourceFile,
                        extractionMethod = m.ExtractionMethod,
                        notes = m.Notes
                    })
                })
            })
        };

        return JsonSerializer.Serialize(payload, SerializerOptions);
    }
}
