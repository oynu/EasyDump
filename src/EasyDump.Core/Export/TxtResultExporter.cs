using System.Text;
using EasyDump.Core.Models;

namespace EasyDump.Core.Export;

public sealed class TxtResultExporter : IResultExporter
{
    public ExportFormat Format => ExportFormat.Txt;
    public string FileExtension => ".txt";

    public async Task ExportAsync(ExportRequest request, string outputPath, CancellationToken cancellationToken = default)
    {
        string text = RenderToString(request);
        await File.WriteAllTextAsync(outputPath, text, Encoding.UTF8, cancellationToken).ConfigureAwait(false);
    }

    public string RenderToString(ExportRequest request)
    {
        var sb = new StringBuilder(16 * 1024);
        var r = request.Result;

        sb.AppendLine("// ============================================================================");
        sb.AppendLine($"// EasyDump Offset Report — {r.Detection.GameName}");
        sb.AppendLine($"// Engine       : {r.Detection.Engine}");
        if (!string.IsNullOrWhiteSpace(r.Detection.UnityVersion))
            sb.AppendLine($"// Unity Version: {r.Detection.UnityVersion} ({r.Detection.UnityVersionSource})");
        sb.AppendLine($"// Architecture : {r.Detection.Architecture}");
        if (r.Detection.MetadataVersion.HasValue)
            sb.AppendLine($"// Metadata Ver : v{r.Detection.MetadataVersion.Value}");
        sb.AppendLine($"// Scope        : {request.Scope}{(request.ScopeDescription is not null ? $" ({request.ScopeDescription})" : "")}");
        sb.AppendLine($"// Exported UTC : {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine("// ============================================================================");
        sb.AppendLine();

        foreach (var asm in request.AssembliesToExport)
        {
            sb.AppendLine($"// Assembly: {asm.Name} ({asm.TotalTypes} types, {asm.SourcePath})");
            foreach (var type in asm.Types)
            {
                string nsPrefix = string.IsNullOrWhiteSpace(type.Namespace) ? string.Empty : $"{type.Namespace}.";
                string baseSuffix = string.IsNullOrWhiteSpace(type.BaseType) ? string.Empty : $" : {type.BaseType}";
                sb.AppendLine($"// Token: {type.TokenHex} | Assembly: {type.AssemblyName}");
                sb.AppendLine($"{type.Kind.ToLowerInvariant()} {nsPrefix}{type.Name}{baseSuffix}");
                sb.AppendLine("{");

                if (type.Fields.Count > 0)
                {
                    sb.AppendLine("    // Fields");
                    foreach (var f in type.Fields)
                    {
                        string mod = string.IsNullOrWhiteSpace(f.Modifiers) ? string.Empty : f.Modifiers + " ";
                        string constPart = f.ConstantValue is not null ? $" = {f.ConstantValue}" : string.Empty;
                        string offsetPart = f.FieldOffset?.Value is not null
                            ? $"Offset: {f.FieldOffset.DisplayValue}"
                            : f.FieldRva?.Value is not null
                                ? $"FieldRVA: {f.FieldRva.DisplayValue}"
                                : "Offset: Unresolved";

                        sb.AppendLine($"    {mod}{f.FieldType} {f.Name}{constPart}; // {offsetPart} | Token: {f.TokenHex} | [{f.OverallStatus}] ({f.ExtractionMethod})");
                    }
                }

                if (type.Methods.Count > 0)
                {
                    if (type.Fields.Count > 0) sb.AppendLine();
                    sb.AppendLine("    // Methods");
                    foreach (var m in type.Methods)
                    {
                        string mod = string.IsNullOrWhiteSpace(m.Modifiers) ? string.Empty : m.Modifiers + " ";
                        sb.AppendLine($"    // RVA: {m.RvaDisplay} | VA: {m.VirtualAddressDisplay} | FileOffset: {m.FileOffsetDisplay} | Token: {m.TokenHex} | [{m.OverallStatus}] ({m.ExtractionMethod})");
                        sb.AppendLine($"    {mod}{m.ReturnType} {m.Name}({m.ParametersSignature});");
                    }
                }

                sb.AppendLine("}");
                sb.AppendLine();
            }
        }

        return sb.ToString();
    }
}
