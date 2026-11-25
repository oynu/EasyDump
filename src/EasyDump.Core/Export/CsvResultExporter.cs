using System.Text;
using EasyDump.Core.Models;

namespace EasyDump.Core.Export;

public sealed class CsvResultExporter : IResultExporter
{
    public ExportFormat Format => ExportFormat.Csv;
    public string FileExtension => ".csv";

    public async Task ExportAsync(ExportRequest request, string outputPath, CancellationToken cancellationToken = default)
    {
        string csv = RenderToString(request);
        await File.WriteAllTextAsync(outputPath, csv, new UTF8Encoding(encoderShouldEmitUTF8Identifier: true), cancellationToken)
            .ConfigureAwait(false);
    }

    public string RenderToString(ExportRequest request)
    {
        var sb = new StringBuilder(16 * 1024);
        sb.AppendLine("Assembly,Namespace,Type,MemberKind,MemberName,SignatureOrType,Modifiers,FieldOffset,RVA,VirtualAddress,FileOffset,Token,Status,Confidence,SourceFile,ExtractionMethod,Notes");

        foreach (var asm in request.AssembliesToExport)
        {
            foreach (var type in asm.Types)
            {
                foreach (var f in type.Fields)
                {
                    WriteRow(sb,
                        asm.Name,
                        type.Namespace,
                        type.Name,
                        "Field",
                        f.Name,
                        f.FieldType,
                        f.Modifiers,
                        f.FieldOffset?.Value is not null ? f.FieldOffset.DisplayValue : "",
                        f.FieldRva?.Value is not null ? f.FieldRva.DisplayValue : "",
                        "",
                        "",
                        f.TokenHex == "—" ? "" : f.TokenHex,
                        f.OverallStatus.ToString(),
                        f.Confidence.ToString(),
                        f.SourceFile,
                        f.ExtractionMethod,
                        f.Notes ?? "");
                }

                foreach (var m in type.Methods)
                {
                    WriteRow(sb,
                        asm.Name,
                        type.Namespace,
                        type.Name,
                        "Method",
                        m.Name,
                        m.FullSignature,
                        m.Modifiers,
                        "",
                        m.Rva?.Value is not null ? m.Rva.DisplayValue : "",
                        m.VirtualAddress?.Value is not null ? m.VirtualAddress.DisplayValue : "",
                        m.FileOffset?.Value is not null ? m.FileOffset.DisplayValue : "",
                        m.TokenHex == "—" ? "" : m.TokenHex,
                        m.OverallStatus.ToString(),
                        m.Confidence.ToString(),
                        m.SourceFile,
                        m.ExtractionMethod,
                        m.Notes ?? "");
                }
            }
        }

        return sb.ToString();
    }

    private static void WriteRow(StringBuilder sb, params string[] fields)
    {
        for (int i = 0; i < fields.Length; i++)
        {
            if (i > 0) sb.Append(',');
            sb.Append(EscapeCsv(fields[i]));
        }
        sb.AppendLine();
    }

    private static string EscapeCsv(string? value)
    {
        if (string.IsNullOrEmpty(value))
            return string.Empty;

        bool mustQuote = value.Contains(',') || value.Contains('"') || value.Contains('\n') || value.Contains('\r');
        if (!mustQuote)
            return value;

        return $"\"{value.Replace("\"", "\"\"")}\"";
    }
}
