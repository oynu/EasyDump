using System.Buffers.Binary;
using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;

namespace EasyDump.Core.Detection;

/// <summary>
/// Extracts the Unity engine version from UnityPlayer.dll, globalgamemanagers,
/// data.unity3d (UnityFS bundle), or boot.config.
/// </summary>
public static partial class UnityVersionDetector
{
    [GeneratedRegex(@"\b((?:19|20|6000|[45])\d{0,3}\.\d+\.\d+[a-z]\d+)\b", RegexOptions.Compiled)]
    private static partial Regex UnityVersionRegex();

    public static (string? Version, string? Source) Detect(string rootOrDataDirectory)
    {
        if (string.IsNullOrWhiteSpace(rootOrDataDirectory) || !Directory.Exists(rootOrDataDirectory))
            return (null, null);

        // 1. Check UnityPlayer.dll (Windows standalone builds)
        var unityPlayer = Path.Combine(rootOrDataDirectory, "UnityPlayer.dll");
        if (!File.Exists(unityPlayer))
        {
            var parent = Directory.GetParent(rootOrDataDirectory)?.FullName;
            if (parent is not null)
            {
                var candidate = Path.Combine(parent, "UnityPlayer.dll");
                if (File.Exists(candidate))
                    unityPlayer = candidate;
            }
        }

        if (File.Exists(unityPlayer))
        {
            var ver = TryReadFromPeVersionInfo(unityPlayer);
            if (ver is not null)
                return (ver, "UnityPlayer.dll (PE FileVersionInfo)");
        }

        // Locate *_Data directory
        var dataDirs = new List<string>();
        if (rootOrDataDirectory.EndsWith("_Data", StringComparison.OrdinalIgnoreCase))
            dataDirs.Add(rootOrDataDirectory);

        try
        {
            dataDirs.AddRange(Directory.GetDirectories(rootOrDataDirectory, "*_Data", SearchOption.TopDirectoryOnly));
        }
        catch
        {
            // Ignore enumeration errors
        }

        var assetsBinData = Path.Combine(rootOrDataDirectory, "assets", "bin", "Data");
        if (Directory.Exists(assetsBinData))
            dataDirs.Add(assetsBinData);

        foreach (var dataDir in dataDirs.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            // 2. globalgamemanagers / mainData / level0
            foreach (var assetFile in new[] { "globalgamemanagers", "mainData", "level0" })
            {
                var path = Path.Combine(dataDir, assetFile);
                if (File.Exists(path))
                {
                    var ver = TryReadFromSerializedFile(path);
                    if (ver is not null)
                        return (ver, $"{assetFile} (Unity SerializedFile header)");
                }
            }

            // 3. data.unity3d (UnityFS bundle)
            var bundlePath = Path.Combine(dataDir, "data.unity3d");
            if (File.Exists(bundlePath))
            {
                var ver = TryReadFromUnityFsBundle(bundlePath);
                if (ver is not null)
                    return (ver, "data.unity3d (UnityFS header)");
            }
        }

        // 4. Executable PE VersionInfo as final fallback (older Unity 4/5 builds without UnityPlayer.dll)
        try
        {
            foreach (var exe in Directory.EnumerateFiles(rootOrDataDirectory, "*.exe", SearchOption.TopDirectoryOnly))
            {
                if (Path.GetFileName(exe).Contains("CrashHandler", StringComparison.OrdinalIgnoreCase))
                    continue;
                var ver = TryReadFromPeVersionInfo(exe);
                if (ver is not null)
                    return (ver, $"{Path.GetFileName(exe)} (PE FileVersionInfo)");
            }
        }
        catch
        {
            // Ignore
        }

        return (null, null);
    }

    public static string? TryReadFromPeVersionInfo(string filePath)
    {
        try
        {
            var info = FileVersionInfo.GetVersionInfo(filePath);
            foreach (var candidate in new[] { info.ProductVersion, info.FileVersion })
            {
                if (string.IsNullOrWhiteSpace(candidate))
                    continue;

                var match = UnityVersionRegex().Match(candidate);
                if (match.Success)
                    return match.Groups[1].Value;
            }
        }
        catch
        {
            // Ignore
        }
        return null;
    }

    /// <summary>
    /// Parses Unity SerializedFile header (globalgamemanagers / level0 / mainData)
    /// to extract the embedded Unity version string safely.
    /// </summary>
    public static string? TryReadFromSerializedFile(string filePath)
    {
        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            int toRead = (int)Math.Min(fs.Length, 4096);
            if (toRead < 24)
                return null;

            byte[] buf = new byte[toRead];
            int read = fs.Read(buf, 0, toRead);
            if (read < 24)
                return null;

            // SerializedFile header:
            // 0x00: uint32 metadataSize (BE)
            // 0x04: uint32 fileSize (BE)
            // 0x08: uint32 formatVersion (BE)
            // 0x0C: uint32 dataOffset (BE)
            // 0x10: byte endianness, 3 reserved bytes
            // If formatVersion >= 22: 0x14..0x2F are large-file 64-bit sizes, version string starts at 0x30
            // If formatVersion < 22 and >= 9: version string starts at 0x14
            uint formatVersion = BinaryPrimitives.ReadUInt32BigEndian(buf.AsSpan(8, 4));
            int stringOffset = formatVersion >= 22 && formatVersion < 100 ? 0x30 : 0x14;

            if (stringOffset < read)
            {
                var candidate = ReadNullTerminatedAscii(buf, stringOffset, 48);
                if (candidate is not null)
                {
                    var match = UnityVersionRegex().Match(candidate);
                    if (match.Success)
                        return match.Groups[1].Value;
                }
            }

            // Fallback scan of header bytes in case of minor format variance
            var ascii = Encoding.ASCII.GetString(buf, 0, Math.Min(read, 512));
            var fallbackMatch = UnityVersionRegex().Match(ascii);
            return fallbackMatch.Success ? fallbackMatch.Groups[1].Value : null;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Parses a UnityFS bundle header (data.unity3d) where the exact Unity version
    /// follows "UnityFS\0", format uint32 (BE), and player version string ("5.x.x\0").
    /// </summary>
    public static string? TryReadFromUnityFsBundle(string filePath)
    {
        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            int toRead = (int)Math.Min(fs.Length, 512);
            if (toRead < 24)
                return null;

            byte[] buf = new byte[toRead];
            int read = fs.Read(buf, 0, toRead);
            if (read < 24)
                return null;

            // Signature: "UnityFS\0"
            if (!buf.AsSpan(0, 8).SequenceEqual("UnityFS\0"u8))
                return null;

            int pos = 8 + 4; // skip signature + format uint32
            // Skip player version string (e.g. "5.x.x\0")
            while (pos < read && buf[pos] != 0) pos++;
            pos++; // skip null terminator

            if (pos >= read)
                return null;

            var engineVersion = ReadNullTerminatedAscii(buf, pos, 48);
            if (engineVersion is null)
                return null;

            var match = UnityVersionRegex().Match(engineVersion);
            return match.Success ? match.Groups[1].Value : null;
        }
        catch
        {
            return null;
        }
    }

    private static string? ReadNullTerminatedAscii(byte[] buf, int offset, int maxLen)
    {
        int end = offset;
        int limit = Math.Min(buf.Length, offset + maxLen);
        while (end < limit && buf[end] != 0)
            end++;
        if (end == offset)
            return null;
        return Encoding.ASCII.GetString(buf, offset, end - offset);
    }
}
