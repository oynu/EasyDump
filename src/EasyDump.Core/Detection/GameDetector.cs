using EasyDump.Core.Diagnostics;
using EasyDump.Core.Models;

namespace EasyDump.Core.Detection;

/// <summary>
/// Detects game engine, architecture, Unity version, metadata version,
/// and relevant binary/metadata files from a user-supplied folder or file.
/// </summary>
public sealed class GameDetector
{
    public GameDetectionResult Detect(string inputPath)
    {
        var logger = new DiagnosticLogger();

        if (string.IsNullOrWhiteSpace(inputPath))
        {
            logger.Error("Detection", "No path was provided.");
            return new GameDetectionResult
            {
                InputPath = inputPath ?? string.Empty,
                GameName = "Unknown",
                Engine = GameEngineType.Unknown,
                Architecture = ArchitectureType.Unknown,
                Diagnostics = logger.Snapshot()
            };
        }

        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(inputPath.Trim().Trim('"'));
        }
        catch (Exception ex)
        {
            logger.Error("Detection", "Invalid path format.", ex.Message);
            return new GameDetectionResult
            {
                InputPath = inputPath,
                GameName = "Invalid Path",
                Engine = GameEngineType.Unknown,
                Architecture = ArchitectureType.Unknown,
                Diagnostics = logger.Snapshot()
            };
        }

        bool isDir = Directory.Exists(fullPath);
        bool isFile = !isDir && File.Exists(fullPath);

        if (!isDir && !isFile)
        {
            logger.Error("Detection", $"Path does not exist: {fullPath}");
            return new GameDetectionResult
            {
                InputPath = fullPath,
                GameName = Path.GetFileName(fullPath),
                Engine = GameEngineType.Unknown,
                Architecture = ArchitectureType.Unknown,
                Diagnostics = logger.Snapshot()
            };
        }

        string rootDir = ResolveGameRoot(fullPath, isDir);
        string gameName = InferGameName(fullPath, rootDir, isDir);
        var detectedFiles = new List<DetectedFile>();

        // 1. Check for Unity (IL2CPP or Mono) within rootDir or directly supplied file
        var unityResult = TryDetectUnity(fullPath, isFile, rootDir, gameName, detectedFiles, logger);
        if (unityResult is not null)
            return unityResult;

        // 2. Check for Unreal Engine
        var unrealResult = TryDetectUnreal(fullPath, isFile, rootDir, gameName, detectedFiles, logger);
        if (unrealResult is not null)
            return unrealResult;

        // 3. Check for Godot
        var godotResult = TryDetectGodot(fullPath, isFile, rootDir, gameName, detectedFiles, logger);
        if (godotResult is not null)
            return godotResult;

        // 4. Fallback: standalone .NET, PE, or ELF binary
        return DetectGenericBinary(fullPath, isFile, rootDir, gameName, detectedFiles, logger);
    }

    private static string ResolveGameRoot(string fullPath, bool isDir)
    {
        if (isDir)
        {
            var dirName = Path.GetFileName(fullPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
            if (dirName.EndsWith("_Data", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(dirName, "Managed", StringComparison.OrdinalIgnoreCase))
            {
                var parent = Directory.GetParent(fullPath);
                if (parent is not null)
                {
                    if (string.Equals(dirName, "Managed", StringComparison.OrdinalIgnoreCase) &&
                        parent.Name.EndsWith("_Data", StringComparison.OrdinalIgnoreCase))
                    {
                        return parent.Parent?.FullName ?? parent.FullName;
                    }
                    return parent.FullName;
                }
            }
            return fullPath;
        }

        // Single file: walk up if it's inside Unity structures (e.g. *_Data/il2cpp_data/Metadata/global-metadata.dat or *_Data/Managed/Assembly-CSharp.dll)
        var fileDir = Path.GetDirectoryName(fullPath)!;
        var fileName = Path.GetFileName(fullPath);

        if (string.Equals(fileName, "global-metadata.dat", StringComparison.OrdinalIgnoreCase))
        {
            var cur = new DirectoryInfo(fileDir);
            for (int i = 0; i < 5 && cur is not null; i++)
            {
                if (File.Exists(Path.Combine(cur.FullName, "GameAssembly.dll")) ||
                    File.Exists(Path.Combine(cur.FullName, "GameAssembly.so")) ||
                    File.Exists(Path.Combine(cur.FullName, "UnityPlayer.dll")))
                {
                    return cur.FullName;
                }
                if (cur.Name.EndsWith("_Data", StringComparison.OrdinalIgnoreCase) && cur.Parent is not null)
                    return cur.Parent.FullName;
                cur = cur.Parent;
            }
        }

        var parentDir = new DirectoryInfo(fileDir);
        if (string.Equals(parentDir.Name, "Managed", StringComparison.OrdinalIgnoreCase) &&
            parentDir.Parent is { } dataParent &&
            dataParent.Name.EndsWith("_Data", StringComparison.OrdinalIgnoreCase) &&
            dataParent.Parent is not null)
        {
            return dataParent.Parent.FullName;
        }

        return fileDir;
    }

    private static string InferGameName(string fullPath, string rootDir, bool isDir)
    {
        if (isDir)
        {
            // Prefer *_Data folder prefix if present
            try
            {
                var dataDir = Directory.GetDirectories(rootDir, "*_Data", SearchOption.TopDirectoryOnly).FirstOrDefault();
                if (dataDir is not null)
                {
                    var name = Path.GetFileName(dataDir);
                    if (name.Length > 5)
                        return name[..^5];
                }
            }
            catch { }

            return Path.GetFileName(rootDir.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        }

        // Single file: if root has *_Data, use that; otherwise file name without extension
        try
        {
            var dataDir = Directory.GetDirectories(rootDir, "*_Data", SearchOption.TopDirectoryOnly).FirstOrDefault();
            if (dataDir is not null)
            {
                var name = Path.GetFileName(dataDir);
                if (name.Length > 5)
                    return name[..^5];
            }
        }
        catch { }

        var baseName = Path.GetFileNameWithoutExtension(fullPath);
        return string.IsNullOrWhiteSpace(baseName) ? Path.GetFileName(fullPath) : baseName;
    }

    private static GameDetectionResult? TryDetectUnity(
        string fullPath,
        bool isFile,
        string rootDir,
        string gameName,
        List<DetectedFile> detectedFiles,
        DiagnosticLogger logger)
    {
        // Locate candidate IL2CPP files
        string? il2cppBinary = null;
        string? metadataFile = null;
        string? managedDir = null;

        if (isFile)
        {
            var fn = Path.GetFileName(fullPath);
            if (fn.Equals("global-metadata.dat", StringComparison.OrdinalIgnoreCase))
                metadataFile = fullPath;
            else if (fn.Equals("GameAssembly.dll", StringComparison.OrdinalIgnoreCase) ||
                     fn.Equals("GameAssembly.so", StringComparison.OrdinalIgnoreCase) ||
                     fn.Equals("libil2cpp.so", StringComparison.OrdinalIgnoreCase))
                il2cppBinary = fullPath;
        }

        // Search rootDir for standard Unity files
        il2cppBinary ??= FindFirstExisting(
            Path.Combine(rootDir, "GameAssembly.dll"),
            Path.Combine(rootDir, "GameAssembly.so"),
            Path.Combine(rootDir, "libil2cpp.so"));

        // Android unpacked / nested libil2cpp.so
        if (il2cppBinary is null)
        {
            try
            {
                il2cppBinary = Directory.EnumerateFiles(rootDir, "libil2cpp.so", SearchOption.AllDirectories)
                    .OrderByDescending(p => p.Contains("arm64", StringComparison.OrdinalIgnoreCase))
                    .FirstOrDefault();
            }
            catch { }
        }

        // Find *_Data directory
        var dataDirs = SafeGetDirectories(rootDir, "*_Data");
        if (Path.GetFileName(rootDir).EndsWith("_Data", StringComparison.OrdinalIgnoreCase))
            dataDirs.Add(rootDir);

        foreach (var dataDir in dataDirs)
        {
            metadataFile ??= FindFirstExisting(
                Path.Combine(dataDir, "il2cpp_data", "Metadata", "global-metadata.dat"),
                Path.Combine(dataDir, "Managed", "Metadata", "global-metadata.dat"));

            var candidateManaged = Path.Combine(dataDir, "Managed");
            if (managedDir is null && Directory.Exists(candidateManaged) &&
                Directory.EnumerateFiles(candidateManaged, "*.dll").Any())
            {
                managedDir = candidateManaged;
            }
        }

        // Android / alternative metadata locations
        metadataFile ??= FindFirstExisting(
            Path.Combine(rootDir, "global-metadata.dat"),
            Path.Combine(rootDir, "il2cpp_data", "Metadata", "global-metadata.dat"),
            Path.Combine(rootDir, "assets", "bin", "Data", "Managed", "Metadata", "global-metadata.dat"));

        if (metadataFile is null && il2cppBinary is not null)
        {
            try
            {
                metadataFile = Directory.EnumerateFiles(rootDir, "global-metadata.dat", SearchOption.AllDirectories)
                    .FirstOrDefault();
            }
            catch { }
        }

        // Single managed DLL dropped directly (if it looks like Unity or inside Managed)
        bool singleManagedDll = isFile &&
            fullPath.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) &&
            BinaryFormatDetector.InspectFile(fullPath).IsDotNetAssembly &&
            (Path.GetFileName(Path.GetDirectoryName(fullPath) ?? "").Equals("Managed", StringComparison.OrdinalIgnoreCase) ||
             Path.GetFileName(fullPath).StartsWith("Assembly-CSharp", StringComparison.OrdinalIgnoreCase));

        bool hasUnityPlayer = File.Exists(Path.Combine(rootDir, "UnityPlayer.dll"));
        bool hasMonoDir = Directory.Exists(Path.Combine(rootDir, "MonoBleedingEdge")) ||
                          Directory.Exists(Path.Combine(rootDir, "Mono"));

        if (il2cppBinary is null && metadataFile is null && managedDir is null && !singleManagedDll && !hasUnityPlayer)
            return null;

        var (unityVersion, unityVersionSource) = UnityVersionDetector.Detect(rootDir);
        if (unityVersion is not null)
            logger.Info("Detection", $"Detected Unity version {unityVersion} via {unityVersionSource}.");

        // Determine Unity IL2CPP vs Mono
        if (il2cppBinary is not null || metadataFile is not null)
        {
            var arch = ArchitectureType.Unknown;
            int? metadataVersion = null;

            if (il2cppBinary is not null)
            {
                var binInfo = BinaryFormatDetector.InspectFile(il2cppBinary);
                arch = binInfo.Architecture;
                AddDetectedFile(detectedFiles, il2cppBinary, "IL2CPP Native Binary", binInfo);
                logger.Info("Detection", $"Found IL2CPP native binary: {Path.GetFileName(il2cppBinary)} ({binInfo.Format}, {arch}).");
            }
            else
            {
                logger.Warning("Detection", "IL2CPP global-metadata.dat found, but no native IL2CPP binary (GameAssembly.dll / libil2cpp.so) was located. Native offsets cannot be resolved without the binary.");
            }

            if (metadataFile is not null)
            {
                var metaInfo = BinaryFormatDetector.InspectFile(metadataFile);
                metadataVersion = metaInfo.MetadataVersion;
                AddDetectedFile(detectedFiles, metadataFile, "IL2CPP Metadata", metaInfo);
                if (metaInfo.Warning is not null)
                    logger.Warning("MetadataValidation", metaInfo.Warning);
                else
                    logger.Info("Detection", $"Found IL2CPP metadata: {Path.GetFileName(metadataFile)} (v{metadataVersion}).");
            }
            else
            {
                logger.Warning("Detection", "IL2CPP native binary found, but global-metadata.dat was not located. Metadata symbols cannot be extracted without global-metadata.dat.");
            }

            if (hasUnityPlayer)
            {
                var upPath = Path.Combine(rootDir, "UnityPlayer.dll");
                var upInfo = BinaryFormatDetector.InspectFile(upPath);
                if (arch == ArchitectureType.Unknown)
                    arch = upInfo.Architecture;
                AddDetectedFile(detectedFiles, upPath, "Unity Engine Runtime", upInfo);
            }

            return new GameDetectionResult
            {
                InputPath = fullPath,
                GameName = gameName,
                Engine = GameEngineType.UnityIl2Cpp,
                UnityVersion = unityVersion,
                UnityVersionSource = unityVersionSource,
                Architecture = arch,
                MetadataVersion = metadataVersion,
                Files = detectedFiles,
                PrimaryBinaryPath = il2cppBinary,
                MetadataPath = metadataFile,
                Diagnostics = logger.Snapshot()
            };
        }

        // Unity Mono
        if (managedDir is not null || singleManagedDll)
        {
            var arch = ArchitectureType.Unknown;
            if (hasUnityPlayer)
            {
                var upPath = Path.Combine(rootDir, "UnityPlayer.dll");
                var upInfo = BinaryFormatDetector.InspectFile(upPath);
                arch = upInfo.Architecture;
                AddDetectedFile(detectedFiles, upPath, "Unity Engine Runtime", upInfo);
            }
            else if (isFile)
            {
                var fInfo = BinaryFormatDetector.InspectFile(fullPath);
                arch = fInfo.Architecture;
            }

            // Try inspecting game exe architecture if still unknown
            if (arch == ArchitectureType.Unknown)
            {
                var mainExe = Directory.EnumerateFiles(rootDir, "*.exe", SearchOption.TopDirectoryOnly)
                    .FirstOrDefault(e => !Path.GetFileName(e).Contains("CrashHandler", StringComparison.OrdinalIgnoreCase));
                if (mainExe is not null)
                {
                    var exeInfo = BinaryFormatDetector.InspectFile(mainExe);
                    arch = exeInfo.Architecture;
                    AddDetectedFile(detectedFiles, mainExe, "Game Executable", exeInfo);
                }
            }

            if (managedDir is not null)
            {
                var dlls = Directory.GetFiles(managedDir, "*.dll", SearchOption.TopDirectoryOnly);
                foreach (var dll in dlls.OrderBy(p => p, StringComparer.OrdinalIgnoreCase))
                {
                    var role = Path.GetFileName(dll).StartsWith("Assembly-CSharp", StringComparison.OrdinalIgnoreCase)
                        ? "Primary Game Assembly"
                        : "Managed Assembly";
                    AddDetectedFile(detectedFiles, dll, role, BinaryFormatDetector.InspectFile(dll));
                }
                logger.Info("Detection", $"Detected Unity Mono build with {dlls.Length} managed assemblies in {managedDir}.");
            }
            else if (singleManagedDll)
            {
                var info = BinaryFormatDetector.InspectFile(fullPath);
                AddDetectedFile(detectedFiles, fullPath, "Managed Assembly", info);
                logger.Info("Detection", $"Detected standalone Unity Mono managed assembly: {Path.GetFileName(fullPath)}.");
            }

            if (hasMonoDir)
                logger.Info("Detection", "Detected Mono runtime directory.");

            return new GameDetectionResult
            {
                InputPath = fullPath,
                GameName = gameName,
                Engine = GameEngineType.UnityMono,
                UnityVersion = unityVersion,
                UnityVersionSource = unityVersionSource,
                Architecture = arch,
                Files = detectedFiles,
                PrimaryBinaryPath = isFile ? fullPath : null,
                ManagedDirectoryPath = managedDir,
                Diagnostics = logger.Snapshot()
            };
        }

        // UnityPlayer.dll exists, but neither Managed nor IL2CPP metadata/GameAssembly found (incomplete installation)
        var unityInfo = BinaryFormatDetector.InspectFile(Path.Combine(rootDir, "UnityPlayer.dll"));
        AddDetectedFile(detectedFiles, Path.Combine(rootDir, "UnityPlayer.dll"), "Unity Engine Runtime", unityInfo);
        logger.Warning("Detection", "UnityPlayer.dll found, but neither Managed assemblies nor IL2CPP files (GameAssembly.dll / global-metadata.dat) were found. Installation may be incomplete.");

        return new GameDetectionResult
        {
            InputPath = fullPath,
            GameName = gameName,
            Engine = GameEngineType.UnityMono,
            UnityVersion = unityVersion,
            UnityVersionSource = unityVersionSource,
            Architecture = unityInfo.Architecture,
            Files = detectedFiles,
            PrimaryBinaryPath = Path.Combine(rootDir, "UnityPlayer.dll"),
            Diagnostics = logger.Snapshot()
        };
    }

    private static GameDetectionResult? TryDetectUnreal(
        string fullPath,
        bool isFile,
        string rootDir,
        string gameName,
        List<DetectedFile> detectedFiles,
        DiagnosticLogger logger)
    {
        var engineBinaries = Path.Combine(rootDir, "Engine", "Binaries");
        var hasPak = false;
        try
        {
            hasPak = Directory.EnumerateFiles(rootDir, "*.pak", SearchOption.AllDirectories).Take(1).Any();
        }
        catch { }

        string? shippingExe = null;
        try
        {
            shippingExe = Directory.EnumerateFiles(rootDir, "*-Shipping.exe", SearchOption.AllDirectories).FirstOrDefault()
                       ?? Directory.EnumerateFiles(rootDir, "*.exe", SearchOption.TopDirectoryOnly)
                           .FirstOrDefault(e => Directory.Exists(engineBinaries));
        }
        catch { }

        if (!Directory.Exists(engineBinaries) && !(hasPak && shippingExe is not null))
            return null;

        var targetBinary = isFile ? fullPath : shippingExe;
        if (targetBinary is null)
        {
            try
            {
                targetBinary = Directory.EnumerateFiles(rootDir, "*.exe", SearchOption.AllDirectories)
                    .FirstOrDefault(e => !Path.GetFileName(e).Contains("CrashReport", StringComparison.OrdinalIgnoreCase));
            }
            catch { }
        }

        var arch = ArchitectureType.Unknown;
        if (targetBinary is not null)
        {
            var info = BinaryFormatDetector.InspectFile(targetBinary);
            arch = info.Architecture;
            AddDetectedFile(detectedFiles, targetBinary, "Unreal Binary", info);
        }

        logger.Info("Detection", "Detected Unreal Engine installation. Running best-effort native PE inspection (exports/sections); Unreal reflection names require external SDK/PDB dumps if stripped.");

        return new GameDetectionResult
        {
            InputPath = fullPath,
            GameName = gameName,
            Engine = GameEngineType.UnrealEngine,
            Architecture = arch,
            Files = detectedFiles,
            PrimaryBinaryPath = targetBinary,
            Diagnostics = logger.Snapshot()
        };
    }

    private static GameDetectionResult? TryDetectGodot(
        string fullPath,
        bool isFile,
        string rootDir,
        string gameName,
        List<DetectedFile> detectedFiles,
        DiagnosticLogger logger)
    {
        string? pckFile = null;
        try
        {
            pckFile = Directory.EnumerateFiles(rootDir, "*.pck", SearchOption.TopDirectoryOnly).FirstOrDefault();
        }
        catch { }

        if (pckFile is null)
            return null;

        string? exeFile = isFile && fullPath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
            ? fullPath
            : Directory.EnumerateFiles(rootDir, "*.exe", SearchOption.TopDirectoryOnly).FirstOrDefault();

        var arch = ArchitectureType.Unknown;
        if (exeFile is not null)
        {
            var info = BinaryFormatDetector.InspectFile(exeFile);
            arch = info.Architecture;
            AddDetectedFile(detectedFiles, exeFile, "Godot Executable", info);
        }

        logger.Info("Detection", $"Detected Godot project package ({Path.GetFileName(pckFile)}). Running best-effort binary inspection.");

        return new GameDetectionResult
        {
            InputPath = fullPath,
            GameName = gameName,
            Engine = GameEngineType.Godot,
            Architecture = arch,
            Files = detectedFiles,
            PrimaryBinaryPath = exeFile,
            Diagnostics = logger.Snapshot()
        };
    }

    private static GameDetectionResult DetectGenericBinary(
        string fullPath,
        bool isFile,
        string rootDir,
        string gameName,
        List<DetectedFile> detectedFiles,
        DiagnosticLogger logger)
    {
        string? targetBinary = isFile ? fullPath : null;
        if (targetBinary is null)
        {
            try
            {
                targetBinary = Directory.EnumerateFiles(rootDir, "*.exe", SearchOption.TopDirectoryOnly).FirstOrDefault()
                            ?? Directory.EnumerateFiles(rootDir, "*.dll", SearchOption.TopDirectoryOnly).FirstOrDefault()
                            ?? Directory.EnumerateFiles(rootDir, "*.so", SearchOption.TopDirectoryOnly).FirstOrDefault();
            }
            catch { }
        }

        if (targetBinary is null)
        {
            logger.Warning("Detection", "No supported game files or executables were found in the selected directory.");
            return new GameDetectionResult
            {
                InputPath = fullPath,
                GameName = gameName,
                Engine = GameEngineType.Unknown,
                Architecture = ArchitectureType.Unknown,
                Files = detectedFiles,
                Diagnostics = logger.Snapshot()
            };
        }

        var info = BinaryFormatDetector.InspectFile(targetBinary);
        GameEngineType engine = info.Format switch
        {
            BinaryFormatType.PE when info.IsDotNetAssembly => GameEngineType.DotNetStandalone,
            BinaryFormatType.PE => GameEngineType.NativePe,
            BinaryFormatType.Elf => GameEngineType.NativeElf,
            _ => GameEngineType.Unknown
        };

        AddDetectedFile(detectedFiles, targetBinary, "Primary Binary", info);
        if (info.Warning is not null)
            logger.Warning("Detection", info.Warning);
        else
            logger.Info("Detection", $"Identified {engine} binary: {Path.GetFileName(targetBinary)} ({info.Format}, {info.Architecture}).");

        return new GameDetectionResult
        {
            InputPath = fullPath,
            GameName = gameName,
            Engine = engine,
            Architecture = info.Architecture,
            Files = detectedFiles,
            PrimaryBinaryPath = targetBinary,
            Diagnostics = logger.Snapshot()
        };
    }

    private static string? FindFirstExisting(params string[] paths)
        => paths.FirstOrDefault(File.Exists);

    private static List<string> SafeGetDirectories(string root, string pattern)
    {
        try
        {
            return Directory.GetDirectories(root, pattern, SearchOption.TopDirectoryOnly).ToList();
        }
        catch
        {
            return new List<string>();
        }
    }

    private static void AddDetectedFile(List<DetectedFile> list, string path, string role, BinaryHeaderInfo info)
    {
        try
        {
            var fi = new FileInfo(path);
            list.Add(new DetectedFile(path, role, info.Format, info.Architecture, fi.Length, fi.LastWriteTimeUtc));
        }
        catch
        {
            list.Add(new DetectedFile(path, role, info.Format, info.Architecture, 0, DateTime.MinValue));
        }
    }
}
