# EasyDump — Game Offset Dumper

**EasyDump** is a lightweight, native Windows (.NET 8 WPF) desktop utility for extracting, browsing, verifying, and exporting offsets from local game installations and binaries, with primary focus on **Unity (IL2CPP and Mono)** and modular best-effort support for **non-Unity PE/ELF/.NET binaries**.

## Features

- **Automatic Game & Engine Detection**
  - Detects **Unity IL2CPP** (`GameAssembly.dll`, `libil2cpp.so`, `global-metadata.dat`), **Unity Mono** (`*_Data/Managed/*.dll`, `MonoBleedingEdge`), **Unreal Engine**, **Godot**, and standalone **.NET / PE / ELF** binaries.
  - Detects **architecture** (`X64`, `X86`, `Arm64`, `Arm32`), **Unity version** (`UnityPlayer.dll` PE version info, `globalgamemanagers` SerializedFile header, `data.unity3d` UnityFS bundle header), and **IL2CPP metadata version**.
  - Supports folder selection, single-file selection, and full-window drag-and-drop.
- **Unity IL2CPP Analysis**
  - Validates `global-metadata.dat` magic (`0xFAB11BAF`), version compatibility, and table bounds before parsing.
  - Uses `AssetRipper.LibCpp2IL` to resolve `CodeRegistration` & `MetadataRegistration`, extracting classes, fields (`MetadataRegistration.fieldOffsets`), and methods (`RVA`, `Virtual Address`, `File Offset`, `Metadata Token`).
  - Automatically falls back to bounds-checked metadata-only parsing (`Il2CppMetadata.ReadFrom` + `Il2CppMetadataDirectReader`) when no native binary is present or when registration resolution fails — clearly marking unresolved native addresses instead of guessing.
- **Unity Mono Analysis**
  - Safely inspects managed assemblies via `AsmResolver.DotNet` without loading or executing game code.
  - Extracts namespaces, classes, structs, enums, interfaces, fields, explicit `[FieldOffset]` / `FieldRVA` values, and CIL method RVAs / Virtual Addresses / File Offsets.
  - Never fabricates runtime Mono instance field offsets; auto/sequential fields are honestly marked `Unresolved` with explanatory notes.
- **Modular Non-Unity Inspection**
  - **Windows PE**: sections, exported symbols (RVA, VA, File Offset, forwarders), imported symbols, and embedded .NET metadata.
  - **ELF32 / ELF64**: `PT_LOAD` segments, sections, `.dynsym` / `.symtab` functions and objects with mapped VA, RVA, and File Offset.
- **Verification & Provenance**
  - Every extracted value carries `Status` (`Confirmed`, `Partial`, `Unresolved`), `Confidence`, `SourceFile`, `ExtractionMethod`, and `Notes`.
  - Structured diagnostics log drawer for troubleshooting incomplete or obfuscated files.
- **Fast UI & Export**
  - Minimalistic dark WPF interface with subtle blue accents, virtualized type/member lists, debounced search, filters (`Game Only`, `Confirmed`, Sort), one-click copy, input fingerprinting cache, and **JSON / TXT / CSV** export (`All`, `Filtered`, `SelectedAssembly`, `SelectedType`).

## Architecture

- `src/EasyDump.Core/` — Platform-independent detection, analysis, diagnostics, caching, and export engine:
  - `Models/` — Domain models (`OffsetValue`, `GameDetectionResult`, `AssemblyEntry`, `TypeEntry`, `FieldEntry`, `MethodEntry`, `AnalysisResult`)
  - `Detection/` — `BinaryFormatDetector`, `UnityVersionDetector`, `GameDetector`
  - `Analysis/Unity/Il2Cpp/` — `Il2CppMetadataValidator`, `Il2CppMetadataDirectReader`, `UnityIl2CppAnalyzer`
  - `Analysis/Unity/Mono/` — `UnityMonoAnalyzer`
  - `Analysis/Generic/` — `PeBinaryInspector`, `ElfBinaryReader`, `GenericBinaryAnalyzer`
  - `Analysis/AnalysisOrchestrator.cs` — Fingerprinting cache and analyzer dispatch
  - `Export/` — `JsonResultExporter`, `TxtResultExporter`, `CsvResultExporter`
- `src/EasyDump.App/` — Native .NET 8 WPF desktop application (MVVM via `CommunityToolkit.Mvvm`).
- `tests/EasyDump.Tests/` & `tests/EasyDump.SampleMonoFixture/` — Automated xUnit tests using real compiled assemblies and binary fixtures.

## Build & Run

```powershell
# Build Release
dotnet build EasyDump.sln -c Release

# Run automated tests
dotnet test EasyDump.sln -c Release

# Launch desktop app
dotnet run --project src\EasyDump.App\EasyDump.App.csproj -c Release
```
