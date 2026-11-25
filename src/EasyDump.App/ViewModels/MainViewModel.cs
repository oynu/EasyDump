using System.Collections.ObjectModel;
using System.IO;
using System.Text;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using EasyDump.Core.Analysis;
using EasyDump.Core.Export;
using EasyDump.Core.Models;
using Microsoft.Win32;

namespace EasyDump.App.ViewModels;

public enum MemberSortMode
{
    Name = 0,
    Members = 1,
    Offset = 2
}

public sealed record AssemblyChoice(string Name, AssemblyEntry? Assembly, int TypeCount, bool IsSystemOrEngine)
{
    public string DisplayLabel => Assembly is null
        ? $"All Assemblies ({TypeCount:N0} types)"
        : IsSystemOrEngine
            ? $"{Name} ({TypeCount:N0}) [Engine/System]"
            : $"{Name} ({TypeCount:N0})";
}

public sealed record DetailOffsetRow(
    string Label,
    string ValueText,
    string CopyValue,
    bool HasCopyValue,
    ResolutionStatus Status,
    string SourceFile,
    string ExtractionMethod,
    string? Notes);

public sealed partial class MainViewModel : ObservableObject
{
    private readonly IAnalysisOrchestrator _orchestrator;
    private readonly IReadOnlyDictionary<ExportFormat, IResultExporter> _exporters;
    private CancellationTokenSource? _analysisCts;
    private CancellationTokenSource? _filterDebounceCts;
    private CancellationTokenSource? _toastCts;

    private GameDetectionResult? _currentDetection;
    private AnalysisResult? _currentResult;

    public MainViewModel()
        : this(
            new AnalysisOrchestrator(),
            new IResultExporter[]
            {
                new JsonResultExporter(),
                new TxtResultExporter(),
                new CsvResultExporter()
            })
    {
    }

    public MainViewModel(IAnalysisOrchestrator orchestrator, IEnumerable<IResultExporter> exporters)
    {
        _orchestrator = orchestrator;
        _exporters = exporters.ToDictionary(e => e.Format);
    }

    // --- Game Selection ---
    [ObservableProperty] private string? _selectedPath;
    [ObservableProperty] private string _gameName = "No game selected";
    [ObservableProperty] private string _engineDisplay = "—";
    [ObservableProperty] private string _unityVersionDisplay = "—";
    [ObservableProperty] private string _architectureDisplay = "—";
    [ObservableProperty] private string _metadataVersionDisplay = "—";
    [ObservableProperty] private bool _hasSelection;
    [ObservableProperty] private bool _isUnityGame;

    public ObservableCollection<DetectedFile> DetectedFiles { get; } = new();

    // --- Analysis State ---
    [ObservableProperty] private bool _isAnalyzing;
    [ObservableProperty] private double _progressPercent;
    [ObservableProperty] private bool _isIndeterminate;
    [ObservableProperty] private string _currentStage = "Ready";
    [ObservableProperty] private string _statusMessage = "Select a game folder or binary to begin.";
    [ObservableProperty] private bool _hasError;
    [ObservableProperty] private string? _errorBannerMessage;
    [ObservableProperty] private bool _hasResults;
    [ObservableProperty] private bool _isFromCache;
    [ObservableProperty] private string _durationDisplay = "";

    // --- Results & Filtering ---
    [ObservableProperty] private string _searchQuery = string.Empty;
    [ObservableProperty] private bool _hideSystemAssemblies = true;
    [ObservableProperty] private bool _confirmedOnly;
    [ObservableProperty] private MemberSortMode _sortMode = MemberSortMode.Name;

    public IReadOnlyList<MemberSortMode> SortModes { get; } = new[]
    {
        MemberSortMode.Name,
        MemberSortMode.Members,
        MemberSortMode.Offset
    };

    public ObservableCollection<AssemblyChoice> AssemblyChoices { get; } = new();
    [ObservableProperty] private AssemblyChoice? _selectedAssemblyChoice;

    public ObservableCollection<TypeEntry> FilteredTypes { get; } = new();
    [ObservableProperty] private TypeEntry? _selectedType;

    public ObservableCollection<FieldEntry> VisibleFields { get; } = new();
    public ObservableCollection<MethodEntry> VisibleMethods { get; } = new();
    [ObservableProperty] private int _selectedMemberTabIndex;

    [ObservableProperty] private FieldEntry? _selectedField;
    [ObservableProperty] private MethodEntry? _selectedMethod;

    // --- Details Inspector ---
    [ObservableProperty] private string _inspectorTitle = "Select a field or method";
    [ObservableProperty] private string _inspectorSubtitle = "Click any row in Fields or Methods to inspect provenance, verification status, and copyable offsets.";
    [ObservableProperty] private string _inspectorSignature = string.Empty;
    [ObservableProperty] private ResolutionStatus _inspectorStatus = ResolutionStatus.Unresolved;
    [ObservableProperty] private bool _hasInspectorSelection;
    [ObservableProperty] private string? _inspectorNotes;
    public ObservableCollection<DetailOffsetRow> InspectorOffsets { get; } = new();

    // --- Summary Counts ---
    [ObservableProperty] private int _totalAssembliesCount;
    [ObservableProperty] private int _totalTypesCount;
    [ObservableProperty] private int _confirmedOffsetsCount;
    [ObservableProperty] private int _partialOffsetsCount;
    [ObservableProperty] private int _unresolvedOffsetsCount;

    // --- Export & Diagnostics ---
    [ObservableProperty] private ExportFormat _selectedExportFormat = ExportFormat.Json;
    [ObservableProperty] private ExportScope _selectedExportScope = ExportScope.All;
    [ObservableProperty] private bool _isExportPopupOpen;
    [ObservableProperty] private bool _isDiagnosticsOpen;
    [ObservableProperty] private int _diagnosticCount;
    [ObservableProperty] private int _warningOrErrorCount;
    [ObservableProperty] private string? _toastMessage;
    [ObservableProperty] private bool _isToastVisible;

    public ObservableCollection<DiagnosticMessage> Diagnostics { get; } = new();

    public IReadOnlyList<ExportFormat> ExportFormats { get; } = new[] { ExportFormat.Json, ExportFormat.Txt, ExportFormat.Csv };
    public IReadOnlyList<ExportScope> ExportScopes { get; } = new[] { ExportScope.All, ExportScope.Filtered, ExportScope.SelectedAssembly, ExportScope.SelectedType };

    // --- Property Change Hooks ---
    partial void OnSearchQueryChanged(string value) => ScheduleFilterRefresh();
    partial void OnHideSystemAssembliesChanged(bool value)
    {
        RebuildAssemblyChoices();
        ScheduleFilterRefresh();
    }
    partial void OnConfirmedOnlyChanged(bool value) => ScheduleFilterRefresh();
    partial void OnSortModeChanged(MemberSortMode value) => ScheduleFilterRefresh();

    partial void OnSelectedAssemblyChoiceChanged(AssemblyChoice? value) => ApplyTypeFilter();

    partial void OnSelectedTypeChanged(TypeEntry? value)
    {
        RebuildSelectedTypeMembers();
    }

    partial void OnSelectedFieldChanged(FieldEntry? value)
    {
        if (value is not null)
        {
            SelectedMethod = null;
            PopulateFieldInspector(value);
        }
        else if (SelectedMethod is null)
        {
            ClearInspector();
        }
    }

    partial void OnSelectedMethodChanged(MethodEntry? value)
    {
        if (value is not null)
        {
            SelectedField = null;
            PopulateMethodInspector(value);
        }
        else if (SelectedField is null)
        {
            ClearInspector();
        }
    }

    public void LoadPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return;

        HasError = false;
        ErrorBannerMessage = null;
        SelectedPath = path;

        var detection = _orchestrator.Detect(path);
        _currentDetection = detection;
        HasSelection = true;

        GameName = string.IsNullOrWhiteSpace(detection.GameName) ? "Unknown" : detection.GameName;
        EngineDisplay = FormatEngineName(detection.Engine);
        IsUnityGame = detection.Engine is GameEngineType.UnityIl2Cpp or GameEngineType.UnityMono;
        UnityVersionDisplay = detection.UnityVersion ?? "Not detected";
        ArchitectureDisplay = detection.Architecture == ArchitectureType.Unknown ? "Unknown" : detection.Architecture.ToString();
        MetadataVersionDisplay = detection.MetadataVersion.HasValue ? $"v{detection.MetadataVersion.Value}" : "—";

        DetectedFiles.Clear();
        foreach (var f in detection.Files)
            DetectedFiles.Add(f);

        Diagnostics.Clear();
        foreach (var d in detection.Diagnostics)
            Diagnostics.Add(d);
        UpdateDiagnosticCounts();

        if (detection.Engine == GameEngineType.Unknown && detection.Files.Count == 0)
        {
            HasError = true;
            ErrorBannerMessage = "No supported game binaries or metadata files were detected at the selected path.";
            StatusMessage = ErrorBannerMessage;
        }
        else
        {
            StatusMessage = $"Detected {EngineDisplay} ({ArchitectureDisplay}). Click Start Analysis to extract offsets.";
        }

        // Clear stale results from a previous game
        _currentResult = null;
        HasResults = false;
        AssemblyChoices.Clear();
        FilteredTypes.Clear();
        VisibleFields.Clear();
        VisibleMethods.Clear();
        ClearInspector();

        StartAnalysisCommand.NotifyCanExecuteChanged();
        ForceReanalyzeCommand.NotifyCanExecuteChanged();
        ExportCommand.NotifyCanExecuteChanged();
    }

    private bool CanStartAnalysis() => HasSelection && !IsAnalyzing;
    private bool CanExport() => HasResults && !IsAnalyzing && _currentResult is not null;

    [RelayCommand]
    private void SelectFolder()
    {
        var dlg = new OpenFolderDialog
        {
            Title = "Select Game Installation Folder"
        };
        if (dlg.ShowDialog() == true && !string.IsNullOrWhiteSpace(dlg.FolderName))
        {
            LoadPath(dlg.FolderName);
        }
    }

    [RelayCommand]
    private void SelectFile()
    {
        var dlg = new OpenFileDialog
        {
            Title = "Select Game Executable, Assembly, Binary, or global-metadata.dat",
            Filter = "Supported Game Files|*.exe;*.dll;*.so;global-metadata.dat|Executables & Libraries|*.exe;*.dll;*.so|IL2CPP Metadata|*.dat|All Files|*.*"
        };
        if (dlg.ShowDialog() == true && !string.IsNullOrWhiteSpace(dlg.FileName))
        {
            LoadPath(dlg.FileName);
        }
    }

    [RelayCommand]
    private void SelectProcess()
    {
        var picker = new ProcessPickerWindow
        {
            Owner = Application.Current.MainWindow
        };

        if (picker.ShowDialog() == true && picker.SelectedProcess is { } proc)
        {
            LoadPath(proc.ExecutablePath);
            Diagnostics.Insert(0, new DiagnosticMessage(
                DateTime.UtcNow,
                DiagnosticSeverity.Info,
                "Process",
                $"Selected running process '{proc.ProcessName}' (PID {proc.ProcessId}) -> {proc.ExecutablePath}"));
            UpdateDiagnosticCounts();
        }
    }

    [RelayCommand(CanExecute = nameof(CanStartAnalysis))]
    private Task StartAnalysisAsync() => RunAnalysisAsync(forceReanalyze: false);

    [RelayCommand(CanExecute = nameof(CanStartAnalysis))]
    private Task ForceReanalyzeAsync() => RunAnalysisAsync(forceReanalyze: true);

    private async Task RunAnalysisAsync(bool forceReanalyze)
    {
        if (_currentDetection is null || IsAnalyzing) return;

        _analysisCts?.Cancel();
        _analysisCts?.Dispose();
        _analysisCts = new CancellationTokenSource();
        var ct = _analysisCts.Token;

        IsAnalyzing = true;
        HasError = false;
        ErrorBannerMessage = null;
        ProgressPercent = 0;
        IsIndeterminate = false;
        CurrentStage = "Initializing";
        StatusMessage = "Starting analysis...";
        StartAnalysisCommand.NotifyCanExecuteChanged();
        ForceReanalyzeCommand.NotifyCanExecuteChanged();
        ExportCommand.NotifyCanExecuteChanged();

        var progress = new Progress<AnalysisProgress>(p =>
        {
            CurrentStage = p.Stage;
            StatusMessage = p.Message;
            ProgressPercent = p.Percent;
            IsIndeterminate = p.IsIndeterminate;
        });

        try
        {
            var result = await _orchestrator.AnalyzeAsync(_currentDetection, forceReanalyze, progress, ct);
            _currentResult = result;

            Diagnostics.Clear();
            foreach (var d in result.Diagnostics)
                Diagnostics.Add(d);
            UpdateDiagnosticCounts();

            IsFromCache = result.FromCache;
            DurationDisplay = result.FromCache
                ? "Cached"
                : $"{result.Duration.TotalSeconds:F2}s";

            TotalAssembliesCount = result.TotalAssemblies;
            TotalTypesCount = result.TotalTypes;
            ConfirmedOffsetsCount = result.ConfirmedOffsets;
            PartialOffsetsCount = result.PartialOffsets;
            UnresolvedOffsetsCount = result.UnresolvedOffsets;

            if (!result.Succeeded)
            {
                HasError = true;
                ErrorBannerMessage = result.ErrorMessage ?? "Analysis failed. Check Diagnostics for details.";
                StatusMessage = ErrorBannerMessage;
                HasResults = false;
                IsDiagnosticsOpen = true;
            }
            else
            {
                HasResults = true;
                // Auto-disable "Game Only" if all assemblies are classified as system/engine (e.g. generic or engine-only dump)
                bool hasNonSystem = result.Assemblies.Any(a => !a.IsSystemOrEngine);
                HideSystemAssemblies = hasNonSystem;

                RebuildAssemblyChoices();
                ApplyTypeFilter();

                StatusMessage = $"Extracted {result.TotalTypes:N0} types ({result.ConfirmedOffsets:N0} confirmed offsets) in {DurationDisplay}.";
            }
        }
        catch (OperationCanceledException)
        {
            CurrentStage = "Cancelled";
            StatusMessage = "Analysis cancelled by user.";
        }
        catch (Exception ex)
        {
            HasError = true;
            ErrorBannerMessage = $"Unexpected analysis error: {ex.Message}";
            StatusMessage = ErrorBannerMessage;
            Diagnostics.Add(new DiagnosticMessage(DateTime.UtcNow, DiagnosticSeverity.Error, "UI", ex.Message, ex.ToString()));
            UpdateDiagnosticCounts();
        }
        finally
        {
            IsAnalyzing = false;
            IsIndeterminate = false;
            StartAnalysisCommand.NotifyCanExecuteChanged();
            ForceReanalyzeCommand.NotifyCanExecuteChanged();
            ExportCommand.NotifyCanExecuteChanged();
        }
    }

    [RelayCommand]
    private void CancelAnalysis()
    {
        _analysisCts?.Cancel();
        StatusMessage = "Cancelling...";
    }

    [RelayCommand]
    private void ToggleDiagnostics() => IsDiagnosticsOpen = !IsDiagnosticsOpen;

    [RelayCommand]
    private void ToggleExportPopup() => IsExportPopupOpen = !IsExportPopupOpen;

    [RelayCommand]
    private void CopyText(string? text)
    {
        if (string.IsNullOrWhiteSpace(text) || text == "—") return;
        try
        {
            Clipboard.SetText(text);
            ShowToast($"Copied {TruncateForToast(text)}");
        }
        catch (Exception ex)
        {
            ShowToast($"Clipboard error: {ex.Message}");
        }
    }

    [RelayCommand]
    private void CopyFieldLine(FieldEntry? field)
    {
        if (field is null) return;
        string offsetText = field.FieldOffset?.Value is not null
            ? field.FieldOffset.DisplayValue
            : field.FieldRva?.Value is not null
                ? $"RVA:{field.FieldRva.DisplayValue}"
                : "Unresolved";
        string line = $"{field.Modifiers} {field.FieldType} {field.Name}; // {offsetText} (Token {field.TokenHex}) [{field.OverallStatus}]".Trim();
        CopyText(line);
    }

    [RelayCommand]
    private void CopyMethodLine(MethodEntry? method)
    {
        if (method is null) return;
        string line = $"// RVA: {method.RvaDisplay} | VA: {method.VirtualAddressDisplay} | FileOffset: {method.FileOffsetDisplay} | Token: {method.TokenHex} [{method.OverallStatus}]\n{method.Modifiers} {method.FullSignature};".Trim();
        CopyText(line);
    }

    [RelayCommand]
    private void CopySelectedType()
    {
        if (_currentResult is null || SelectedType is null) return;
        var exporter = _exporters[ExportFormat.Txt];
        var req = new ExportRequest(
            _currentResult,
            new[]
            {
                new AssemblyEntry
                {
                    Name = SelectedType.AssemblyName,
                    IsSystemOrEngine = SelectedType.IsSystemOrEngine,
                    Types = new[] { SelectedType }
                }
            },
            ExportScope.SelectedType,
            SelectedType.FullName);

        CopyText(exporter.RenderToString(req));
    }

    [RelayCommand]
    private void CopyDiagnostics()
    {
        if (Diagnostics.Count == 0) return;
        var text = string.Join(Environment.NewLine, Diagnostics.Select(d => d.FormattedLine));
        CopyText(text);
    }

    [RelayCommand(CanExecute = nameof(CanExport))]
    private async Task ExportAsync()
    {
        if (_currentResult is null) return;

        var assemblies = BuildExportAssemblies();
        if (assemblies.Count == 0 || assemblies.All(a => a.Types.Count == 0))
        {
            ShowToast("Nothing to export for the selected scope.");
            return;
        }

        var exporter = _exporters[SelectedExportFormat];
        string safeGameName = SanitizeFileName(_currentResult.Detection.GameName);
        string defaultName = $"{safeGameName}_offsets{exporter.FileExtension}";

        var dlg = new SaveFileDialog
        {
            Title = "Export Extracted Offsets",
            FileName = defaultName,
            DefaultExt = exporter.FileExtension,
            Filter = SelectedExportFormat switch
            {
                ExportFormat.Json => "JSON Files (*.json)|*.json",
                ExportFormat.Txt => "Text Dump (*.txt)|*.txt",
                ExportFormat.Csv => "CSV Spreadsheet (*.csv)|*.csv",
                _ => "All Files|*.*"
            }
        };

        if (dlg.ShowDialog() != true || string.IsNullOrWhiteSpace(dlg.FileName))
            return;

        try
        {
            IsExportPopupOpen = false;
            var request = new ExportRequest(_currentResult, assemblies, SelectedExportScope, SelectedAssemblyChoice?.Name);
            await exporter.ExportAsync(request, dlg.FileName);
            ShowToast($"Exported to {Path.GetFileName(dlg.FileName)}");
        }
        catch (Exception ex)
        {
            HasError = true;
            ErrorBannerMessage = $"Export failed: {ex.Message}";
            ShowToast("Export failed.");
        }
    }

    private IReadOnlyList<AssemblyEntry> BuildExportAssemblies()
    {
        if (_currentResult is null) return Array.Empty<AssemblyEntry>();

        return SelectedExportScope switch
        {
            ExportScope.All => _currentResult.Assemblies,
            ExportScope.SelectedAssembly => SelectedAssemblyChoice?.Assembly is { } asm
                ? new[] { asm }
                : _currentResult.Assemblies,
            ExportScope.SelectedType => SelectedType is not null
                ? new[]
                {
                    new AssemblyEntry
                    {
                        Name = SelectedType.AssemblyName,
                        IsSystemOrEngine = SelectedType.IsSystemOrEngine,
                        Types = new[] { SelectedType }
                    }
                }
                : Array.Empty<AssemblyEntry>(),
            ExportScope.Filtered => FilteredTypes
                .GroupBy(t => t.AssemblyName)
                .Select(g => new AssemblyEntry
                {
                    Name = g.Key,
                    IsSystemOrEngine = g.First().IsSystemOrEngine,
                    Types = g.ToList()
                }).ToList(),
            _ => _currentResult.Assemblies
        };
    }

    private void RebuildAssemblyChoices()
    {
        AssemblyChoices.Clear();
        if (_currentResult is null) return;

        var visibleAssemblies = _currentResult.Assemblies
            .Where(a => !HideSystemAssemblies || !a.IsSystemOrEngine)
            .ToList();

        int allCount = visibleAssemblies.Sum(a => a.TotalTypes);
        AssemblyChoices.Add(new AssemblyChoice("All Assemblies", null, allCount, false));

        foreach (var asm in visibleAssemblies)
        {
            AssemblyChoices.Add(new AssemblyChoice(asm.Name, asm, asm.TotalTypes, asm.IsSystemOrEngine));
        }

        // Select first non-system assembly or "All Assemblies"
        SelectedAssemblyChoice = AssemblyChoices.FirstOrDefault();
    }

    private void ScheduleFilterRefresh()
    {
        _filterDebounceCts?.Cancel();
        _filterDebounceCts?.Dispose();
        _filterDebounceCts = new CancellationTokenSource();
        var ct = _filterDebounceCts.Token;

        _ = Task.Delay(140, ct).ContinueWith(t =>
        {
            if (t.IsCanceled) return;
            Application.Current?.Dispatcher.InvokeAsync(ApplyTypeFilter);
        }, TaskScheduler.Default);
    }

    private void ApplyTypeFilter()
    {
        if (_currentResult is null) return;

        IEnumerable<TypeEntry> source;
        if (SelectedAssemblyChoice?.Assembly is { } chosenAsm)
        {
            source = chosenAsm.Types;
        }
        else
        {
            source = _currentResult.Assemblies
                .Where(a => !HideSystemAssemblies || !a.IsSystemOrEngine)
                .SelectMany(a => a.Types);
        }

        string query = SearchQuery.Trim();
        if (ConfirmedOnly)
        {
            source = source.Where(t => t.ConfirmedOffsetCount > 0);
        }

        if (!string.IsNullOrEmpty(query))
        {
            source = source.Where(t => TypeMatchesQuery(t, query));
        }

        source = SortMode switch
        {
            MemberSortMode.Members => source.OrderByDescending(t => t.TotalMembers).ThenBy(t => t.FullName, StringComparer.OrdinalIgnoreCase),
            MemberSortMode.Offset => source.OrderByDescending(t => t.ConfirmedOffsetCount).ThenBy(t => t.FullName, StringComparer.OrdinalIgnoreCase),
            _ => source.OrderBy(t => t.FullName, StringComparer.OrdinalIgnoreCase)
        };

        var prevSelected = SelectedType;
        FilteredTypes.Clear();
        foreach (var t in source)
            FilteredTypes.Add(t);

        if (prevSelected is not null && FilteredTypes.Contains(prevSelected))
            SelectedType = prevSelected;
        else
            SelectedType = FilteredTypes.FirstOrDefault();
    }

    private void RebuildSelectedTypeMembers()
    {
        VisibleFields.Clear();
        VisibleMethods.Clear();
        SelectedField = null;
        SelectedMethod = null;
        ClearInspector();

        if (SelectedType is null) return;

        string query = SearchQuery.Trim();
        bool filterMembersByQuery = !string.IsNullOrEmpty(query) &&
                                    !SelectedType.FullName.Contains(query, StringComparison.OrdinalIgnoreCase);

        IEnumerable<FieldEntry> fields = SelectedType.Fields;
        IEnumerable<MethodEntry> methods = SelectedType.Methods;

        if (ConfirmedOnly)
        {
            fields = fields.Where(f => f.OverallStatus == ResolutionStatus.Confirmed);
            methods = methods.Where(m => m.OverallStatus == ResolutionStatus.Confirmed);
        }

        if (filterMembersByQuery)
        {
            var matchingFields = fields.Where(f => FieldMatchesQuery(f, query)).ToList();
            var matchingMethods = methods.Where(m => MethodMatchesQuery(m, query)).ToList();
            if (matchingFields.Count > 0 || matchingMethods.Count > 0)
            {
                fields = matchingFields;
                methods = matchingMethods;
            }
        }

        fields = SortMode == MemberSortMode.Offset
            ? fields.OrderBy(f => f.SortableOffset ?? ulong.MaxValue).ThenBy(f => f.Name, StringComparer.OrdinalIgnoreCase)
            : fields.OrderBy(f => f.Name, StringComparer.OrdinalIgnoreCase);

        methods = SortMode == MemberSortMode.Offset
            ? methods.OrderBy(m => m.SortableOffset ?? ulong.MaxValue).ThenBy(m => m.Name, StringComparer.OrdinalIgnoreCase)
            : methods.OrderBy(m => m.Name, StringComparer.OrdinalIgnoreCase);

        foreach (var f in fields) VisibleFields.Add(f);
        foreach (var m in methods) VisibleMethods.Add(m);

        // Switch tab automatically if current tab is empty and the other has entries
        if (SelectedMemberTabIndex == 0 && VisibleFields.Count == 0 && VisibleMethods.Count > 0)
            SelectedMemberTabIndex = 1;
        else if (SelectedMemberTabIndex == 1 && VisibleMethods.Count == 0 && VisibleFields.Count > 0)
            SelectedMemberTabIndex = 0;

        if (VisibleFields.Count > 0 && SelectedMemberTabIndex == 0)
            SelectedField = VisibleFields[0];
        else if (VisibleMethods.Count > 0 && SelectedMemberTabIndex == 1)
            SelectedMethod = VisibleMethods[0];
    }

    private void PopulateFieldInspector(FieldEntry field)
    {
        HasInspectorSelection = true;
        InspectorTitle = field.Name;
        InspectorSubtitle = $"Field in {SelectedType?.FullName ?? "Type"}";
        InspectorSignature = $"{field.Modifiers} {field.FieldType} {field.Name}".Trim() +
                             (field.ConstantValue is not null ? $" = {field.ConstantValue}" : string.Empty);
        InspectorStatus = field.OverallStatus;
        InspectorNotes = field.Notes;

        InspectorOffsets.Clear();
        if (field.FieldOffset is not null)
        {
            InspectorOffsets.Add(new DetailOffsetRow(
                "Field Offset",
                field.FieldOffset.DisplayValue,
                field.FieldOffset.DisplayValue,
                field.FieldOffset.Value.HasValue,
                field.FieldOffset.Status,
                field.FieldOffset.SourceFile,
                field.FieldOffset.ExtractionMethod,
                field.FieldOffset.Notes));
        }
        if (field.FieldRva is not null)
        {
            InspectorOffsets.Add(new DetailOffsetRow(
                "Field RVA",
                field.FieldRva.DisplayValue,
                field.FieldRva.DisplayValue,
                field.FieldRva.Value.HasValue,
                field.FieldRva.Status,
                field.FieldRva.SourceFile,
                field.FieldRva.ExtractionMethod,
                field.FieldRva.Notes));
        }
        if (field.MetadataToken.HasValue)
        {
            InspectorOffsets.Add(new DetailOffsetRow(
                "Metadata Token",
                field.TokenHex,
                field.TokenHex,
                true,
                ResolutionStatus.Confirmed,
                field.SourceFile,
                "CLI / IL2CPP Metadata Token",
                null));
        }
    }

    private void PopulateMethodInspector(MethodEntry method)
    {
        HasInspectorSelection = true;
        InspectorTitle = method.Name;
        InspectorSubtitle = $"Method in {SelectedType?.FullName ?? "Type"}";
        InspectorSignature = $"{method.Modifiers} {method.FullSignature}".Trim();
        InspectorStatus = method.OverallStatus;
        InspectorNotes = method.Notes;

        InspectorOffsets.Clear();
        if (method.Rva is not null)
        {
            InspectorOffsets.Add(new DetailOffsetRow(
                "RVA",
                method.Rva.DisplayValue,
                method.Rva.DisplayValue,
                method.Rva.Value.HasValue,
                method.Rva.Status,
                method.Rva.SourceFile,
                method.Rva.ExtractionMethod,
                method.Rva.Notes));
        }
        if (method.VirtualAddress is not null)
        {
            InspectorOffsets.Add(new DetailOffsetRow(
                "Virtual Address",
                method.VirtualAddress.DisplayValue,
                method.VirtualAddress.DisplayValue,
                method.VirtualAddress.Value.HasValue,
                method.VirtualAddress.Status,
                method.VirtualAddress.SourceFile,
                method.VirtualAddress.ExtractionMethod,
                method.VirtualAddress.Notes));
        }
        if (method.FileOffset is not null)
        {
            InspectorOffsets.Add(new DetailOffsetRow(
                "File Offset",
                method.FileOffset.DisplayValue,
                method.FileOffset.DisplayValue,
                method.FileOffset.Value.HasValue,
                method.FileOffset.Status,
                method.FileOffset.SourceFile,
                method.FileOffset.ExtractionMethod,
                method.FileOffset.Notes));
        }
        if (method.MetadataToken.HasValue)
        {
            InspectorOffsets.Add(new DetailOffsetRow(
                "Metadata Token",
                method.TokenHex,
                method.TokenHex,
                true,
                ResolutionStatus.Confirmed,
                method.SourceFile,
                "CLI / IL2CPP Metadata Token",
                null));
        }
    }

    private void ClearInspector()
    {
        HasInspectorSelection = false;
        InspectorTitle = "Select a field or method";
        InspectorSubtitle = "Click any row to inspect offset provenance, verification status, and copy values.";
        InspectorSignature = string.Empty;
        InspectorStatus = ResolutionStatus.Unresolved;
        InspectorNotes = null;
        InspectorOffsets.Clear();
    }

    private void UpdateDiagnosticCounts()
    {
        DiagnosticCount = Diagnostics.Count;
        WarningOrErrorCount = Diagnostics.Count(d => d.Severity is DiagnosticSeverity.Warning or DiagnosticSeverity.Error);
    }

    private void ShowToast(string message)
    {
        ToastMessage = message;
        IsToastVisible = true;
        _toastCts?.Cancel();
        _toastCts?.Dispose();
        _toastCts = new CancellationTokenSource();
        var ct = _toastCts.Token;
        _ = Task.Delay(2600, ct).ContinueWith(t =>
        {
            if (t.IsCanceled) return;
            Application.Current?.Dispatcher.InvokeAsync(() => IsToastVisible = false);
        }, TaskScheduler.Default);
    }

    private static bool TypeMatchesQuery(TypeEntry t, string q)
    {
        if (t.FullName.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            t.Name.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            t.Namespace.Contains(q, StringComparison.OrdinalIgnoreCase))
            return true;

        return t.Fields.Any(f => FieldMatchesQuery(f, q)) ||
               t.Methods.Any(m => MethodMatchesQuery(m, q));
    }

    private static bool FieldMatchesQuery(FieldEntry f, string q) =>
        f.Name.Contains(q, StringComparison.OrdinalIgnoreCase) ||
        f.FieldType.Contains(q, StringComparison.OrdinalIgnoreCase) ||
        (f.FieldOffset?.DisplayValue.Contains(q, StringComparison.OrdinalIgnoreCase) ?? false);

    private static bool MethodMatchesQuery(MethodEntry m, string q) =>
        m.Name.Contains(q, StringComparison.OrdinalIgnoreCase) ||
        m.RvaDisplay.Contains(q, StringComparison.OrdinalIgnoreCase) ||
        m.VirtualAddressDisplay.Contains(q, StringComparison.OrdinalIgnoreCase);

    private static string FormatEngineName(GameEngineType engine) => engine switch
    {
        GameEngineType.UnityIl2Cpp => "Unity (IL2CPP)",
        GameEngineType.UnityMono => "Unity (Mono)",
        GameEngineType.UnrealEngine => "Unreal Engine",
        GameEngineType.Godot => "Godot",
        GameEngineType.DotNetStandalone => ".NET Assembly",
        GameEngineType.NativePe => "Native PE",
        GameEngineType.NativeElf => "Native ELF",
        _ => "Unknown"
    };

    private static string TruncateForToast(string s)
        => s.Length > 48 ? s[..45] + "..." : s;

    private static string SanitizeFileName(string name)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var sb = new StringBuilder(name.Length);
        foreach (char c in name)
            sb.Append(Array.IndexOf(invalid, c) >= 0 ? '_' : c);
        return sb.Length > 0 ? sb.ToString() : "EasyDump";
    }
}
