using System.Globalization;
using System.Text;
using Microsoft.AspNetCore.Http;
using SecureUploader.Models;

namespace SecureUploader.Services;

/// <summary>
/// Drives the whole evaluation corpus through the comparison orchestrator and
/// flattens the results into one CSV row per (file x scanner).
///
/// GROUND TRUTH COMES FROM THE DIRECTORY LAYOUT
///     corpus/malicious/...
///     corpus/clean/...
/// and nothing else. A separate label file would be one typo away from silently
/// inverting a class, and a mislabelled corpus produces numbers that look valid
/// and are not. Putting the label in the path makes it physical: a file cannot be
/// mislabelled without being moved.
///
/// WHY THE CSV CARRIES DERIVED COLUMNS
/// Three counting mistakes will corrupt any figure computed from raw verdicts, so
/// the runner resolves all three itself rather than leaving them to a spreadsheet
/// formula written at midnight:
///
///   1. A SCANNER FAILURE is not a detection. An engine that crashed, or a
///      pipeline misconfiguration, rejects the file for reasons that have nothing
///      to do with its content. Counted as a true positive it inflates detection.
///      -> is_scanner_error
///
///   2. A TEST SIGNATURE is not a detection. The EICAR rule fires on a file we
///      wrote ourselves; counting it measures our own fixture.
///      -> is_test_only
///
///   3. RE-ENCODING IS NOT NEUTRALISATION unless something measurable was
///      removed. Every raster image is rewritten whether or not anything was
///      hidden in it, so a neutralisation rate taken from the verdict alone is
///      100% by construction and means nothing.
///      -> is_neutralized
///
/// A fourth distinction cannot be derived and has to be read from the reason
/// code: a file refused because its TYPE is not accepted in this category was
/// never inspected. All four DVWA levels reject PDFs on that basis alone, so
/// treating those rejections as detections would credit them with finding
/// something they never looked at.
///
/// TIMINGS AND THE CACHE
/// The verdict cache makes a second run over the same corpus almost free, which
/// is a real feature and a ruinous measurement artefact. from_cache is recorded
/// per row so a contaminated run is identifiable instead of merely suspicious;
/// clear the cache before any run whose timings will be reported.
/// </summary>
public sealed class CorpusRunner
{
    private readonly ComparisonOrchestrator _orchestrator;
    private readonly ILogger<CorpusRunner> _logger;

    public CorpusRunner(ComparisonOrchestrator orchestrator, ILogger<CorpusRunner> logger)
    {
        _orchestrator = orchestrator;
        _logger = logger;
    }

    public sealed record CorpusSummary(
        string CsvPath,
        int FilesProcessed,
        int MaliciousFiles,
        int CleanFiles,
        int RowsWritten,
        int FilesFailed,
        double TotalSeconds);

    /// <summary>
    /// Runs every file under <paramref name="corpusRoot"/>/malicious and
    /// /clean, and writes the CSV beside it.
    /// </summary>
    /// <param name="category">
    /// The upload category to submit under. This is NOT cosmetic: category
    /// selects which extensions Layer 1 admits, so the same bytes accepted under
    /// 'id' are refused under 'profile'. One category per run, recorded in every
    /// row, because mixing them would make the results incomparable.
    /// </param>
    public async Task<CorpusSummary> RunAsync(
        string corpusRoot,
        string category,
        CancellationToken ct = default)
    {
        if (!Directory.Exists(corpusRoot))
            throw new DirectoryNotFoundException($"Corpus root not found: {corpusRoot}");

        var started = DateTime.UtcNow;

        var groups = new (string Label, string Path)[]
        {
            ("malicious", Path.Combine(corpusRoot, "malicious")),
            ("clean",     Path.Combine(corpusRoot, "clean")),
        };

        var stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
        var csvPath = Path.Combine(corpusRoot, $"results-{category}-{stamp}.csv");

        int processed = 0, malicious = 0, clean = 0, rows = 0, failed = 0;

        // Written incrementally and flushed per file: a run over the full corpus
        // takes minutes, and a partial CSV from an interrupted run is still usable
        // where an in-memory buffer lost on cancellation is not.
        await using var writer = new StreamWriter(csvPath, append: false, Encoding.UTF8);
        await writer.WriteLineAsync(HeaderRow());

        foreach (var (label, dir) in groups)
        {
            if (!Directory.Exists(dir))
            {
                _logger.LogWarning("Corpus group '{Label}' has no directory at {Dir}; skipped.", label, dir);
                continue;
            }

            var files = Directory
                .EnumerateFiles(dir, "*", SearchOption.AllDirectories)
                .OrderBy(p => p, StringComparer.Ordinal)
                .ToList();

            _logger.LogInformation("Corpus group '{Label}': {Count} file(s).", label, files.Count);

            foreach (var path in files)
            {
                ct.ThrowIfCancellationRequested();

                // Samples are neutralised on disk by appending .sample so that no
                // stray double-click can hand one to a real handler. The suffix is
                // stripped here so the pipeline sees the name an attacker would
                // actually have used — the filename is itself an input to Layers
                // 1, 3 and 4, so testing the padded name would test nothing.
                var submittedName = StripSampleSuffix(Path.GetFileName(path));

                try
                {
                    var bytes = await File.ReadAllBytesAsync(path, ct);
                    var formFile = new DiskFormFile(bytes, submittedName);

                    var result = await _orchestrator.RunAsync(formFile, category, ct);

                    foreach (var line in BuildRows(result, path, corpusRoot, submittedName, label, category))
                    {
                        await writer.WriteLineAsync(line);
                        rows++;
                    }

                    processed++;
                    if (label == "malicious") malicious++; else clean++;

                    if (processed % 10 == 0)
                    {
                        await writer.FlushAsync(ct);
                        _logger.LogInformation("Corpus progress: {Processed} file(s) done.", processed);
                    }
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    // A file that cannot even be read is logged and skipped. It must
                    // not abort the run, and it must not silently become a row —
                    // a missing row is visible in the count, a fabricated one is not.
                    failed++;
                    _logger.LogError(ex, "Corpus file failed before scanning: {Path}", path);
                }
            }
        }

        await writer.FlushAsync(ct);

        var summary = new CorpusSummary(
            csvPath, processed, malicious, clean, rows, failed,
            (DateTime.UtcNow - started).TotalSeconds);

        _logger.LogInformation(
            "Corpus run finished: {Processed} file(s) ({Mal} malicious / {Clean} clean), " +
            "{Rows} row(s), {Failed} unreadable, {Seconds:F1}s -> {Csv}",
            summary.FilesProcessed, summary.MaliciousFiles, summary.CleanFiles,
            summary.RowsWritten, summary.FilesFailed, summary.TotalSeconds, csvPath);

        return summary;
    }

    // ------------------------------------------------------------------
    // CSV shape
    // ------------------------------------------------------------------

    private static string HeaderRow() => string.Join(",", new[]
    {
        "file", "relative_path", "sha256", "size_bytes", "truth", "category",
        "scanner", "accepted", "content_rewritten",
        "is_scanner_error", "is_test_only", "is_neutralized",
        "stopped_at_layer", "reason_code", "top_severity",
        "layers_run", "from_cache", "elapsed_ms", "stored_size", "reason",
    });

    private static IEnumerable<string> BuildRows(
        ComparisonResult result,
        string diskPath,
        string corpusRoot,
        string submittedName,
        string truth,
        string category)
    {
        var relative = Path.GetRelativePath(corpusRoot, diskPath).Replace('\\', '/');

        foreach (var entry in result.Results)
        {
            var traces = entry.Traces ?? new List<LayerTrace>();

            // The layer that ended the run. For a flat comparator there are no
            // traces, so the column is empty rather than guessed at.
            var stopping = traces.LastOrDefault(t => t.Decision == "Rejected");

            var evidence = traces.SelectMany(t => t.Evidence ?? Array.Empty<Scanning.ScanEvidence>()).ToList();

            var severities = evidence
                .Select(e => (e.Severity ?? "").ToLowerInvariant())
                .Where(s => s.Length > 0)
                .ToList();

            // A crashed engine and a misconfigured pipeline both mark themselves
            // 'unknown'; the reason prefix catches the cases that fail before any
            // evidence is produced.
            bool scannerError =
                severities.Contains("unknown") ||
                (entry.Reason ?? "").StartsWith("EL-ERROR", StringComparison.Ordinal) ||
                (entry.Reason ?? "").StartsWith("HCM-PIPELINE", StringComparison.Ordinal) ||
                (entry.Reason ?? "").StartsWith("SVG-PARSE", StringComparison.Ordinal) ||
                (entry.Reason ?? "").Contains("Scanner threw an exception", StringComparison.Ordinal);

            // Findings that come only from a rule marked as a test. Excluded from
            // detection figures: the file was written by us for that rule.
            var findingSeverities = severities
                .Where(s => s is "critical" or "high" or "medium" or "test")
                .ToList();

            bool testOnly = findingSeverities.Count > 0 && findingSeverities.All(s => s == "test");

            // Real neutralisation: a sanitisation layer reports 'high' on its own
            // rewrite entry only when it destroyed something measurable.
            bool neutralized =
                entry.Accepted &&
                entry.ContentRewritten &&
                evidence.Any(e =>
                    e.Kind.EndsWith("-rewrite", StringComparison.Ordinal) &&
                    string.Equals(e.Severity, "high", StringComparison.OrdinalIgnoreCase));

            yield return string.Join(",", new[]
            {
                Csv(submittedName),
                Csv(relative),
                Csv(result.Sha256),
                result.OriginalSize.ToString(CultureInfo.InvariantCulture),
                Csv(truth),
                Csv(category),
                Csv(entry.Scanner),
                entry.Accepted ? "1" : "0",
                entry.ContentRewritten ? "1" : "0",
                scannerError ? "1" : "0",
                testOnly ? "1" : "0",
                neutralized ? "1" : "0",
                Csv(stopping?.Layer ?? ""),
                Csv(ReasonCode(entry.Reason, stopping)),
                Csv(TopSeverity(severities)),
                traces.Count.ToString(CultureInfo.InvariantCulture),
                traces.Any(t => t.FromCache) ? "1" : "0",
                entry.ElapsedMs.ToString("F3", CultureInfo.InvariantCulture),
                entry.StoredSize.ToString(CultureInfo.InvariantCulture),
                Csv(entry.Reason ?? ""),
            });
        }
    }

    /// <summary>
    /// A short, groupable cause. Prefers the explicit prefix a layer emits
    /// (DE-PATTERN, HCM-MISMATCH, EL-SCHEME, SVG-BADROOT); falls back to the kind
    /// of the first piece of evidence, which is what the signature layers carry
    /// instead of a prefix. Grouping on the prose message would break the moment
    /// any wording changed.
    /// </summary>
    private static string ReasonCode(string? reason, LayerTrace? stopping)
    {
        var text = stopping?.Reason ?? reason ?? "";

        int colon = text.IndexOf(':');
        if (colon > 0 && colon <= 16)
        {
            var candidate = text[..colon];
            if (candidate.Length >= 4 &&
                candidate.All(c => char.IsUpper(c) || c == '-' || char.IsDigit(c)))
                return candidate;
        }

        var first = stopping?.Evidence?.FirstOrDefault();
        if (first is not null) return first.Kind;

        return text.Length == 0 ? "" : "UNCODED";
    }

    private static readonly string[] SeverityOrder =
        { "critical", "high", "medium", "low", "test", "info", "unknown" };

    private static string TopSeverity(List<string> severities)
    {
        foreach (var level in SeverityOrder)
            if (severities.Contains(level))
                return level;

        return "";
    }

    /// <summary>RFC 4180 quoting. Reasons contain commas, quotes and newlines.</summary>
    private static string Csv(string value)
    {
        if (value.Length == 0) return "";

        bool needsQuotes = value.Contains(',') || value.Contains('"') ||
                           value.Contains('\n') || value.Contains('\r');

        if (!needsQuotes) return value;

        return "\"" + value.Replace("\"", "\"\"").Replace("\r", " ").Replace("\n", " ") + "\"";
    }

    /// <summary>
    /// Removes the containment suffix used to keep samples inert on disk.
    /// Applied repeatedly: a file may be stored as name.jpg.sample.sample.
    /// </summary>
    private static string StripSampleSuffix(string fileName)
    {
        while (fileName.EndsWith(".sample", StringComparison.OrdinalIgnoreCase))
            fileName = fileName[..^".sample".Length];

        return fileName;
    }
}

/// <summary>
/// Presents a file already in memory as an <see cref="IFormFile"/>, so a corpus
/// file travels the exact code path an HTTP upload does. Reusing that path is the
/// point: a separate offline harness would be measuring a different program.
/// </summary>
internal sealed class DiskFormFile : IFormFile
{
    private readonly byte[] _content;

    public DiskFormFile(byte[] content, string fileName)
    {
        _content = content;
        FileName = fileName;
        Name = "file";
        ContentType = GuessContentType(fileName);

        Headers = new HeaderDictionary
        {
            ["Content-Type"] = ContentType,
            ["Content-Disposition"] = $"form-data; name=\"file\"; filename=\"{fileName}\"",
        };
    }

    /// <summary>
    /// Derived from the EXTENSION, deliberately, because that is what a browser
    /// does: it consults the OS MIME registry keyed on the extension and never
    /// looks at the bytes. Deriving it from the content instead would hand Layer 3
    /// a declaration that agrees with the file by construction, and the layer
    /// would then never disagree with anything.
    /// </summary>
    private static string GuessContentType(string name) =>
        Path.GetExtension(name).ToLowerInvariant() switch
        {
            ".jpg" or ".jpeg" => "image/jpeg",
            ".png" => "image/png",
            ".gif" => "image/gif",
            ".svg" => "image/svg+xml",
            ".webp" => "image/webp",
            ".pdf" => "application/pdf",
            _ => "application/octet-stream",
        };

    public string ContentType { get; }
    public string ContentDisposition => Headers["Content-Disposition"]!;
    public IHeaderDictionary Headers { get; }
    public long Length => _content.Length;
    public string Name { get; }
    public string FileName { get; }

    // A fresh stream per call: the orchestrator hashes the bytes and then hands
    // them to every scanner in turn, so the source has to be re-readable.
    public Stream OpenReadStream() => new MemoryStream(_content, writable: false);

    public void CopyTo(Stream target) => target.Write(_content, 0, _content.Length);

    public Task CopyToAsync(Stream target, CancellationToken ct = default) =>
        target.WriteAsync(_content, 0, _content.Length, ct);
}