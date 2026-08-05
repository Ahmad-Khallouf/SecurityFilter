using System.Diagnostics;
using System.Security.Cryptography;
using SecureUploader.Models;

namespace SecureUploader.Services;

/// <summary>
/// Runs ONE uploaded file through EVERY configured scanner and collects their
/// verdicts side by side.
///
/// CONTROLLED COMPARISON: every scanner receives the same bytes, the same
/// filename, and the same declared Content-Type. Nothing else varies, so any
/// difference between verdicts is attributable to the scanners alone. This is
/// what makes the output usable as evidence.
///
/// Scanners run SEQUENTIALLY, not in parallel. Timings are part of the result,
/// and running six scanners concurrently — several of which spawn an external
/// YARA process — would have them contend for CPU and make every measurement
/// meaningless. Correctness of the numbers outweighs the latency.
///
/// The orchestrator is deliberately independent of HTTP so the automated test
/// harness can drive the whole corpus through the same code path the UI uses.
/// </summary>
public sealed class ComparisonOrchestrator
{
    private readonly IReadOnlyList<IFileScanner> _scanners;
    private readonly string _storageRoot;
    private readonly ILogger<ComparisonOrchestrator> _logger;

    public ComparisonOrchestrator(
        IEnumerable<IFileScanner> scanners,
        string storageRoot,
        ILogger<ComparisonOrchestrator> logger)
    {
        _scanners = scanners.ToList();
        _storageRoot = storageRoot;
        _logger = logger;
    }

    public async Task<ComparisonResult> RunAsync(IFormFile file, string category, CancellationToken ct = default)
    {
        var runId = Guid.NewGuid().ToString("N");
        var runDir = Path.Combine(_storageRoot, runId);
        Directory.CreateDirectory(runDir);

        // Hash the submitted bytes once. Identifies the exact input across runs,
        // so a corpus result can be tied to the file that produced it.
        string sha256;
        await using (var hashStream = file.OpenReadStream())
        {
            var hash = await SHA256.HashDataAsync(hashStream, ct);
            sha256 = Convert.ToHexString(hash).ToLowerInvariant();
        }

        var entries = new List<ComparisonEntry>();

        foreach (var scanner in _scanners)
        {
            var stopwatch = Stopwatch.StartNew();
            ScanResult result;

            try
            {
                result = await scanner.ScanAsync(file, category, ct);
            }
            catch (Exception ex)
            {
                // A comparator throwing is itself a finding, not a reason to abort
                // the run: record it and continue with the remaining scanners.
                stopwatch.Stop();
                _logger.LogError(ex, "Scanner '{Scanner}' threw during comparison run {RunId}.",
                    scanner.GetType().Name, runId);

                entries.Add(new ComparisonEntry
                {
                    Scanner = scanner.GetType().Name,
                    Accepted = false,
                    Reason = $"Scanner threw an exception: {ex.Message}",
                    ElapsedMs = stopwatch.Elapsed.TotalMilliseconds
                });
                continue;
            }

            stopwatch.Stop();

            string? storedName = null;
            long storedSize = 0;
            bool rewritten = result.SanitizedContent is not null;

            // Store ONLY what an accepting scanner would have kept. A rejection
            // stores nothing, exactly as the real upload path behaves.
            if (result.Accepted)
            {
                storedName = BuildFileName(result.ScannerName, file.FileName);
                var fullPath = Path.Combine(runDir, storedName);

                await using (var output = File.Create(fullPath))
                {
                    if (result.SanitizedContent is not null)
                    {
                        await using var sanitized = result.SanitizedContent;
                        sanitized.Position = 0;
                        await sanitized.CopyToAsync(output, ct);
                    }
                    else
                    {
                        await using var source = file.OpenReadStream();
                        await source.CopyToAsync(output, ct);
                    }
                }

                storedSize = new FileInfo(fullPath).Length;
            }
            else if (result.SanitizedContent is not null)
            {
                // Rejected but a stream was produced anyway — release it.
                await result.SanitizedContent.DisposeAsync();
            }

            entries.Add(new ComparisonEntry
            {
                Scanner = result.ScannerName,
                Accepted = result.Accepted,
                Reason = result.Reason,
                Checks = result.Checks,
                Traces = result.Traces,
                ElapsedMs = stopwatch.Elapsed.TotalMilliseconds,
                StoredName = storedName,
                StoredSize = storedSize,
                ContentRewritten = result.Accepted && rewritten
            });
        }

        _logger.LogInformation(
            "Comparison run {RunId} completed for '{File}': {Accepted}/{Total} scanners accepted.",
            runId, file.FileName, entries.Count(e => e.Accepted), entries.Count);

        return new ComparisonResult
        {
            RunId = runId,
            OriginalName = file.FileName,
            DeclaredContentType = file.ContentType ?? "",
            Category = category,
            OriginalSize = file.Length,
            Sha256 = sha256,
            Results = entries
        };
    }

    /// <summary>
    /// Builds a filesystem-safe output name from the scanner's display name.
    /// The extension is taken from the SUBMITTED name and is not trusted to
    /// describe the content — these outputs are for inspection, never served.
    /// </summary>
    private static string BuildFileName(string scannerName, string originalName)
    {
        var slug = new string(scannerName
            .Select(c => char.IsLetterOrDigit(c) ? char.ToLowerInvariant(c) : '-')
            .ToArray());

        while (slug.Contains("--"))
            slug = slug.Replace("--", "-");
        slug = slug.Trim('-');

        var ext = Path.GetExtension(originalName);
        if (string.IsNullOrEmpty(ext) || ext.Length > 10)
            ext = ".bin";

        return slug + ext;
    }
}
