using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using SecureUploader.Models;
using SecureUploader.Services;

namespace SecureUploader.Controllers;

/// <summary>
/// Batch evaluation: drives the whole corpus through every scanner and writes a
/// CSV of the results.
///
/// GATED ON DEMO MODE, returning 404 rather than 403 — same reasoning as the
/// comparison endpoint. This is an evaluation surface and production genuinely
/// does not include it.
///
/// THE CORPUS PATH IS NOT A REQUEST PARAMETER
/// It comes from configuration (Demo:CorpusRoot) and nowhere else. An endpoint
/// that accepted a directory from the caller and enumerated everything inside it
/// would be an arbitrary-read primitive — path traversal with the traversal step
/// removed, since no relative path is even needed. Reading it from server
/// configuration leaves nothing for a request to influence, so the whole class of
/// problem does not arise rather than being filtered for.
///
/// The setting is absent by default. With no corpus configured the endpoints
/// report that and do nothing, so a deployment cannot inherit the capability by
/// accident.
/// </summary>
[ApiController]
[Route("api/corpus")]
public class CorpusController : ControllerBase
{
    private static readonly string[] ValidCategories = { "profile", "id" };

    private readonly CorpusRunner _runner;
    private readonly DemoOptions _demo;
    private readonly IConfiguration _config;
    private readonly ILogger<CorpusController> _logger;

    public CorpusController(
        CorpusRunner runner,
        IOptions<DemoOptions> demo,
        IConfiguration config,
        ILogger<CorpusController> logger)
    {
        _runner = runner;
        _demo = demo.Value;
        // Read straight from configuration rather than through DemoOptions so that
        // this endpoint needs no change to the existing options class. Folding it
        // into DemoOptions later is tidier and changes nothing functionally.
        _config = config;
        _logger = logger;
    }

    private string CorpusRoot => (_config["Demo:CorpusRoot"] ?? "").Trim();

    /// <summary>
    /// Reports whether a corpus is configured and what is in it, WITHOUT running
    /// anything.
    ///
    /// Deliberately separate from the run. A full pass takes minutes, and
    /// discovering afterwards that one group directory was misspelled — so half
    /// the corpus was silently skipped — wastes the whole pass. The counts here
    /// are meant to be checked against the expected corpus size before starting.
    /// </summary>
    [HttpGet("status")]
    public IActionResult Status()
    {
        if (!_demo.Enabled) return NotFound();

        var root = CorpusRoot;

        if (root.Length == 0)
        {
            return Ok(new
            {
                configured = false,
                message = "Demo:CorpusRoot is not set in configuration. Add it to appsettings.json.",
            });
        }

        if (!Directory.Exists(root))
        {
            return Ok(new
            {
                configured = true,
                exists = false,
                root,
                message = "Demo:CorpusRoot is set but the directory does not exist.",
            });
        }

        var groups = new[] { "malicious", "clean" }
            .Select(label =>
            {
                var dir = Path.Combine(root, label);
                var exists = Directory.Exists(dir);

                return new
                {
                    group = label,
                    exists,
                    files = exists
                        ? Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories).Count()
                        : 0,
                };
            })
            .ToList();

        return Ok(new
        {
            configured = true,
            exists = true,
            root,
            groups,
            totalFiles = groups.Sum(g => g.files),
            note = "Clear the verdict cache before a run whose timings will be reported.",
        });
    }

    /// <summary>
    /// Runs the corpus for one category and writes the CSV beside it.
    ///
    /// One category per run, and it must be stated: the category selects which
    /// extensions Layer 1 admits, so the same bytes are accepted under 'id' and
    /// refused under 'profile'. Results from two categories are not comparable and
    /// are kept in separate files.
    ///
    /// The request is long-running by nature — minutes for a full corpus, since
    /// scanners run sequentially so their timings stay meaningful. The CSV is
    /// flushed as it goes, so an interrupted run still leaves usable rows.
    /// </summary>
    [HttpPost("run")]
    public async Task<IActionResult> Run([FromQuery] string? category, CancellationToken ct)
    {
        if (!_demo.Enabled) return NotFound();

        var root = CorpusRoot;
        if (root.Length == 0)
            return BadRequest(UploadResponse.Error("Demo:CorpusRoot is not configured."));

        if (!Directory.Exists(root))
            return BadRequest(UploadResponse.Error($"Configured corpus root does not exist: {root}"));

        category = (category ?? "").Trim().ToLowerInvariant();
        if (!ValidCategories.Contains(category))
            return BadRequest(UploadResponse.Error(
                $"Unknown category '{category}'. Expected one of: {string.Join(", ", ValidCategories)}."));

        _logger.LogWarning(
            "CORPUS RUN starting for category '{Category}' from {Root}. " +
            "Weak comparators will write every file they accept to the comparison output folder, " +
            "including malicious ones, unmodified.",
            category, root);

        try
        {
            var summary = await _runner.RunAsync(root, category, ct);

            return Ok(new
            {
                summary.CsvPath,
                summary.FilesProcessed,
                summary.MaliciousFiles,
                summary.CleanFiles,
                summary.RowsWritten,
                summary.FilesFailed,
                seconds = Math.Round(summary.TotalSeconds, 1),
            });
        }
        catch (OperationCanceledException)
        {
            // Cancellation is not a failure: the partial CSV on disk is still valid
            // for the rows it contains.
            _logger.LogWarning("Corpus run cancelled; the partial CSV remains on disk.");
            return StatusCode(499, UploadResponse.Error("Run cancelled. The partial CSV is on disk."));
        }
    }
}