using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using SecureUploader.Models;
using SecureUploader.Services;

namespace SecureUploader.Controllers;

[ApiController]
[Route("api")]
public class UploadController : ControllerBase
{
    // The two upload entry points required by Phase 1 of the project plan.
    private static readonly string[] ValidCategories = { "profile", "id" };

    private readonly IFileScanner _scanner;
    private readonly UploadOptions _options;
    private readonly DemoOptions _demo;
    private readonly IWebHostEnvironment _env;
    private readonly ILogger<UploadController> _logger;

    public UploadController(
        IFileScanner scanner,
        IOptions<UploadOptions> options,
        IOptions<DemoOptions> demo,
        IWebHostEnvironment env,
        ILogger<UploadController> logger)
    {
        _scanner = scanner;
        _options = options.Value;
        _demo = demo.Value;
        _env = env;
        _logger = logger;
    }

    private string StorageRoot => Path.IsPathRooted(_options.StorageRoot)
        ? _options.StorageRoot
        : Path.Combine(_env.ContentRootPath, _options.StorageRoot);

    /// <summary>Accepts a single file for the given category and runs it through the scanner.</summary>
    [HttpPost("upload")]
    public async Task<IActionResult> Upload(
        [FromForm] IFormFile? file,
        [FromForm] string? category,
        CancellationToken ct)
    {
        category = (category ?? "").Trim().ToLowerInvariant();
        if (!ValidCategories.Contains(category))
            return BadRequest(UploadResponse.Error(
                $"Unknown category '{category}'. Expected one of: {string.Join(", ", ValidCategories)}."));

        if (file is null || file.Length == 0)
            return BadRequest(UploadResponse.Error("No file was provided."));

        // --- inspection seam: the Phase 3 filter swaps in behind IFileScanner ---
        var scan = await _scanner.ScanAsync(file, category, ct);
        if (!scan.Accepted)
            return UnprocessableEntity(UploadResponse.Rejected(file, category, scan, _demo.Enabled));

        // Store the accepted file under a random name. The random name prevents
        // path-traversal / overwrite of host files.
        var ext = Path.GetExtension(file.FileName);
        var storedName = $"{Guid.NewGuid():N}{ext}";
        var dir = Path.Combine(StorageRoot, category);
        Directory.CreateDirectory(dir);
        var fullPath = Path.Combine(dir, storedName);

        await using (var stream = System.IO.File.Create(fullPath))
        {
            if (scan.SanitizedContent is not null)
            {
                // A sanitization layer (EXIF stripping / SVG sanitization) rewrote the
                // file. Store the CLEANED content — storing the original would discard
                // the sanitization work and leave the payload on disk.
                await using var sanitized = scan.SanitizedContent;
                sanitized.Position = 0;
                await sanitized.CopyToAsync(stream, ct);
            }
            else
            {
                // No layer modified the file (e.g. the weak baseline scanner) — store
                // the ORIGINAL content unchanged, so the baseline stays a faithful
                // target for the Phase 4 attacks.
                await file.CopyToAsync(stream, ct);
            }
        }

        var storedSize = new FileInfo(fullPath).Length;

        _logger.LogInformation("Stored '{Stored}' ({Size:N0} bytes, from '{Original}', category '{Category}').",
            storedName, storedSize, file.FileName, category);

        return Ok(UploadResponse.Stored(file, category, scan, storedName, storedSize, _demo.Enabled));
    }

    /// <summary>Lists everything stored so far (used by the front-end gallery / later phases).</summary>
    [HttpGet("files")]
    public IActionResult List()
    {
        var items = new List<object>();
        foreach (var category in ValidCategories)
        {
            var dir = Path.Combine(StorageRoot, category);
            if (!Directory.Exists(dir)) continue;

            foreach (var path in Directory.EnumerateFiles(dir))
            {
                var name = Path.GetFileName(path);
                items.Add(new
                {
                    category,
                    storedName = name,
                    size = new FileInfo(path).Length,
                    url = $"/api/files/{category}/{name}"
                });
            }
        }
        return Ok(items);
    }

    /// <summary>Serves a stored file back to the browser.</summary>
    [HttpGet("files/{category}/{name}")]
    public IActionResult Get(string category, string name)
    {
        category = (category ?? "").ToLowerInvariant();
        if (!ValidCategories.Contains(category))
            return NotFound();

        // Guard the RETRIEVAL path against traversal — unrelated to the content
        // weakness under study, this just stops '../' from escaping the folder.
        if (string.IsNullOrWhiteSpace(name) || name.Contains("..") ||
            name.Contains('/') || name.Contains('\\'))
            return BadRequest();

        var path = Path.Combine(StorageRoot, category, name);
        if (!System.IO.File.Exists(path))
            return NotFound();

        // NOTE: files are still served INLINE with a content type guessed from the
        // extension. With the baseline scanner this is the intentional weakness that
        // makes the Phase 4 stored-XSS demonstration possible. With the static-analysis
        // scanner the stored content is already sanitized; hardening the RESPONSE side
        // ('Content-Disposition: attachment' + a strict CSP) is a separate step.
        var contentType = GuessContentType(name);
        var bytes = System.IO.File.ReadAllBytes(path);
        return File(bytes, contentType); // inline
    }

    private static string GuessContentType(string name) =>
        Path.GetExtension(name).ToLowerInvariant() switch
        {
            ".jpg" or ".jpeg" => "image/jpeg",
            ".png" => "image/png",
            ".gif" => "image/gif",
            ".svg" => "image/svg+xml",
            ".webp" => "image/webp",
            ".pdf" => "application/pdf",
            _ => "application/octet-stream"
        };
}