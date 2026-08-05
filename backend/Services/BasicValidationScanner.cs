using Microsoft.Extensions.Options;
using SecureUploader.Models;

namespace SecureUploader.Services;

/// <summary>
/// PHASE 1 BASELINE — intentionally weak validation.
///
/// This scanner checks only three things: file size, the file's last extension,
/// and the client-declared Content-Type. It does NOT read the file's bytes, does
/// NOT verify magic bytes, and does NOT sanitize SVG/XML. It is therefore
/// bypassable by the Phase 4 attack suite (content-type spoofing, double
/// extensions, polyglot files, script-bearing SVGs). That is by design: this is
/// the "before" state that the Phase 3 static-analysis filter is measured
/// against. Do not harden this class — build the real filter as a separate
/// IFileScanner instead.
/// </summary>
public class BasicValidationScanner : IFileScanner
{
    public const string Name = "BasicValidationScanner (baseline)";

    private readonly UploadOptions _options;
    private readonly ILogger<BasicValidationScanner> _logger;

    public BasicValidationScanner(IOptions<UploadOptions> options, ILogger<BasicValidationScanner> logger)
    {
        _options = options.Value;
        _logger = logger;
    }

    public Task<ScanResult> ScanAsync(IFormFile file, string category, CancellationToken ct = default)
    {
        var checks = new List<string>();

        // 1) Size --------------------------------------------------------------
        if (file.Length == 0)
            return Reject("File is empty.", checks);

        var maxMb = _options.MaxFileSizeBytes / (1024 * 1024);
        if (file.Length > _options.MaxFileSizeBytes)
            return Reject($"File is larger than the {maxMb} MB limit.", checks);
        checks.Add($"Size OK: {file.Length:N0} bytes (limit {_options.MaxFileSizeBytes:N0}).");

        // 2) Extension allow-list (WEAK: only the final extension is examined,
        //    so 'shell.php.jpg' passes as a '.jpg'). --------------------------
        var ext = Path.GetExtension(file.FileName).ToLowerInvariant();
        if (string.IsNullOrEmpty(ext))
            return Reject("File has no extension.", checks);
        if (!_options.AllowedExtensions.Contains(ext, StringComparer.OrdinalIgnoreCase))
            return Reject($"Extension '{ext}' is not on the allow-list.", checks);
        checks.Add($"Extension OK: '{ext}' is allowed.");

        // 3) Declared Content-Type (WEAK: this value is sent by the client and
        //    is trivially spoofed in a proxy such as Burp). ------------------
        var declared = file.ContentType ?? "";
        if (!_options.AllowedContentTypes.Contains(declared, StringComparer.OrdinalIgnoreCase))
            return Reject($"Declared content type '{declared}' is not allowed.", checks);
        checks.Add($"Declared Content-Type OK: '{declared}'.");

        // >>> PHASE 3 STATIC-ANALYSIS FILTER HOOKS IN HERE <<<
        // No magic-byte verification, no content/signature scan, no SVG
        // sanitization yet. Those layers belong in your Phase 3 IFileScanner.

        _logger.LogInformation("Baseline accepted '{File}' ({Category}).", file.FileName, category);
        return Task.FromResult(ScanResult.Accept(Name, "Passed baseline validation.", checks));

        Task<ScanResult> Reject(string reason, List<string> done)
        {
            _logger.LogWarning("Baseline rejected '{File}' ({Category}): {Reason}", file.FileName, category, reason);
            return Task.FromResult(ScanResult.Reject(Name, reason, done));
        }
    }
}
