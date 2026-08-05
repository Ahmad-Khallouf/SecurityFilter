using SecureUploader.Models;

namespace SecureUploader.Services;

/// <summary>
/// The inspection seam for uploaded files — the heart of the project lives here.
///
/// Today the only implementation is <see cref="BasicValidationScanner"/> (the
/// deliberately weak Phase 1 baseline). In Phase 3 you add a static-analysis
/// implementation (magic-byte verification, content/signature scanning, SVG
/// sanitization, heuristics) behind this same interface and swap it in
/// Program.cs. The controller never changes — it just asks the scanner whether a
/// file may be accepted.
/// </summary>
public interface IFileScanner
{
    Task<ScanResult> ScanAsync(IFormFile file, string category, CancellationToken ct = default);
}
