using SecureUploader.Models;
using SecureUploader.Scanning;

namespace SecureUploader.Services;

/// <summary>
/// The Phase 3 static-analysis file scanner.
/// Implements the same IFileScanner seam as the weak baseline, but runs the
/// upload through the full nine-layer fail-fast pipeline (SecureUploadScanner).
/// Swapping between baseline and this scanner is a single line in Program.cs.
/// </summary>
public sealed class StaticAnalysisScanner : IFileScanner
{
    public const string Name = "SecureUploader (layered filter)";

    private readonly SecureUploadScanner _pipeline;

    public StaticAnalysisScanner(SecureUploadScanner pipeline)
    {
        _pipeline = pipeline;
    }

    public async Task<Models.ScanResult> ScanAsync(IFormFile file, string category, CancellationToken ct = default)
    {
        // Copy the upload into a seekable in-memory stream: layers read the content
        // repeatedly (and rewind it), which IFormFile's stream does not guarantee.
        var buffer = new MemoryStream();
        await using (var source = file.OpenReadStream())
        {
            await source.CopyToAsync(buffer, ct);
        }
        buffer.Position = 0;

        var context = new FileScanContext(
            fileStream: buffer,
            fileName: file.FileName,
            declaredContentType: file.ContentType,
            category: category);

        var result = _pipeline.ScanFile(context);

        if (result.Decision == ScanDecision.Rejected)
        {
            await buffer.DisposeAsync();

            // The client gets a GENERIC message — the specific layer and reason
            // would be a per-layer oracle for tuning an evasion. The detail is
            // logged server-side and carried in Traces, which the controller
            // releases only when demo mode is explicitly enabled.
            return Models.ScanResult.Reject(
                scanner: Name,
                reason: "File rejected by the security filter.",
                traces: context.Traces);
        }

        // Accepted. context.FileStream now holds the FINAL content — the original
        // bytes if no layer modified it, or the sanitized version if re-encoding
        // or SVG sanitization rewrote it. Hand it to the controller for storage.
        context.FileStream.Position = 0;

        return Models.ScanResult.AcceptSanitized(
            scanner: Name,
            reason: "File passed all static-analysis layers.",
            sanitizedContent: context.FileStream,
            traces: context.Traces);
    }
}