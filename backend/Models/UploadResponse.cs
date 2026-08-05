namespace SecureUploader.Models;

/// <summary>
/// JSON shape returned to the front-end for every upload attempt (accepted or
/// rejected). Mirrors the fields the React result panel renders.
///
/// DISCLOSURE RULE: the layer trace is attached ONLY when demo mode is enabled,
/// and the caller passes it explicitly. Nothing here reads configuration, so the
/// decision stays at the controller boundary — one place to audit, rather than a
/// rule re-implemented in every factory method.
/// </summary>
public class UploadResponse
{
    public bool Accepted { get; init; }
    public string Message { get; init; } = "";
    public string? Category { get; init; }
    public string? OriginalName { get; init; }
    public string? StoredName { get; init; }
    public long? Size { get; init; }
    public string? DeclaredContentType { get; init; }
    public string? Url { get; init; }
    public string? Scanner { get; init; }
    public List<string> Checks { get; init; } = new();

    /// <summary>
    /// Per-layer audit with timings. Empty in production: a client that learns
    /// exactly which layer stopped its file, and why, has a per-layer oracle for
    /// tuning an evasion one attempt at a time.
    /// </summary>
    public List<LayerTrace> Traces { get; init; } = new();

    /// <summary>True when the stored bytes differ from the submitted bytes (sanitization occurred).</summary>
    public bool ContentRewritten { get; init; }

    public static UploadResponse Error(string message) =>
        new() { Accepted = false, Message = message };

    public static UploadResponse Rejected(IFormFile file, string category, ScanResult scan, bool includeTraces = false) =>
        new()
        {
            Accepted = false,
            Message = scan.Reason,
            Category = category,
            OriginalName = file.FileName,
            Size = file.Length,
            DeclaredContentType = file.ContentType,
            Scanner = scan.ScannerName,
            Checks = scan.Checks,
            Traces = includeTraces ? scan.Traces : new()
        };

    public static UploadResponse Stored(
        IFormFile file,
        string category,
        ScanResult scan,
        string storedName,
        long storedSize,
        bool includeTraces = false) =>
        new()
        {
            Accepted = true,
            Message = scan.Reason,
            Category = category,
            OriginalName = file.FileName,
            StoredName = storedName,
            Size = file.Length,
            DeclaredContentType = file.ContentType,
            Url = $"/api/files/{category}/{storedName}",
            Scanner = scan.ScannerName,
            Checks = scan.Checks,
            Traces = includeTraces ? scan.Traces : new(),
            // Compared against the SUBMITTED size: if the stored file is a
            // different size, a sanitization layer rewrote it. This is what makes
            // neutralization visible in the UI without trusting a self-report.
            ContentRewritten = storedSize != file.Length
        };
}
