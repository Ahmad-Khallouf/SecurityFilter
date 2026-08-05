namespace SecureUploader.Models;

/// <summary>
/// Outcome of running a file through an <see cref="Services.IFileScanner"/>.
/// Carries the accept/reject decision, a human-readable reason, the name of the
/// scanner that produced it, and the list of individual checks performed (handy
/// for showing your work in the UI and in Phase 4/5 reports).
/// </summary>
public class ScanResult
{
    public bool Accepted { get; init; }
    public string Reason { get; init; } = "";
    public string ScannerName { get; init; } = "";
    public List<string> Checks { get; init; } = new();

    /// <summary>
    /// The sanitized file content, set when a sanitization step modified the file
    /// (image re-encoding, SVG sanitization). Null when the file was not modified —
    /// in that case the controller stores the original upload as-is.
    /// </summary>
    public Stream? SanitizedContent { get; init; }

    /// <summary>
    /// Per-layer audit of the scan, when the scanner is layered. Empty for the
    /// flat comparators (baseline, DVWA levels), which have no internal layers.
    ///
    /// ALWAYS populated by the layered scanner. Whether it reaches the client is
    /// decided in exactly one place — the controller, from DemoOptions — so the
    /// disclosure rule lives at the boundary rather than being re-implemented
    /// (and eventually forgotten) inside each scanner.
    /// </summary>
    public List<LayerTrace> Traces { get; init; } = new();

    public static ScanResult Accept(
        string scanner,
        string reason,
        IEnumerable<string>? checks = null,
        IEnumerable<LayerTrace>? traces = null) =>
        new()
        {
            Accepted = true,
            Reason = reason,
            ScannerName = scanner,
            Checks = checks?.ToList() ?? new(),
            Traces = traces?.ToList() ?? new()
        };

    /// <summary>
    /// Accept the file and hand back the SANITIZED content to be stored instead
    /// of the original (used by the layered scanner and by DVWA Impossible).
    /// </summary>
    public static ScanResult AcceptSanitized(
        string scanner,
        string reason,
        Stream sanitizedContent,
        IEnumerable<string>? checks = null,
        IEnumerable<LayerTrace>? traces = null) =>
        new()
        {
            Accepted = true,
            Reason = reason,
            ScannerName = scanner,
            Checks = checks?.ToList() ?? new(),
            SanitizedContent = sanitizedContent,
            Traces = traces?.ToList() ?? new()
        };

    public static ScanResult Reject(
        string scanner,
        string reason,
        IEnumerable<string>? checks = null,
        IEnumerable<LayerTrace>? traces = null) =>
        new()
        {
            Accepted = false,
            Reason = reason,
            ScannerName = scanner,
            Checks = checks?.ToList() ?? new(),
            Traces = traces?.ToList() ?? new()
        };
}