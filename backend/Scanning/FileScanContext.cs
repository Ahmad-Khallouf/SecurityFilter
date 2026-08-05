using SecureUploader.Models;

namespace SecureUploader.Scanning;

/// <summary>
/// Carries all information about the uploaded file through the scan pipeline.
/// Passed to every scan layer in order.
/// Reference: OWASP File Upload Cheat Sheet — client-supplied metadata
/// (filename, Content-Type) is untrusted input and must never be relied upon alone.
/// </summary>
public sealed class FileScanContext
{
    /// <summary>The file content. Layers read from this stream.</summary>
    public Stream FileStream { get; set; }

    /// <summary>Original filename as sent by the client. UNTRUSTED.</summary>
    public string FileName { get; }

    /// <summary>Content-Type declared by the client (browser/attacker). UNTRUSTED.</summary>
    public string DeclaredContentType { get; }

    /// <summary>Upload category: "profile" (images) or "id" (PDF/images).</summary>
    public string Category { get; }

    /// <summary>
    /// The REAL file type as detected by the Magic Bytes layer.
    /// Written by MagicBytesLayer, read by HeaderContentMatchingLayer.
    /// Null until Magic Bytes runs.
    /// </summary>
    public string? DetectedFileType { get; set; }

    /// <summary>
    /// SHA-256 of the uploaded content (lowercase hex). Computed lazily by the
    /// FIRST CachedScanLayer that needs it, then reused by every subsequent
    /// cached layer in the same scan — so the content is hashed at most once
    /// per upload. Valid because all cached (detection) layers run BEFORE any
    /// sanitization layer replaces the stream.
    /// </summary>
    public string? ContentHash { get; set; }

    /// <summary>
    /// Per-layer audit of this scan, appended by SecureUploadScanner as the file
    /// travels down the pipeline — one entry for EVERY layer that ran, not only
    /// the one that stopped it.
    ///
    /// Travelling on the context rather than in a return value keeps the
    /// IScanLayer contract unchanged: no layer knows the trace exists, so none
    /// can forget to populate it or lie about it.
    ///
    /// Always collected. Whether any of it reaches the client is decided later,
    /// in one place, by DemoOptions.
    /// </summary>
    public List<LayerTrace> Traces { get; } = new();

    public FileScanContext(Stream fileStream, string fileName, string declaredContentType, string category)
    {
        FileStream = fileStream;
        FileName = fileName;
        DeclaredContentType = declaredContentType;
        Category = category;
    }
}