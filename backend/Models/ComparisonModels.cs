namespace SecureUploader.Models;

/// <summary>
/// One scanner's verdict on the file, inside a single comparison run.
/// </summary>
public sealed class ComparisonEntry
{
    /// <summary>Display name of the scanner that produced this verdict.</summary>
    public string Scanner { get; init; } = "";

    /// <summary>Whether this scanner would have accepted the upload.</summary>
    public bool Accepted { get; init; }

    /// <summary>The scanner's own explanation of its verdict.</summary>
    public string Reason { get; init; } = "";

    /// <summary>Individual checks the scanner reported performing.</summary>
    public List<string> Checks { get; init; } = new();

    /// <summary>Per-layer audit. Populated only by the layered filter; empty for flat comparators.</summary>
    public List<LayerTrace> Traces { get; init; } = new();

    /// <summary>Wall-clock time this scanner took, in milliseconds.</summary>
    public double ElapsedMs { get; init; }

    /// <summary>
    /// Filename this scanner's output was written under, or null if it rejected
    /// the file (nothing is stored for a rejection).
    /// </summary>
    public string? StoredName { get; init; }

    /// <summary>Size in bytes of what was stored. Zero when nothing was stored.</summary>
    public long StoredSize { get; init; }

    /// <summary>
    /// True when the scanner ACCEPTED the file but rewrote its content — the
    /// neutralization case. Distinguishing this from a plain accept is the whole
    /// point of the comparison: a scanner can fail to detect a payload and still
    /// destroy it, and those are different outcomes that a binary accept/reject
    /// table would collapse into one.
    /// </summary>
    public bool ContentRewritten { get; init; }
}

/// <summary>
/// The result of running ONE uploaded file through EVERY configured scanner.
///
/// Same bytes, same filename, same declared content type, every scanner — so any
/// difference in the verdicts is attributable to the scanners themselves and to
/// nothing else. That controlled comparison is what makes the output usable as
/// evidence rather than as a demonstration.
/// </summary>
public sealed class ComparisonResult
{
    /// <summary>Identifier for this run; also the folder its outputs are written to.</summary>
    public string RunId { get; init; } = "";

    /// <summary>The filename as submitted by the client. UNTRUSTED — echoed for the record only.</summary>
    public string OriginalName { get; init; } = "";

    /// <summary>The Content-Type as declared by the client. UNTRUSTED — part of the test input.</summary>
    public string DeclaredContentType { get; init; } = "";

    /// <summary>Upload category the file was submitted under.</summary>
    public string Category { get; init; } = "";

    /// <summary>Size of the submitted file, in bytes.</summary>
    public long OriginalSize { get; init; }

    /// <summary>SHA-256 of the submitted bytes; identifies the exact input across runs.</summary>
    public string Sha256 { get; init; } = "";

    /// <summary>One entry per scanner, in a fixed order (weakest first).</summary>
    public List<ComparisonEntry> Results { get; init; } = new();
}
