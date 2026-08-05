namespace SecureUploader.Models;

/// <summary>
/// Configuration for the PDF FlateDecode scanning layer (Layer 5b), bound from
/// the "PdfDecode" section of appsettings.json.
///
/// These limits close two gaps that were documented as known weaknesses of the
/// original single-pass, unbounded implementation:
///   - decompression-bomb exposure (inflating untrusted streams with no cap),
///   - nested-filter evasion (/Filter [/FlateDecode /FlateDecode]).
/// </summary>
public sealed class PdfDecodeOptions
{
    public const string SectionName = "PdfDecode";

    /// <summary>
    /// Maximum bytes accepted from a SINGLE inflated stream. Reaching it does
    /// not by itself condemn the file: the content is truncated and still
    /// scanned, because a large legitimate stream is plausible.
    /// </summary>
    public int MaxBytesPerStream { get; set; } = 10 * 1024 * 1024;   // 10 MB

    /// <summary>
    /// Maximum total inflated bytes held in memory across ALL streams of one
    /// PDF. Bounds the worst case for a document containing many streams.
    /// </summary>
    public int MaxTotalBytes { get; set; } = 50 * 1024 * 1024;       // 50 MB

    /// <summary>
    /// Maximum tolerated expansion ratio (inflated size / compressed size) for
    /// a single stream. Unlike the byte caps this IS treated as an attack
    /// indicator: ordinary content compresses in the single digits, so a
    /// three-orders-of-magnitude expansion is the signature of a crafted bomb.
    /// </summary>
    public int MaxExpansionRatio { get; set; } = 200;

    /// <summary>
    /// How many times inflation may be re-applied to its own output, to defeat
    /// nested filters such as /Filter [/FlateDecode /FlateDecode]. Bounded so
    /// that recursion itself cannot be turned into the DoS.
    /// </summary>
    public int MaxDecodeDepth { get; set; } = 4;
}