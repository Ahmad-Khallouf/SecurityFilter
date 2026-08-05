namespace SecureUploader.Models;

/// <summary>
/// Strongly-typed configuration for the image re-encoding sanitization layer
/// (Layer 6), bound from the "ReEncoding" section of appsettings.json.
///
/// The dimension caps below are the FIRST line of defense against
/// decompression bombs: they are checked against the image HEADER only,
/// before any pixel data is decoded. The Magick.NET resource limits
/// (applied at startup in Program.cs) are the second, library-level line.
/// </summary>
public sealed class ReEncodingOptions
{
    public const string SectionName = "ReEncoding";

    /// <summary>Maximum accepted image width in pixels (header check, pre-decode).</summary>
    public int MaxWidth { get; set; } = 10_000;

    /// <summary>Maximum accepted image height in pixels (header check, pre-decode).</summary>
    public int MaxHeight { get; set; } = 10_000;

    /// <summary>
    /// Maximum accepted total pixel count (width × height). Pixel count — not
    /// file size — is what drives decode memory, so this is the real bomb cap:
    /// a few-KB PNG can declare a multi-gigapixel canvas.
    /// </summary>
    public long MaxTotalPixels { get; set; } = 40_000_000; // 40 megapixels

    /// <summary>
    /// JPEG re-encode quality (1–100). 90 is visually near-lossless while still
    /// forcing full re-quantization of the pixel data.
    /// </summary>
    public int JpegQuality { get; set; } = 90;

    /// <summary>
    /// Whether to strip all metadata profiles (EXIF/XMP/IPTC/ICC/comments)
    /// during re-encoding. Kept as a switch so the ablation study can measure
    /// re-encoding with and without metadata stripping.
    /// </summary>
    public bool StripMetadata { get; set; } = true;

    /// <summary>
    /// Memory ceiling (in megabytes) for the ImageMagick decoder, enforced
    /// library-wide via ResourceLimits at startup. Backstop in case a crafted
    /// file gets past the header checks.
    /// </summary>
    /// <summary>
    /// Whether to clear the least-significant bit of every colour channel during
    /// re-encoding. This destroys pixel-domain LSB steganography, which lossless
    /// PNG->PNG re-encoding otherwise preserves. Kept as a switch so the ablation
    /// study can measure re-encoding with and without LSB neutralisation.
    ///
    /// Trade-off: alters every image by at most one intensity level per channel
    /// (visually imperceptible) but is applied to clean and malicious files alike.
    /// </summary>
    public bool ClearLeastSignificantBit { get; set; } = false;
    public long MagickMemoryLimitMb { get; set; } = 256;
}