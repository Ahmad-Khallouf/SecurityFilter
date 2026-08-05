using System.Security.Cryptography;
using System.Text;
using ImageMagick;
using SecureUploader.Models;

namespace SecureUploader.Scanning;

/// <summary>
/// Layer 6: Image Re-encoding Sanitization (SANITIZATION layer).
/// Replaces the former MetadataInspectionLayer and strictly extends it.
///
/// The image is fully DECODED to pixels and RE-ENCODED into a fresh file of the
/// same format. Only pixel data survives this round-trip, which structurally
/// destroys entire hiding classes instead of trying to detect them:
///   - bytes appended after the end-of-image marker (classic webshell-in-image),
///   - polyglot files (image + something else in one byte stream),
///   - executables buried inside the image container,
///   - metadata-carried payloads (EXIF/XMP/IPTC/ICC/comments) via Strip().
///
/// SECURITY ORDER: this layer must run AFTER the detection layers (5 / 5b / 5c),
/// otherwise it would destroy the very evidence those layers measure.
///
/// ATTACK-SURFACE CONTROLS (decoding untrusted input is itself risky):
///   1. Header-only dimension pre-check (MagickImageInfo) BEFORE pixel decode —
///      rejects decompression bombs without paying the decode cost.
///   2. Library-wide ResourceLimits (set at startup in Program.cs) as backstop.
///   3. The decode format is PINNED from DetectedFileType (MagicBytesLayer);
///      the parser is never allowed to guess.
///   4. Fail-closed: any decode/re-encode failure rejects the file.
///
/// WHY THIS LAYER MEASURES WHAT IT DESTROYED
/// -----------------------------------------
/// A detection layer explains a rejection. This one accepts the file and rewrites
/// it, so the question it has to answer is different: what was removed, and how
/// would anyone know?
///
/// It matters for the numbers, not only for the narrative. EVERY raster image
/// returns Sanitized, because re-encoding is prophylactic and runs whether or not
/// anything suspicious was present. A neutralisation rate computed from that
/// verdict alone is therefore 100% by construction — it would count an ordinary
/// photograph as neutralised — and says nothing. Neutralisation is only meaningful
/// where something MEASURABLE was destroyed, so the quantity is measured here and
/// recorded, and the metric is derived from the measurement rather than from the
/// verdict.
///
/// The measurable quantity is trailing data. Every accepted raster format has a
/// defined end: FF D9 for JPEG, the IEND chunk for PNG, the RIFF size field for
/// WebP. Bytes beyond that point are not image content — they are the appended
/// payload that this layer exists to remove. Their count and offset are reported,
/// which turns "the file was sanitised" into a figure a reviewer can confirm with
/// a hex editor.
///
/// Independent support for the approach: Koch et al. (WWW 2025) measured YARA
/// signature matching on image polyglots at roughly 82% recall, while image
/// re-encoding removed 100% of them — the same reason this layer sits behind the
/// signature layers rather than instead of them.
///
/// LSB NEUTRALISATION (optional, ablation switch)
/// ----------------------------------------------
/// Lossless PNG->PNG re-encoding preserves pixel values exactly, so payloads
/// hidden in the least-significant bit (pixel-domain LSB steganography) SURVIVE
/// re-encoding. When ClearLeastSignificantBit is enabled, the LSB of every colour
/// channel is zeroed (Posterize 128) after decode, which destroys LSB capacity.
/// It is applied uniformly to clean and malicious files and alters each pixel by
/// at most one intensity level (visually imperceptible). Kept behind a switch so
/// the ablation study can measure re-encoding with and without it; LSB stego is an
/// exfiltration threat, at the edge of the upload-safety gate's remit, so the
/// default is off.
/// </summary>
public sealed class ImageReEncodingLayer : IScanLayer
{
    public string Name => "ImageReEncoding";

    private readonly ReEncodingOptions _options;

    public ImageReEncodingLayer(ReEncodingOptions options)
    {
        _options = options;
    }

    // Raster formats this layer re-encodes. SVG (vector/XML) is handled by
    // Layer 7; PDF is out of scope by design. Kept in CODE, not config:
    // a config typo must never be able to silently disable sanitization.
    private static readonly Dictionary<string, MagickFormat> RasterFormats =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["jpeg"] = MagickFormat.Jpeg,
            ["png"] = MagickFormat.Png,
            ["webp"] = MagickFormat.WebP
        };

    /// <summary>
    /// Metadata containers checked by name before stripping. Naming the profiles
    /// that were present is a stronger statement than reporting that stripping ran:
    /// EXIF and XMP are the containers a payload is actually carried in, and a file
    /// that had neither loses nothing to the strip.
    /// </summary>
    private static readonly string[] ProfileNames =
        { "exif", "xmp", "iptc", "icc", "icm", "8bim", "app1", "app12", "iptctc" };

    public ScanResult Scan(FileScanContext context)
    {
        var type = context.DetectedFileType;
        if (type is null || !RasterFormats.TryGetValue(type, out var format))
        {
            return ScanResult.Accept(Name, new[]
            {
                new ScanEvidence(
                    Kind: "reencode-scope",
                    Label: "not-raster",
                    Detail: $"Detected type '{type ?? "(none)"}' is not a raster image handled by this layer. " +
                            "SVG is sanitised by Layer 7; PDF is out of scope by design.",
                    Severity: "info")
            });
        }

        var evidence = new List<ScanEvidence>();

        try
        {
            // The original bytes are needed twice: to decode, and to locate the
            // format's end marker so that trailing data can be quantified.
            context.FileStream.Position = 0;
            byte[] original;
            using (var buffer = new MemoryStream())
            {
                context.FileStream.CopyTo(buffer);
                original = buffer.ToArray();
            }

            // ---- 1) Header-only pre-check: dimensions BEFORE any pixel decode ----
            context.FileStream.Position = 0;
            var info = new MagickImageInfo(context.FileStream);

            if (info.Width > (uint)_options.MaxWidth || info.Height > (uint)_options.MaxHeight)
            {
                return ScanResult.Reject(Name,
                    $"Image dimensions {info.Width}x{info.Height} exceed the configured maximum " +
                    $"{_options.MaxWidth}x{_options.MaxHeight} (decompression-bomb guard).",
                    new[]
                    {
                        new ScanEvidence(
                            Kind: "reencode-bomb",
                            Label: "dimensions",
                            Detail: $"Header declares {info.Width}x{info.Height}; limit is " +
                                    $"{_options.MaxWidth}x{_options.MaxHeight}. Rejected from the header " +
                                    "alone, before any pixel was decoded, so the bomb never got to consume " +
                                    "memory.",
                            Severity: "high",
                            Reference: "CWE-409 (improper handling of highly compressed data)")
                    });
            }

            long totalPixels = (long)info.Width * info.Height;
            if (totalPixels > _options.MaxTotalPixels)
            {
                return ScanResult.Reject(Name,
                    $"Image pixel count {totalPixels} exceeds the configured maximum " +
                    $"{_options.MaxTotalPixels} (decompression-bomb guard).",
                    new[]
                    {
                        new ScanEvidence(
                            Kind: "reencode-bomb",
                            Label: "pixel-count",
                            Detail: $"{info.Width}x{info.Height} = {totalPixels} pixels; limit is " +
                                    $"{_options.MaxTotalPixels}. Dimensions individually within range, so " +
                                    "the area check is what caught this shape.",
                            Severity: "high",
                            Reference: "CWE-409 (improper handling of highly compressed data)")
                    });
            }

            // Trailing-data survey, taken from the ORIGINAL bytes: this is the
            // quantity that makes neutralisation measurable rather than assumed.
            var trailing = MeasureTrailingData(original, type);
            evidence.Add(DescribeTrailing(trailing, original.Length));

            // ---- 2) Full decode with the format PINNED to the detected type ----
            context.FileStream.Position = 0;
            var readSettings = new MagickReadSettings { Format = format };

            using var image = new MagickImage(context.FileStream, readSettings);

            evidence.Add(new ScanEvidence(
                Kind: "reencode-decode",
                Label: "pixels",
                Detail: $"Decoded as {format} (format pinned from signature detection, not guessed): " +
                        $"{image.Width}x{image.Height}, {image.ColorSpace} colour space, " +
                        $"{image.Depth}-bit depth. Only this pixel data can survive to the output.",
                Severity: "info"));

            // ---- LSB neutralisation (pixel-domain steganography) ----
            // Lossless PNG->PNG re-encoding preserves pixel values, so LSB-embedded
            // payloads survive it. Posterize(128) collapses each channel to the top
            // 7 bits, zeroing the least-significant bit and destroying LSB capacity.
            // Applied to clean and malicious files alike; visually imperceptible
            // (at most one intensity level per channel).
            if (_options.ClearLeastSignificantBit)
            {
                // Palette/indexed images don't expose per-channel RGB bits directly,
                // so normalise to true-colour first for a uniform operation.
                if (image.ColorType is ColorType.Palette or ColorType.PaletteAlpha)
                    image.ColorType = ColorType.TrueColor;

                // Clear the least-significant bit DETERMINISTICALLY via bitwise-AND
                // with 0xFE (254). Unlike Posterize, which ROUNDS to the nearest
                // level and can leave the LSB set on bright pixels, AND 0xFE zeroes
                // bit 0 on every channel of every pixel without exception.
                image.Evaluate(Channels.RGB, EvaluateOperator.And, 0xFE);

                evidence.Add(new ScanEvidence(
                    Kind: "reencode-lsb",
                    Label: "pixel-domain",
                    Detail: "Least-significant bit cleared on every RGB channel via deterministic " +
                            "bitwise-AND with 0xFE (after normalising palette images to true-colour). " +
                            "Destroys pixel-domain LSB steganography, which lossless re-encoding preserves. " +
                            "Alters each pixel by at most one intensity level.",
                    Severity: "medium"));
            }

            // ---- 3) Metadata stripping (a sub-operation of re-encoding) ----
            var profilesPresent = ProfileNames
                .Where(n => image.GetProfile(n) is not null)
                .ToList();

            if (_options.StripMetadata)
            {
                image.Strip();

                evidence.Add(new ScanEvidence(
                    Kind: "reencode-strip",
                    Label: "metadata",
                    Detail: profilesPresent.Count == 0
                        ? "Stripping enabled; the image carried none of the checked metadata containers, " +
                          "so nothing was removed at this step."
                        : $"Stripping enabled. Removed profile(s): {string.Join(", ", profilesPresent)}. " +
                          "These containers hold arbitrary bytes and are a documented payload carrier.",
                    Severity: profilesPresent.Count == 0 ? "info" : "medium"));
            }
            else
            {
                // The ablation switch has a security consequence, and it should be
                // legible in the result rather than only in the configuration file.
                evidence.Add(new ScanEvidence(
                    Kind: "reencode-strip",
                    Label: "metadata",
                    Detail: profilesPresent.Count == 0
                        ? "Stripping DISABLED, but the image carried none of the checked metadata containers."
                        : $"Stripping DISABLED and the image carries profile(s): " +
                          $"{string.Join(", ", profilesPresent)}. Magick.NET preserves profiles on write, so " +
                          "any payload held in them SURVIVES this layer. Present as an ablation setting; " +
                          "not a shipping configuration.",
                    Severity: profilesPresent.Count == 0 ? "info" : "high"));
            }

            // ---- 4) Re-encode: write a FRESH file of the same format ----
            if (format == MagickFormat.Jpeg)
                image.Quality = (uint)_options.JpegQuality;

            var reEncoded = new MemoryStream();
            image.Write(reEncoded, format);
            reEncoded.Position = 0;

            evidence.Add(DescribeRewrite(original, reEncoded, format, trailing));

            return ScanResult.Sanitize(Name, reEncoded, evidence);
        }
        catch (Exception ex)
        {
            // Fail-closed: if the file cannot be decoded and rebuilt as a plain
            // raster image, it is not treated as one.
            evidence.Add(new ScanEvidence(
                Kind: "scanner-error",
                Label: ex.GetType().Name,
                Detail: $"{ex.Message} A file that a pinned decoder cannot rebuild is not a plain raster " +
                        "image, so it is refused rather than passed through unmodified.",
                Severity: "unknown"));

            return ScanResult.Reject(Name, $"Image could not be re-encoded: {ex.Message}", evidence);
        }
    }

    // ------------------------------------------------------------------
    // Trailing-data measurement
    // ------------------------------------------------------------------

    /// <summary>
    /// Bytes found beyond the format's declared end of image.
    /// <paramref name="Determinable"/> is false when the end could not be located,
    /// in which case the absence of trailing data must not be reported as proof
    /// that there was none.
    /// </summary>
    private sealed record TrailingData(bool Determinable, long EndOffset, long ExtraBytes, string Basis, string Preview);

    private static TrailingData MeasureTrailingData(byte[] data, string type)
    {
        return type.ToLowerInvariant() switch
        {
            "jpeg" => MeasureJpeg(data),
            "png" => MeasurePng(data),
            "webp" => MeasureWebp(data),
            _ => new TrailingData(false, 0, 0, "unsupported format", "")
        };
    }

    /// <summary>
    /// JPEG ends at the EOI marker FF D9. The LAST occurrence is used: an embedded
    /// EXIF thumbnail is itself a complete JPEG and carries its own EOI, so the
    /// first match would sit inside the metadata rather than at the true end.
    /// </summary>
    private static TrailingData MeasureJpeg(byte[] data)
    {
        for (int i = data.Length - 2; i >= 0; i--)
        {
            if (data[i] != 0xFF || data[i + 1] != 0xD9) continue;

            long end = i + 2;
            long extra = data.Length - end;
            return new TrailingData(true, end, extra, "JPEG EOI marker (FF D9)", Preview(data, end, extra));
        }

        return new TrailingData(false, 0, 0, "JPEG EOI marker not found", "");
    }

    /// <summary>
    /// PNG ends with the IEND chunk: a 4-byte type followed by a 4-byte CRC and no
    /// payload, so the stream ends eight bytes after the type field begins.
    /// </summary>
    private static TrailingData MeasurePng(byte[] data)
    {
        var iend = Encoding.ASCII.GetBytes("IEND");

        for (int i = data.Length - iend.Length; i >= 0; i--)
        {
            bool match = true;
            for (int j = 0; j < iend.Length; j++)
                if (data[i + j] != iend[j]) { match = false; break; }

            if (!match) continue;

            long end = i + iend.Length + 4; // type + CRC
            if (end > data.Length) end = data.Length;

            long extra = data.Length - end;
            return new TrailingData(true, end, extra, "PNG IEND chunk", Preview(data, end, extra));
        }

        return new TrailingData(false, 0, 0, "PNG IEND chunk not found", "");
    }

    /// <summary>
    /// WebP is a RIFF container: bytes 4..7 hold a little-endian size covering
    /// everything after the first eight bytes, so the file should end there. Data
    /// beyond it is outside the container entirely — the byte range a RIFF reader
    /// never looks at, which is exactly what makes it a useful hiding place.
    /// </summary>
    private static TrailingData MeasureWebp(byte[] data)
    {
        if (data.Length < 12)
            return new TrailingData(false, 0, 0, "file shorter than a RIFF header", "");

        long riffSize = data[4] | ((long)data[5] << 8) | ((long)data[6] << 16) | ((long)data[7] << 24);
        long end = 8 + riffSize;

        if (end > data.Length || end < 12)
            return new TrailingData(false, 0, 0, "RIFF size field inconsistent with the actual length", "");

        long extra = data.Length - end;
        return new TrailingData(true, end, extra, "RIFF size field (bytes 4-7)", Preview(data, end, extra));
    }

    /// <summary>Printable window of the trailing bytes, so the reader can see what was there.</summary>
    private static string Preview(byte[] data, long start, long count, int max = 48)
    {
        if (count <= 0) return "";

        int take = (int)Math.Min(count, max);
        var sb = new StringBuilder();

        for (int i = 0; i < take; i++)
        {
            char c = (char)data[start + i];
            sb.Append(char.IsControl(c) || data[start + i] > 126 ? '.' : c);
        }

        if (count > take) sb.Append("...");
        return sb.ToString();
    }

    // ------------------------------------------------------------------
    // Reporting
    // ------------------------------------------------------------------

    private static ScanEvidence DescribeTrailing(TrailingData trailing, long totalSize)
    {
        if (!trailing.Determinable)
        {
            return new ScanEvidence(
                Kind: "reencode-trailing",
                Label: "appended-data",
                Detail: $"Could not locate the end of image ({trailing.Basis}), so the presence of appended " +
                        "data is UNDETERMINED for this file. Re-encoding still removes anything outside the " +
                        "pixel data, but this file must not be counted as evidence that none was there.",
                Severity: "low");
        }

        if (trailing.ExtraBytes <= 0)
        {
            return new ScanEvidence(
                Kind: "reencode-trailing",
                Label: "appended-data",
                Detail: $"None. The file ends at byte {trailing.EndOffset} per the {trailing.Basis}, which is " +
                        $"the full length ({totalSize} B). No content was hidden past the image.",
                Offset: trailing.EndOffset,
                Severity: "info");
        }

        return new ScanEvidence(
            Kind: "reencode-trailing",
            Label: "appended-data",
            Detail: $"{trailing.ExtraBytes} byte(s) present AFTER the end of image at offset " +
                    $"0x{trailing.EndOffset:X} ({trailing.Basis}), out of {totalSize} B total. " +
                    $"First bytes: \"{trailing.Preview}\". This range is not image content and no decoder " +
                    "reads it, which is what makes it a hiding place — and what re-encoding destroys. " +
                    "Verifiable in any hex editor at the stated offset.",
            Offset: trailing.EndOffset,
            Severity: "high",
            Reference: "Koch et al., On the Abuse and Detection of Polyglot Files, WWW 2025");
    }

    /// <summary>
    /// The before/after record, including a hash of the output.
    ///
    /// The hash is what makes the determinism claim checkable: re-running the same
    /// input through the same settings must produce the same digest. Without it,
    /// "deterministic" is an assertion; with it, a second run either reproduces the
    /// value or does not.
    /// </summary>
    private ScanEvidence DescribeRewrite(byte[] original, MemoryStream reEncoded, MagickFormat format, TrailingData trailing)
    {
        long before = original.Length;
        long after = reEncoded.Length;

        var position = reEncoded.Position;
        reEncoded.Position = 0;
        var digest = Convert.ToHexString(SHA256.HashData(reEncoded)).ToLowerInvariant();
        reEncoded.Position = position;

        var quality = format == MagickFormat.Jpeg ? $", JPEG quality {_options.JpegQuality}" : "";

        var neutralised = trailing.Determinable && trailing.ExtraBytes > 0
            ? $"NEUTRALISED: {trailing.ExtraBytes} byte(s) of appended data destroyed."
            : "Rebuilt with nothing measurable removed — a size change here is recompression, " +
              "not neutralisation, and must not be counted as one.";

        return new ScanEvidence(
            Kind: "reencode-rewrite",
            Label: "before/after",
            Detail: $"{before} B -> {after} B ({(after - before >= 0 ? "+" : "")}{after - before} B){quality}. " +
                    $"Output SHA-256: {digest}. {neutralised}",
            Severity: trailing.Determinable && trailing.ExtraBytes > 0 ? "high" : "info");
    }
}