using ImageMagick;
using SecureUploader.Models;

namespace SecureUploader.Services;

/// <summary>
/// Reference comparators: a C# re-implementation of the file-upload validation
/// logic of DVWA (Damn Vulnerable Web Application), at its four documented
/// security levels.
///
/// WHY DVWA: it is the most widely used teaching reference for secure file
/// upload, so its "Impossible" level is a recognised, citable point of
/// comparison — considerably stronger evidence than a weak baseline we wrote
/// ourselves and then beat.
///
/// METHODOLOGICAL DISCLOSURE (must be stated in the thesis):
///   - The original is PHP; this is a re-implementation of its documented logic
///     in C#, following the upstream source. DVWA itself was not executed.
///   - PHP's getimagesize() is modelled with MagickImageInfo: both read only the
///     image header and both accept any recognised image format regardless of
///     the file's extension. That equivalence is the point — it is also the
///     weakness that lets a header-valid image carrying an appended payload
///     through at the High level.
///   - DVWA re-encodes with PHP-GD; this uses Magick.NET, since it is already a
///     project dependency.
///   - Our host process sets ImageMagick ResourceLimits globally (Program.cs),
///     so these comparators inherit a memory ceiling the PHP original does not
///     have. They are therefore marginally MORE robust than real DVWA against
///     decompression bombs. Report the comparison as conservative, not exact.
///
/// DO NOT HARDEN THESE CLASSES. Their weaknesses are the measurement. Any check
/// added here that DVWA does not perform invalidates the comparison.
/// </summary>
public abstract class DvwaScannerBase : IFileScanner
{
    /// <summary>DVWA's size limit, in bytes, at every level above Low.</summary>
    protected const long DvwaMaxSize = 100_000;

    /// <summary>Extensions DVWA accepts. Note: no WEBP, no SVG, no PDF.</summary>
    protected static readonly string[] DvwaExtensions = { "jpg", "jpeg", "png" };

    /// <summary>Content types DVWA accepts (client-declared, therefore spoofable).</summary>
    protected static readonly string[] DvwaContentTypes = { "image/jpeg", "image/png" };

    public abstract string ScannerName { get; }

    public abstract Task<ScanResult> ScanAsync(IFormFile file, string category, CancellationToken ct = default);

    /// <summary>
    /// Mirrors DVWA's substr(name, strrpos(name, '.') + 1): the text after the
    /// LAST dot, lower-cased, without the dot.
    /// </summary>
    protected static string GetDvwaExtension(string fileName)
    {
        int dot = fileName.LastIndexOf('.');
        return dot < 0 ? "" : fileName[(dot + 1)..].ToLowerInvariant();
    }

    /// <summary>
    /// Models PHP getimagesize(): true if the HEADER parses as a known image.
    /// Reads the header only — it does not validate the rest of the file, which
    /// is precisely why appended-payload images survive this check.
    /// </summary>
    protected static bool LooksLikeImage(IFormFile file)
    {
        try
        {
            using var stream = file.OpenReadStream();
            var info = new MagickImageInfo(stream);
            return info.Width > 0 && info.Height > 0;
        }
        catch
        {
            return false;
        }
    }

    protected ScanResult Accept(string reason, List<string> checks) =>
        ScanResult.Accept(ScannerName, reason, checks);

    protected ScanResult Deny(string reason, List<string> checks) =>
        ScanResult.Reject(ScannerName, reason, checks);
}

/// <summary>
/// DVWA LOW — no validation whatsoever. The upstream code moves the uploaded
/// file into place without inspecting anything. Included as the true zero point
/// of the comparison: it accepts a web shell as readily as a photograph.
/// </summary>
public sealed class DvwaLowScanner : DvwaScannerBase
{
    public const string Name = "DVWA Low (no validation)";
    public override string ScannerName => Name;

    public override Task<ScanResult> ScanAsync(IFormFile file, string category, CancellationToken ct = default)
    {
        var checks = new List<string> { "No validation performed (DVWA Low accepts every upload)." };
        return Task.FromResult(Accept("Accepted without inspection.", checks));
    }
}

/// <summary>
/// DVWA MEDIUM — client-declared Content-Type plus a size limit.
/// Both inputs are attacker-controlled: the Content-Type is a request header,
/// and the size is trivially kept under the limit. The filename extension is
/// never examined, so 'shell.php' declared as image/jpeg is accepted.
/// </summary>
public sealed class DvwaMediumScanner : DvwaScannerBase
{
    public const string Name = "DVWA Medium (content-type + size)";
    public override string ScannerName => Name;

    public override Task<ScanResult> ScanAsync(IFormFile file, string category, CancellationToken ct = default)
    {
        var checks = new List<string>();
        var declared = file.ContentType ?? "";

        if (!DvwaContentTypes.Contains(declared, StringComparer.OrdinalIgnoreCase))
            return Task.FromResult(Deny($"Declared Content-Type '{declared}' is not image/jpeg or image/png.", checks));
        checks.Add($"Declared Content-Type accepted: '{declared}' (client-controlled).");

        if (file.Length >= DvwaMaxSize)
            return Task.FromResult(Deny($"File is {file.Length:N0} bytes; DVWA's limit is {DvwaMaxSize:N0}.", checks));
        checks.Add($"Size accepted: {file.Length:N0} bytes.");

        return Task.FromResult(Accept("Passed DVWA Medium validation.", checks));
    }
}

/// <summary>
/// DVWA HIGH — extension, size, and getimagesize(). Notably it does NOT check
/// the declared Content-Type, and getimagesize() inspects only the header, so a
/// file with a valid image header and a payload appended after the image data
/// passes this level intact.
/// </summary>
public sealed class DvwaHighScanner : DvwaScannerBase
{
    public const string Name = "DVWA High (extension + size + getimagesize)";
    public override string ScannerName => Name;

    public override Task<ScanResult> ScanAsync(IFormFile file, string category, CancellationToken ct = default)
    {
        var checks = new List<string>();
        var ext = GetDvwaExtension(file.FileName);

        if (!DvwaExtensions.Contains(ext))
            return Task.FromResult(Deny($"Extension '{ext}' is not jpg, jpeg, or png.", checks));
        checks.Add($"Extension accepted: '{ext}' (last extension only).");

        if (file.Length >= DvwaMaxSize)
            return Task.FromResult(Deny($"File is {file.Length:N0} bytes; DVWA's limit is {DvwaMaxSize:N0}.", checks));
        checks.Add($"Size accepted: {file.Length:N0} bytes.");

        if (!LooksLikeImage(file))
            return Task.FromResult(Deny("getimagesize() equivalent failed: header is not a recognised image.", checks));
        checks.Add("Image header parsed successfully (header only — trailing data is not examined).");

        return Task.FromResult(Accept("Passed DVWA High validation.", checks));
    }
}

/// <summary>
/// DVWA IMPOSSIBLE — extension AND size AND declared Content-Type AND
/// getimagesize(), followed by RE-ENCODING the image, which discards everything
/// that is not pixel data.
///
/// This is the strongest reference comparator and overlaps deliberately with our
/// own Layer 6: it destroys appended payloads, polyglots, and metadata-carried
/// content by the same mechanism. The comparison is therefore not "we do
/// re-encoding and they do not" — it is about the accepted type range (this
/// handles JPEG/PNG only; no PDF, no SVG, no WEBP), the absence of signature
/// scanning, and the absence of any bomb guard.
/// </summary>
public sealed class DvwaImpossibleScanner : DvwaScannerBase
{
    public const string Name = "DVWA Impossible (validate + re-encode)";
    public override string ScannerName => Name;

    public override async Task<ScanResult> ScanAsync(IFormFile file, string category, CancellationToken ct = default)
    {
        var checks = new List<string>();
        var ext = GetDvwaExtension(file.FileName);

        if (!DvwaExtensions.Contains(ext))
            return Deny($"Extension '{ext}' is not jpg, jpeg, or png.", checks);
        checks.Add($"Extension accepted: '{ext}'.");

        if (file.Length >= DvwaMaxSize)
            return Deny($"File is {file.Length:N0} bytes; DVWA's limit is {DvwaMaxSize:N0}.", checks);
        checks.Add($"Size accepted: {file.Length:N0} bytes.");

        var declared = file.ContentType ?? "";
        if (!DvwaContentTypes.Contains(declared, StringComparer.OrdinalIgnoreCase))
            return Deny($"Declared Content-Type '{declared}' is not image/jpeg or image/png.", checks);
        checks.Add($"Declared Content-Type accepted: '{declared}'.");

        if (!LooksLikeImage(file))
            return Deny("getimagesize() equivalent failed: header is not a recognised image.", checks);
        checks.Add("Image header parsed successfully.");

        // Re-encode. DVWA uses PHP-GD (imagecreatefromjpeg + imagejpeg at quality
        // 100, or imagecreatefrompng + imagepng at compression 9); Magick.NET is
        // substituted here. Note there is NO dimension or pixel-count guard —
        // faithfully so: DVWA has none either.
        try
        {
            var buffer = new MemoryStream();
            await using (var source = file.OpenReadStream())
                await source.CopyToAsync(buffer, ct);
            buffer.Position = 0;

            using var image = new MagickImage(buffer);
            var format = ext == "png" ? MagickFormat.Png : MagickFormat.Jpeg;

            if (format == MagickFormat.Jpeg)
                image.Quality = 100;

            var reEncoded = new MemoryStream();
            image.Write(reEncoded, format);
            reEncoded.Position = 0;

            checks.Add("Image re-encoded; non-pixel data discarded.");
            return ScanResult.AcceptSanitized(ScannerName, "Passed DVWA Impossible validation and was re-encoded.", reEncoded, checks);
        }
        catch (Exception ex)
        {
            return Deny($"Re-encoding failed: {ex.Message}", checks);
        }
    }
}
