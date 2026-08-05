using System.Text;

namespace SecureUploader.Scanning;

/// <summary>
/// Layer 2: Magic Bytes (File Signature) Verification.
/// Determines the REAL file type from its content, ignoring the
/// (untrusted) extension and declared Content-Type.
/// Reference: OWASP File Upload Cheat Sheet — validate the file type by
/// checking the file signature, never trust client-supplied metadata.
/// Signature offsets/values are taken from the official format specifications.
///
/// This layer DETECTS a type; it does not compare that type against what the
/// client claimed. The comparison is Layer 3's job, and keeping the two apart is
/// what allows the evaluation to distinguish "the bytes are of a type we do not
/// accept" from "the bytes disagree with the declared type" — two different
/// findings that a combined layer would report as one.
///
/// WHY A REJECTION NAMES THE FORMAT IT FOUND
/// -----------------------------------------
/// "Signature does not match any allowed type" states the conclusion and discards
/// the observation. The bytes were in hand; the layer could have said what they
/// were. A reference table of common formats that are NOT accepted is therefore
/// consulted on the way out, so a rejection reads "these bytes are a ZIP archive"
/// rather than "unknown".
///
/// This matters for the polyglot corpus specifically. Real in-the-wild samples
/// pair an image container with a covert ZIP, RAR, PHP or SWF payload
/// (Koch et al., WWW 2025), so naming the covert format converts a bare refusal
/// into a statement about which attack class was met — and a claim a reviewer can
/// verify with any hex editor.
/// </summary>
public sealed class MagicBytesLayer : IScanLayer
{
    public string Name => "MagicBytes";

    /// <summary>A byte pattern expected at a specific offset in the file.</summary>
    private sealed record FileSignature(int Offset, byte[] Pattern);

    // Known signatures per file type. A type matches only if ALL of its
    // signatures match (needed for WEBP: "RIFF" at 0 AND "WEBP" at 8).
    private static readonly Dictionary<string, FileSignature[]> Signatures = new()
    {
        ["jpeg"] = new[] { new FileSignature(0, new byte[] { 0xFF, 0xD8, 0xFF }) },
        ["png"] = new[] { new FileSignature(0, new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }) },
        ["pdf"] = new[] { new FileSignature(0, new byte[] { 0x25, 0x50, 0x44, 0x46 }) }, // "%PDF"
        ["webp"] = new[]
        {
            new FileSignature(0, new byte[] { 0x52, 0x49, 0x46, 0x46 }), // "RIFF"
            new FileSignature(8, new byte[] { 0x57, 0x45, 0x42, 0x50 })  // "WEBP"
        }
    };

    /// <summary>
    /// A format this pipeline recognises but does not accept, with the reason.
    /// Consulted only to EXPLAIN a rejection — nothing here can cause one, since
    /// anything absent from <see cref="Signatures"/> is already refused.
    /// </summary>
    private sealed record KnownForeignFormat(string Name, int Offset, byte[] Pattern, string Note);

    /// <summary>
    /// Formats worth naming when they turn up. Chosen for what actually appears
    /// on an upload endpoint: archive and executable containers used as covert
    /// halves of image polyglots, script and markup types that a permissive
    /// server may execute, and the image formats deliberately dropped from the
    /// accepted set — a removed type should be reported as removed, not unknown.
    /// Ordered longest-pattern-first so the most specific match wins.
    /// </summary>
    private static readonly KnownForeignFormat[] ForeignFormats =
    {
        new("OLE / legacy Office (CFB)", 0, new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 },
            "Office binary container; compound documents are outside the accepted set."),
        new("RAR archive", 0, new byte[] { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07 },
            "Archive. A PNG+RAR pairing is a documented in-the-wild polyglot."),
        new("7-Zip archive", 0, new byte[] { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C },
            "Archive; archives are outside the accepted set."),
        new("RTF document", 0, new byte[] { 0x7B, 0x5C, 0x72, 0x74, 0x66 },
            "Rich Text; historically an exploit-delivery container."),
        new("ELF executable", 0, new byte[] { 0x7F, 0x45, 0x4C, 0x46 },
            "Executable binary."),
        new("Java class file", 0, new byte[] { 0xCA, 0xFE, 0xBA, 0xBE },
            "Executable bytecode."),
        new("ZIP archive (or JAR / OOXML)", 0, new byte[] { 0x50, 0x4B, 0x03, 0x04 },
            "Archive. A JPEG+ZIP pairing is a documented in-the-wild polyglot."),
        new("ZIP archive (empty or spanned)", 0, new byte[] { 0x50, 0x4B, 0x05, 0x06 },
            "Archive; end-of-central-directory variant."),
        new("GIF image", 0, new byte[] { 0x47, 0x49, 0x46, 0x38 },
            "Recognised image format, REMOVED from the accepted set (superseded by WebP)."),
        new("TIFF image (little-endian)", 0, new byte[] { 0x49, 0x49, 0x2A, 0x00 },
            "Recognised image format, not in the accepted set."),
        new("TIFF image (big-endian)", 0, new byte[] { 0x4D, 0x4D, 0x00, 0x2A },
            "Recognised image format, not in the accepted set."),
        new("Windows icon", 0, new byte[] { 0x00, 0x00, 0x01, 0x00 },
            "Recognised image format, not in the accepted set."),
        new("WebAssembly module", 0, new byte[] { 0x00, 0x61, 0x73, 0x6D },
            "Executable module."),
        new("PostScript", 0, new byte[] { 0x25, 0x21, 0x50, 0x53 },
            "Interpreted page-description language."),
        new("Microsoft Cabinet", 0, new byte[] { 0x4D, 0x53, 0x43, 0x46 },
            "Archive."),
        new("Flash (uncompressed)", 0, new byte[] { 0x46, 0x57, 0x53 },
            "Executable media. A SWF disguised with an image extension appears in the polyglot corpus."),
        new("Flash (compressed)", 0, new byte[] { 0x43, 0x57, 0x53 },
            "Executable media."),
        new("Windows executable (MZ / PE)", 0, new byte[] { 0x4D, 0x5A },
            "Executable binary."),
        new("gzip stream", 0, new byte[] { 0x1F, 0x8B },
            "Compressed stream; archives are outside the accepted set."),
        new("BMP image", 0, new byte[] { 0x42, 0x4D },
            "Recognised image format, not in the accepted set."),
        new("Shell script (shebang)", 0, new byte[] { 0x23, 0x21 },
            "Interpreted script."),
    };

    /// <summary>
    /// Text markers checked when no binary signature matched. Text formats have no
    /// magic bytes, so a hostile upload can be plain text end to end; naming what
    /// the text actually is turns "unknown bytes" into a specific finding.
    /// </summary>
    private static readonly (string Name, string Marker, string Note)[] ForeignTextMarkers =
    {
        ("PHP source", "<?php", "Server-side script; the covert half of most documented image polyglots."),
        ("PHP short-open source", "<?=", "Server-side script (short-open tag)."),
        ("HTML document", "<!doctype html", "Markup; renders and can execute script when served inline."),
        ("HTML document", "<html", "Markup; renders and can execute script when served inline."),
        ("XML document (non-SVG)", "<?xml", "XML without an <svg root element."),
        ("Windows batch script", "@echo off", "Interpreted script."),
    };

    // How many bytes we need from the start of the file to test every
    // signature above (longest requirement: WEBP needs bytes 0..11).
    private const int HeaderReadLength = 16;

    /// <summary>Bytes of text inspected when looking for a text-based type.</summary>
    private const int TextProbeLength = 1024;

    public ScanResult Scan(FileScanContext context)
    {
        // Reset explicitly. The stream is shared with every other layer, so reading
        // from wherever a predecessor happened to leave the cursor makes this
        // layer's correctness depend on the pipeline's order. It works today only
        // because Layer 1 inspects the filename and never touches the stream.
        context.FileStream.Position = 0;

        var header = new byte[HeaderReadLength];
        int bytesRead = ReadUpTo(context.FileStream, header, HeaderReadLength);

        // Fail securely: a file too small to contain any valid signature is rejected.
        if (bytesRead < 4)
        {
            var tooSmall = new[]
            {
                new ScanEvidence(
                    Kind: "magic-size",
                    Label: "bytes-available",
                    Detail: $"{bytesRead} byte(s) readable; at least 4 are required to test any signature. " +
                            (bytesRead > 0 ? $"Observed: {ToHex(header, bytesRead)}" : "The stream is empty."),
                    Offset: 0,
                    Severity: "low")
            };

            context.FileStream.Position = 0;
            return ScanResult.Reject(Name, $"File too small to contain a valid signature ({bytesRead} B).", tooSmall);
        }

        // 1) Try binary signatures first. Ordered for a stable, reproducible report.
        foreach (var type in Signatures.Keys.OrderBy(k => k, StringComparer.Ordinal))
        {
            var signatures = Signatures[type];
            if (!signatures.All(sig => MatchesAt(header, bytesRead, sig))) continue;

            context.DetectedFileType = type;

            var accepted = signatures.Select(sig => new ScanEvidence(
                Kind: "magic-match",
                Label: $"{type} @{sig.Offset}",
                Detail: $"expected {ToHex(sig.Pattern, sig.Pattern.Length)}, " +
                        $"found {ToHex(header, bytesRead, sig.Offset, sig.Pattern.Length)} — match",
                Offset: sig.Offset,
                Severity: "info")).ToList();

            context.FileStream.Position = 0;
            return ScanResult.Accept(Name, accepted);
        }

        // 2) SVG special case: text-based (XML), has no binary magic bytes.
        //    Read a larger text chunk and look for the <svg root element.
        var probe = ReadTextProbe(context.FileStream);

        if (LooksLikeSvg(probe, out int svgIndex, out bool svgIsRoot))
        {
            context.DetectedFileType = "svg";

            // Reported, not enforced. The marker is accepted wherever it appears in
            // the probe — which is how this layer has always behaved — but an <svg
            // that is NOT the root element is an anomaly worth surfacing: it is how
            // a file of some other type acquires an SVG classification. Tightening
            // the check would change which files are accepted, so the observation is
            // published and the decision left to the measurement.
            var svgEvidence = new List<ScanEvidence>
            {
                new(Kind: "magic-match",
                    Label: "svg marker",
                    Detail: svgIsRoot
                        ? "\"<svg\" is the first element in the document — a well-formed SVG root."
                        : $"\"<svg\" found at byte {svgIndex} but it is NOT the first element. " +
                          "Detection is by marker presence, so a non-root occurrence still " +
                          "classifies the file as SVG. Structural anomaly.",
                    Offset: svgIndex,
                    Severity: svgIsRoot ? "info" : "low")
            };

            context.FileStream.Position = 0;
            return ScanResult.Accept(Name, svgEvidence);
        }

        // Fail securely: unknown signature => reject. On the way out, say what the
        // bytes actually were — the information is already in hand.
        var evidence = new List<ScanEvidence>
        {
            new(Kind: "magic-observed",
                Label: "header",
                Detail: $"first {bytesRead} byte(s): {ToHex(header, bytesRead)}",
                Offset: 0,
                Severity: "info")
        };

        string identified = IdentifyForeign(header, bytesRead, probe, evidence);

        foreach (var near in NearMisses(header, bytesRead))
            evidence.Add(near);

        context.FileStream.Position = 0;

        return ScanResult.Reject(
            Name,
            identified.Length > 0
                ? $"Signature is not an accepted type — content identified as {identified}. " +
                  $"Header: {ToHex(header, bytesRead)}"
                : $"File signature does not match any allowed type. Header: {ToHex(header, bytesRead)}",
            evidence);
    }

    // ------------------------------------------------------------------
    // Identification helpers
    // ------------------------------------------------------------------

    /// <summary>
    /// Names the content when it is a format this pipeline knows but rejects, and
    /// records the finding. Returns an empty string when nothing is recognised.
    /// </summary>
    private static string IdentifyForeign(byte[] header, int bytesRead, string probe, List<ScanEvidence> evidence)
    {
        foreach (var format in ForeignFormats)
        {
            if (!MatchesAt(header, bytesRead, new FileSignature(format.Offset, format.Pattern)))
                continue;

            evidence.Add(new ScanEvidence(
                Kind: "magic-foreign",
                Label: format.Name,
                Detail: $"signature {ToHex(format.Pattern, format.Pattern.Length)} at offset {format.Offset}. {format.Note}",
                Offset: format.Offset,
                Severity: "medium"));

            return format.Name;
        }

        var trimmed = probe.TrimStart('\uFEFF', ' ', '\t', '\r', '\n');

        foreach (var (name, marker, note) in ForeignTextMarkers)
        {
            int idx = trimmed.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            if (idx < 0) continue;

            evidence.Add(new ScanEvidence(
                Kind: "magic-foreign",
                Label: name,
                Detail: $"text marker \"{marker}\" found at byte {idx} of the decoded probe. {note}",
                Offset: idx,
                Severity: "medium"));

            return name;
        }

        return "";
    }

    /// <summary>
    /// Reports allowed signatures that partially matched, with the byte where they
    /// diverged. A near miss distinguishes a truncated or corrupted file of an
    /// accepted type from a file of an entirely different type — the same
    /// rejection, but not the same finding.
    /// </summary>
    private static IEnumerable<ScanEvidence> NearMisses(byte[] header, int bytesRead)
    {
        foreach (var type in Signatures.Keys.OrderBy(k => k, StringComparer.Ordinal))
        {
            foreach (var sig in Signatures[type])
            {
                if (sig.Offset >= bytesRead) continue;

                int matched = 0;
                int comparable = Math.Min(sig.Pattern.Length, bytesRead - sig.Offset);

                while (matched < comparable && header[sig.Offset + matched] == sig.Pattern[matched])
                    matched++;

                // Only interesting when it started to match but then broke.
                if (matched == 0 || matched == sig.Pattern.Length) continue;

                var expected = sig.Pattern[matched];
                var found = header[sig.Offset + matched];

                yield return new ScanEvidence(
                    Kind: "magic-near-miss",
                    Label: $"{type} @{sig.Offset}",
                    Detail: $"first {matched} of {sig.Pattern.Length} signature byte(s) matched, then diverged " +
                            $"at offset {sig.Offset + matched}: expected 0x{expected:X2}, found 0x{found:X2}.",
                    Offset: sig.Offset + matched,
                    Severity: "low");
            }
        }
    }

    // ------------------------------------------------------------------
    // Low-level helpers
    // ------------------------------------------------------------------

    /// <summary>
    /// Fills the buffer with a read LOOP.
    /// A single Stream.Read may legally return fewer bytes than asked for; it
    /// happens to fill for a MemoryStream, which is why one call has worked so
    /// far. Against a stream that returns short reads, a 12-byte signature such as
    /// WebP's would silently fail to match a perfectly valid file.
    /// </summary>
    private static int ReadUpTo(Stream stream, byte[] buffer, int count)
    {
        int total = 0;
        while (total < count)
        {
            int read = stream.Read(buffer, total, count - total);
            if (read == 0) break;
            total += read;
        }
        return total;
    }

    /// <summary>
    /// Reads the leading text of the file for marker-based detection.
    /// Up to 1 KB: enough to get past an XML declaration, comments, and whitespace
    /// before the root element.
    /// </summary>
    private static string ReadTextProbe(Stream stream)
    {
        stream.Position = 0;

        var buffer = new byte[TextProbeLength];
        int read = ReadUpTo(stream, buffer, TextProbeLength);

        return Encoding.UTF8.GetString(buffer, 0, read);
    }

    /// <summary>
    /// Marker-based SVG detection, unchanged in effect: the file counts as SVG when
    /// "&lt;svg" appears anywhere in the probe.
    /// Also reports WHERE it appeared and whether it was the first element, so the
    /// gap between that rule and a true root-element check is visible in the
    /// results rather than only in this comment.
    ///
    /// (Deep XSS inspection is NOT this layer's job — that is Layer 7,
    /// SVG Sanitization.)
    /// </summary>
    private static bool LooksLikeSvg(string probe, out int index, out bool isRoot)
    {
        index = probe.IndexOf("<svg", StringComparison.OrdinalIgnoreCase);
        isRoot = false;

        if (index < 0) return false;

        // Root when the only elements before it are the XML declaration, a DOCTYPE,
        // or comments — i.e. nothing that is itself content.
        var before = probe[..index];
        int firstElement = -1;

        for (int i = 0; i < before.Length; i++)
        {
            if (before[i] != '<') continue;

            bool declarative =
                (i + 1 < before.Length && (before[i + 1] == '?' || before[i + 1] == '!'));

            if (!declarative) { firstElement = i; break; }
        }

        isRoot = firstElement < 0;
        return true;
    }

    private static bool MatchesAt(byte[] header, int bytesRead, FileSignature sig)
    {
        if (sig.Offset + sig.Pattern.Length > bytesRead)
            return false;

        for (int i = 0; i < sig.Pattern.Length; i++)
        {
            if (header[sig.Offset + i] != sig.Pattern[i])
                return false;
        }
        return true;
    }

    /// <summary>Space-separated uppercase hex, the form a reviewer can compare against a hex editor.</summary>
    private static string ToHex(byte[] data, int length, int start = 0, int? take = null)
    {
        int end = Math.Min(length, take is null ? length : start + take.Value);
        if (start >= end) return "(none)";

        var sb = new StringBuilder();
        for (int i = start; i < end; i++)
        {
            if (sb.Length > 0) sb.Append(' ');
            sb.Append(data[i].ToString("X2"));
        }
        return sb.ToString();
    }
}