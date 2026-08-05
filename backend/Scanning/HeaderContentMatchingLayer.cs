namespace SecureUploader.Scanning;

/// <summary>
/// Layer 3: Header–Content Matching.
/// Verifies that the client-declared Content-Type is consistent with the
/// REAL file type detected by the Magic Bytes layer.
/// Reference: OWASP File Upload Cheat Sheet — Content-Type is untrusted
/// and must be validated against the actual content.
/// DEPENDENCY: requires MagicBytesLayer to run BEFORE this layer.
///
/// ON "A MISMATCH NEVER HAPPENS LEGITIMATELY"
/// ------------------------------------------
/// That is not quite true, and the distinction matters for the reported
/// false-positive rate. A browser derives the Content-Type of an upload from the
/// operating system's MIME registry keyed on the file's EXTENSION — not from its
/// content. A user who renames a JPEG to .png on their own machine and uploads it
/// therefore produces a genuine mismatch with no hostile intent whatsoever, and
/// this layer rejects it.
///
/// So a mismatch does indicate that the declared type was not derived from the
/// bytes; it does NOT by itself indicate a crafted request. Misnamed files are
/// common in practice, and they are an expected source of false positives here —
/// stated rather than discovered later.
///
/// THE THIRD SIGNAL, AND WHY IT IS ONLY REPORTED
/// --------------------------------------------
/// Three things describe an upload's type: the filename extension, the declared
/// Content-Type, and the actual bytes. This layer compares the last two. Nothing
/// in the pipeline compares the FIRST against either — Layer 1 only checks the
/// extension against an allowlist, Layer 4 only looks for a hidden one.
///
/// A file named photo.png, carrying JPEG bytes, declared image/jpeg, therefore
/// passes every layer: the extension is allowed, the type is detected, and the
/// declaration agrees with the detection. Yet extension-versus-content
/// disagreement is precisely the signature of the documented in-the-wild
/// polyglots (a .jpg holding PNG+RAR, a .gif holding JPEG+PHP; Koch et al.,
/// WWW 2025).
///
/// The disagreement is therefore MEASURED AND REPORTED here, but does not cause a
/// rejection. Making it fatal would change which files the pipeline accepts, and
/// that change should follow from corpus evidence about how often benign uploads
/// are simply misnamed — not from an assumption made while writing the layer.
/// </summary>
public sealed class HeaderContentMatchingLayer : IScanLayer
{
    public string Name => "HeaderContentMatching";

    /// <summary>
    /// Reason prefixes, so corpus results can be grouped by rejection CAUSE
    /// without string-matching prose. MISMATCH is a finding about the upload;
    /// PIPELINE is a fault in our own configuration; MISSING and UNMAPPED are
    /// neither, and counting all four together would misreport every one of them.
    /// </summary>
    public const string ReasonMismatch = "HCM-MISMATCH";
    public const string ReasonMissing = "HCM-MISSING";
    public const string ReasonUnmapped = "HCM-UNMAPPED";
    public const string ReasonPipeline = "HCM-PIPELINE";

    // Accepted Content-Type values for each detected (real) file type.
    // The FIRST entry of each list is the canonical type; the rest are tolerated
    // aliases. The distinction is recorded, because a canonical value is what a
    // browser sends and an alias suggests an unusual or hand-built client.
    private static readonly Dictionary<string, string[]> AcceptedContentTypes =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["jpeg"] = new[] { "image/jpeg", "image/jpg" },
            ["png"] = new[] { "image/png" },
            ["webp"] = new[] { "image/webp" },
            ["svg"] = new[] { "image/svg+xml" },
            ["pdf"] = new[] { "application/pdf" }
        };

    /// <summary>
    /// Filename extension to the type its presence implies. Used ONLY to report
    /// extension-versus-content disagreement; never to accept or reject.
    /// </summary>
    private static readonly Dictionary<string, string> ExtensionToType =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["jpg"] = "jpeg",
            ["jpeg"] = "jpeg",
            ["png"] = "png",
            ["webp"] = "webp",
            ["svg"] = "svg",
            ["pdf"] = "pdf"
        };

    public ScanResult Scan(FileScanContext context)
    {
        // Fail securely: this layer cannot work without the detected type.
        // If it's missing, the pipeline is misconfigured (Magic Bytes didn't run).
        if (string.IsNullOrEmpty(context.DetectedFileType))
        {
            return ScanResult.Reject(Name,
                $"{ReasonPipeline}: DetectedFileType is missing — MagicBytesLayer must run before this layer.",
                new[]
                {
                    new ScanEvidence(
                        Kind: "hcm-pipeline",
                        Label: "detected-type",
                        Detail: "Absent. This is a fault in our own layer ordering, not a property of the " +
                                "upload, and must not be counted as a detection.",
                        Severity: "unknown")
                });
        }

        var detected = context.DetectedFileType;

        if (string.IsNullOrWhiteSpace(context.DeclaredContentType))
        {
            return ScanResult.Reject(Name,
                $"{ReasonMissing}: No Content-Type header was supplied (detected content: '{detected}').",
                BuildEvidence(context, detected, declaredRaw: "(absent)", declared: "", expected: null, matched: false));
        }

        if (!AcceptedContentTypes.TryGetValue(detected, out var accepted))
        {
            return ScanResult.Reject(Name,
                $"{ReasonUnmapped}: No Content-Type mapping exists for detected type '{detected}'. " +
                "The type passed signature detection but has no declared-type policy — a configuration gap.",
                new[]
                {
                    new ScanEvidence(
                        Kind: "hcm-unmapped",
                        Label: detected,
                        Detail: $"MagicBytesLayer recognises '{detected}' but this layer has no accepted " +
                                "Content-Type list for it. A gap between the two tables, not a finding " +
                                "about the file.",
                        Severity: "unknown")
                });
        }

        // Strip any parameters (e.g. "image/svg+xml; charset=utf-8" -> "image/svg+xml").
        var declaredRaw = context.DeclaredContentType;
        var declared = declaredRaw.Split(';')[0].Trim();

        bool matches = accepted.Any(a => string.Equals(a, declared, StringComparison.OrdinalIgnoreCase));

        var evidence = BuildEvidence(context, detected, declaredRaw, declared, accepted, matches);

        if (!matches)
        {
            return ScanResult.Reject(Name,
                $"{ReasonMismatch}: Declared Content-Type '{declared}' does not match detected content " +
                $"'{detected}'. Expected one of: {string.Join(", ", accepted)}.",
                evidence);
        }

        return ScanResult.Accept(Name, evidence);
    }

    /// <summary>
    /// Records all three type signals — extension, declaration, content — and how
    /// they relate. Produced on accept as well as reject: an accepted file whose
    /// extension disagrees with its content is exactly the case this layer does
    /// not currently act on, and it can only be quantified if it is written down
    /// when it happens.
    /// </summary>
    private static List<ScanEvidence> BuildEvidence(
        FileScanContext context,
        string detected,
        string declaredRaw,
        string declared,
        string[]? expected,
        bool matched)
    {
        var evidence = new List<ScanEvidence>
        {
            new(Kind: "hcm-detected",
                Label: "content",
                Detail: $"MagicBytesLayer identified the bytes as '{detected}'.",
                Severity: "info"),

            new(Kind: "hcm-declared",
                Label: "declared",
                Detail: declared.Length == 0
                    ? "No Content-Type header was supplied."
                    : $"Client declared '{declared}'" +
                      (declaredRaw != declared ? $" (raw header: '{declaredRaw}')" : "") + ".",
                Severity: "info")
        };

        if (expected is { Length: > 0 })
        {
            var canonical = expected[0];
            bool isAlias = matched && !string.Equals(declared, canonical, StringComparison.OrdinalIgnoreCase);

            evidence.Add(new ScanEvidence(
                Kind: matched ? "hcm-match" : "hcm-mismatch",
                Label: $"{detected} policy",
                Detail: matched
                    ? (isAlias
                        ? $"Accepted as a tolerated alias of the canonical '{canonical}'. Browsers send the " +
                          "canonical value, so an alias points to an unusual or hand-built client."
                        : $"Matches the canonical Content-Type for '{detected}'.")
                    : $"Expected one of [{string.Join(", ", expected)}]; the declaration is none of them. " +
                      "The declared type was therefore not derived from the bytes.",
                Severity: matched ? (isAlias ? "low" : "info") : "medium",
                Reference: matched ? null : "OWASP File Upload Cheat Sheet — Content-Type is untrusted"));
        }

        // The third signal. Reported only; see the class remarks for why it does
        // not decide anything.
        var extension = GetFinalExtension(context.FileName);

        if (extension.Length == 0)
        {
            evidence.Add(new ScanEvidence(
                Kind: "hcm-extension",
                Label: "extension",
                Detail: "The filename carries no extension, so no extension-versus-content comparison is possible.",
                Severity: "info"));
        }
        else if (!ExtensionToType.TryGetValue(extension, out var impliedByExtension))
        {
            evidence.Add(new ScanEvidence(
                Kind: "hcm-extension",
                Label: $".{extension}",
                Detail: "The extension implies no known type in this pipeline, so it cannot be compared " +
                        "against the content.",
                Severity: "info"));
        }
        else if (string.Equals(impliedByExtension, detected, StringComparison.OrdinalIgnoreCase))
        {
            evidence.Add(new ScanEvidence(
                Kind: "hcm-extension",
                Label: $".{extension}",
                Detail: $"Extension implies '{impliedByExtension}', which agrees with the detected content. " +
                        "All three type signals are consistent.",
                Severity: "info"));
        }
        else
        {
            evidence.Add(new ScanEvidence(
                Kind: "hcm-extension-mismatch",
                Label: $".{extension} vs {detected}",
                Detail: $"Extension implies '{impliedByExtension}' but the content is '{detected}'. " +
                        "NOT ACTED ON by this layer: no rule in the pipeline compares the extension " +
                        "against the bytes, so this observation is recorded and the file's fate is " +
                        "decided elsewhere. Extension-versus-content disagreement is the signature of " +
                        "the documented in-the-wild image polyglots, and is also what a locally " +
                        "misnamed but harmless file looks like — which is why it is measured before " +
                        "being enforced.",
                Severity: "medium",
                Reference: "Koch et al., On the Abuse and Detection of Polyglot Files, WWW 2025"));
        }

        return evidence;
    }

    /// <summary>
    /// Final extension, lowercased, without the dot. Empty when there is none.
    /// A dot-prefixed name such as ".htaccess" has no final extension in this
    /// sense and is Layer 4's concern, not this layer's.
    /// </summary>
    private static string GetFinalExtension(string? fileName)
    {
        if (string.IsNullOrWhiteSpace(fileName)) return "";

        int dot = fileName.LastIndexOf('.');
        if (dot <= 0 || dot == fileName.Length - 1) return "";

        return fileName[(dot + 1)..].Trim().ToLowerInvariant();
    }
}