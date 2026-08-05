using System.Text;
using System.Text.RegularExpressions;

namespace SecureUploader.Scanning;

/// <summary>
/// Layer 5c: Embedded Link Scanning.
/// SVG and PDF files can embed URLs (external references, link annotations,
/// URI actions). An external or dangerous-scheme link inside an uploaded file
/// is a phishing / SSRF / tracking / script-injection vector. This layer
/// extracts URLs from linkable file types and rejects:
///   - any dangerous URI scheme (javascript:, file:, executable data:, ...)
///   - any external http(s) link whose host is not on the trusted allow-list
///
/// SCHEME MATCHING IS ANCHORED, NOT SUBSTRING
/// ------------------------------------------
/// The previous implementation tested each scheme with a bare substring search.
/// That rejects on any occurrence anywhere in the file, including inside ordinary
/// words, and "file:" is a substring of "Profile:" — a heading that appears in
/// most curricula vitae. Every CV in the benign corpus would have been rejected
/// as embedding a dangerous URI. "jar:" inside "Cellar:" and "mocha:" inside
/// longer words fail the same way.
///
/// A scheme is therefore matched only where a URI can actually begin: at the start
/// of the text or after a character that cannot be part of a scheme name. The
/// change makes the layer strictly less aggressive, so files that were previously
/// rejected for this reason will now pass — which is the intended correction, not
/// a relaxation of policy.
///
/// URL-SHAPED STRINGS THAT ARE NOT LINKS
/// -------------------------------------
/// Measured on the 25 benign PDFs of CIC-Evasive-PDFMal2022, this layer rejected
/// 19 of them. Every single rejection came from XML namespace identifiers in the
/// XMP metadata packet — www.w3.org, ns.adobe.com and similar — and /URI appeared
/// ZERO times across the whole benign set. Not one file contained a real link.
///
/// A namespace identifier is URL-shaped by convention and nothing more: it is
/// never fetched, never clicked, and never chosen by whoever produced the
/// document. The XMP and RDF specifications fix these exact strings and every PDF
/// writer emits them. The layer was therefore inspecting FORMAT METADATA as
/// though it were user content, and the fix below is a correction of that, not a
/// relaxation of policy.
///
/// This is deliberately NOT a list of "reputable" or "well-known safe" sites.
/// Popularity is not safety — modern phishing is hosted on GitHub Pages, Drive
/// and Dropbox precisely BECAUSE those hosts are trusted — and because matching
/// includes subdomains, admitting one such host would admit every page under it.
/// The distinction drawn here is between format machinery and content, which is
/// stable, rather than between good and bad hosts, which is not.
///
/// TWO LIMITS THIS LAYER DECLARES RATHER THAN HIDES
/// ------------------------------------------------
/// (1) COMPRESSED STREAMS ARE INVISIBLE. Only raw bytes are inspected, so a URL
///     inside a FlateDecode-compressed PDF stream is not seen — the same
///     limitation that justifies Layer 5b existing, except that 5b runs YARA over
///     the decompressed content and does not extract links from it. When a
///     compressed stream is present, that fact is recorded, so a clean result is
///     never mistaken for a complete one.
///
/// (2) LITERAL MATCHING SEES NO ENCODING. SVG may express a scheme with character
///     entities or percent-encoding, and browsers decode both. Matching plain text
///     does not. Noted on SVG input for the same reason.
///
/// An empty allow-list means every external host is untrusted, so with external
/// blocking enabled ANY http(s) link is fatal. That remains the policy for real
/// links, and its cost is reported in the evidence of every scan so it stays
/// visible in the results rather than being discovered in them.
/// </summary>
public sealed class EmbeddedLinkLayer : IScanLayer
{
    public string Name => "EmbeddedLinkScan";

    /// <summary>
    /// Reason prefixes, so corpus results can be grouped by rejection CAUSE
    /// without string-matching prose. EXTERNAL is a policy outcome with a known
    /// benign-collision rate; SCHEME and DATAURI are findings about content that
    /// has no legitimate reason to be in an upload. Counting them together would
    /// hide which of the two the numbers actually came from.
    /// </summary>
    public const string ReasonScheme = "EL-SCHEME";
    public const string ReasonDataUri = "EL-DATAURI";
    public const string ReasonExternal = "EL-EXTERNAL";
    public const string ReasonError = "EL-ERROR";

    private readonly HashSet<string> _allowedDomains;
    private readonly bool _blockExternalLinks;

    // Always-dangerous URI schemes, without the colon: the colon and any
    // whitespace before it are handled by the anchored pattern.
    private static readonly string[] DangerousSchemes =
        { "javascript", "vbscript", "livescript", "mocha", "file", "php", "jar" };

    /// <summary>
    /// Anchored scheme patterns, built once.
    /// The lookbehind rejects a match preceded by any character that could belong
    /// to a scheme name, which is what prevents "file" inside "profile" from
    /// matching. Whitespace before the colon is tolerated because parsers do.
    /// </summary>
    private static readonly (string Scheme, Regex Pattern)[] SchemePatterns =
        DangerousSchemes.Select(s => (
            s,
            new Regex($@"(?<![A-Za-z0-9+.\-]){Regex.Escape(s)}\s*:",
                RegexOptions.IgnoreCase | RegexOptions.Compiled)
        )).ToArray();

    // data: URIs that can carry executable content (benign image data: URIs are allowed).
    private static readonly string[] DangerousDataUris =
        { "data:text/html", "data:application/", "data:image/svg" };

    private static readonly Regex UrlRegex = new(
        @"https?://[^\s""'<>)\]]+",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex HostRegex = new(
        @"^https?://([^/:\s]+)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>
    /// Hosts that appear in a document as XML NAMESPACE IDENTIFIERS rather than as
    /// links, established by measurement — see the class remarks.
    ///
    /// Every entry is fixed by a published specification (RDF, XMP, Dublin Core,
    /// PDF/A, ICC), so which strings appear here is not a judgement about the
    /// hosts. It is a statement about which byte sequences the FORMAT requires a
    /// writer to emit.
    ///
    /// Matched on the HOST, so a genuine request to one of these hosts is also
    /// permitted — a narrow, accepted hole. Closing it properly means skipping the
    /// metadata REGIONS instead of these hosts, which needs the structural parsing
    /// this filter deliberately avoids for attack-surface reasons. Recorded as a
    /// known limitation rather than presented as complete.
    /// </summary>
    private static readonly HashSet<string> SpecificationNamespaceHosts =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "www.w3.org",             // RDF / XML / SVG namespace declarations
            "ns.adobe.com",           // XMP: iX, pdf, xap, photoshop schemas
            "purl.org",               // Dublin Core metadata terms
            "iptc.org",               // IPTC photo metadata
            "www.iptc.org",
            "www.aiim.org",           // PDF/A identification schema
            "pdfa.org",
            "www.pdfa.org",
            "www.npes.org",           // PRISM / print production metadata
            "schemas.microsoft.com",  // Office-produced PDF metadata
            "www.color.org",          // ICC profile references
            "iso.org",
            "www.iso.org",
            "crossmark.crossref.org", // publisher metadata schema
            "www.prismstandard.org",
        };

    /// <summary>How many distinct findings to name inline before summarising.</summary>
    private const int MaxReportedItems = 5;

    public EmbeddedLinkLayer(IEnumerable<string>? allowedDomains = null, bool blockExternalLinks = true)
    {
        _allowedDomains = (allowedDomains ?? Enumerable.Empty<string>())
            .Select(d => d.Trim().ToLowerInvariant())
            .Where(d => d.Length > 0)
            .ToHashSet();
        _blockExternalLinks = blockExternalLinks;
    }

    public ScanResult Scan(FileScanContext context)
    {
        try
        {
            context.FileStream.Position = 0;
            byte[] raw;
            using (var ms = new MemoryStream())
            {
                context.FileStream.CopyTo(ms);
                raw = ms.ToArray();
            }
            context.FileStream.Position = 0;

            // Only SVG and PDF can meaningfully embed links among accepted types.
            var kind = ClassifyLinkableType(raw);
            if (kind == LinkableKind.None)
            {
                return ScanResult.Accept(Name, new[]
                {
                    new ScanEvidence(
                        Kind: "link-scope",
                        Label: "not-linkable",
                        Detail: "Neither a PDF nor an SVG, so no link-bearing structure exists to inspect.",
                        Severity: "info")
                });
            }

            // Decode as text (Latin1 preserves every byte; URLs are ASCII anyway).
            string content = Encoding.Latin1.GetString(raw);

            var evidence = new List<ScanEvidence> { DescribeScope(kind, content) };
            evidence.Add(DescribePolicy());

            // 1a. Always-dangerous schemes, anchored so ordinary words cannot match.
            foreach (var (scheme, pattern) in SchemePatterns)
            {
                var match = pattern.Match(content);
                if (!match.Success) continue;

                evidence.Add(new ScanEvidence(
                    Kind: "link-scheme",
                    Label: $"{scheme}:",
                    Detail: $"Found at byte {match.Index} as \"{Excerpt(content, match.Index, match.Length)}\". " +
                            $"Total occurrences: {pattern.Matches(content).Count}. " +
                            "The scheme sits at a position where a URI can begin, so it is a genuine " +
                            "scheme reference rather than a substring of a longer word.",
                    Offset: match.Index,
                    Severity: "high",
                    Reference: "OWASP File Upload Cheat Sheet — dangerous URI schemes"));

                return ScanResult.Reject(Name,
                    $"{ReasonScheme}: Embeds the dangerous URI scheme '{scheme}:' at byte {match.Index}.",
                    evidence);
            }

            // 1b. Executable data: URIs (benign image data: URIs are allowed).
            foreach (var d in DangerousDataUris)
            {
                int idx = content.IndexOf(d, StringComparison.OrdinalIgnoreCase);
                if (idx < 0) continue;

                evidence.Add(new ScanEvidence(
                    Kind: "link-datauri",
                    Label: d,
                    Detail: $"Found at byte {idx} as \"{Excerpt(content, idx, d.Length)}\". " +
                            "A data: URI of this media type carries content that can execute, unlike a " +
                            "plain image data: URI, which is permitted.",
                    Offset: idx,
                    Severity: "high"));

                return ScanResult.Reject(Name,
                    $"{ReasonDataUri}: Embeds an executable data: URI '{d}' at byte {idx}.",
                    evidence);
            }

            // 2. External http(s) links. Every link is collected before any verdict,
            //    so the report states how many there were and how many hosts were
            //    involved — a single named host would give no sense of scale.
            var links = CollectLinks(content);
            evidence.Add(DescribeLinks(links));

            var untrusted = links
                .Where(l => !IsAllowed(l.Host))
                .ToList();

            if (_blockExternalLinks && untrusted.Count > 0)
            {
                var hosts = untrusted
                    .Select(l => l.Host)
                    .Distinct(StringComparer.Ordinal)
                    .OrderBy(h => h, StringComparer.Ordinal)
                    .ToList();

                foreach (var host in hosts.Take(MaxReportedItems))
                {
                    var first = untrusted.First(l => l.Host == host);
                    int count = untrusted.Count(l => l.Host == host);

                    evidence.Add(new ScanEvidence(
                        Kind: "link-external",
                        Label: host,
                        Detail: $"{count} link(s); first at byte {first.Offset}: \"{Truncate(first.Url, 80)}\". " +
                                "Host is not on the trusted allow-list and is not a specification namespace.",
                        Offset: first.Offset,
                        Severity: "medium"));
                }

                var named = string.Join(", ", hosts.Take(MaxReportedItems));
                if (hosts.Count > MaxReportedItems)
                    named += $", +{hosts.Count - MaxReportedItems} more";

                return ScanResult.Reject(Name,
                    $"{ReasonExternal}: Embeds {untrusted.Count} link(s) to {hosts.Count} untrusted host(s): {named}.",
                    evidence);
            }

            return ScanResult.Accept(Name, evidence);
        }
        catch (Exception ex)
        {
            // Fail securely: if we cannot analyse the file, we do not let it through.
            // Recorded as an error so an analysis failure stays distinguishable from
            // a detection when the corpus results are grouped.
            return ScanResult.Reject(Name,
                $"{ReasonError}: Embedded-link scan failed: {ex.Message}",
                new[]
                {
                    new ScanEvidence(
                        Kind: "scanner-error",
                        Label: ex.GetType().Name,
                        Detail: ex.Message,
                        Severity: "unknown")
                });
        }
    }

    // ------------------------------------------------------------------
    // Scope, policy and link inventory
    // ------------------------------------------------------------------

    private enum LinkableKind { None, Pdf, Svg }

    /// <summary>True only for file types that can embed links (SVG, PDF).</summary>
    private static LinkableKind ClassifyLinkableType(byte[] data)
    {
        int pdfLimit = Math.Min(data.Length, 1024);
        if (pdfLimit > 0 && Encoding.ASCII.GetString(data, 0, pdfLimit).Contains("%PDF"))
            return LinkableKind.Pdf;

        int svgLimit = Math.Min(data.Length, 2048);
        if (svgLimit > 0 && Encoding.ASCII.GetString(data, 0, svgLimit)
                .IndexOf("<svg", StringComparison.OrdinalIgnoreCase) >= 0)
            return LinkableKind.Svg;

        return LinkableKind.None;
    }

    /// <summary>
    /// States what was inspected and, more importantly, what was NOT — so a clean
    /// result carries its own caveat instead of reading as full coverage.
    /// </summary>
    private static ScanEvidence DescribeScope(LinkableKind kind, string content)
    {
        if (kind == LinkableKind.Pdf)
        {
            int flate = CountOccurrences(content, "/FlateDecode");

            return new ScanEvidence(
                Kind: "link-scope",
                Label: "pdf raw-bytes only",
                Detail: flate > 0
                    ? $"PDF inspected as raw bytes. {flate} FlateDecode filter reference(s) present, so any " +
                      "URL inside those compressed streams was NOT examined by this layer. Layer 5b " +
                      "decompresses the same streams but runs signature matching over them rather than " +
                      "link extraction — a known coverage gap, stated because a clean verdict here does " +
                      "not mean the document is link-free."
                    : "PDF inspected as raw bytes. No FlateDecode filter reference found, so no compressed " +
                      "stream is hiding link content from this layer.",
                Severity: flate > 0 ? "low" : "info");
        }

        bool entities = content.Contains("&#", StringComparison.Ordinal);

        return new ScanEvidence(
            Kind: "link-scope",
            Label: "svg literal text",
            Detail: entities
                ? "SVG inspected as literal text. Character-entity sequences (\"&#\") are present; a browser " +
                  "decodes those before resolving a URI, while literal matching does not, so an " +
                  "entity-encoded scheme could evade this layer. Layer 7 sanitisation is the control that " +
                  "does not depend on recognising the encoding."
                : "SVG inspected as literal text; no character-entity sequences present.",
            Severity: entities ? "low" : "info");
    }

    /// <summary>
    /// Publishes the policy in force, including the namespace exemption, so a
    /// reader of one result can tell which rule produced it without consulting
    /// the configuration.
    /// </summary>
    private ScanEvidence DescribePolicy() =>
        new(Kind: "link-policy",
            Label: "external-links",
            Detail: !_blockExternalLinks
                ? "External link blocking is DISABLED; only dangerous schemes and executable data: URIs " +
                  "are fatal."
                : (_allowedDomains.Count == 0
                    ? "External link blocking is ENABLED with an EMPTY allow-list, so every real http(s) " +
                      "link is treated as untrusted. "
                    : $"External link blocking is ENABLED. Allowed domains and their subdomains: " +
                      $"{string.Join(", ", _allowedDomains.OrderBy(d => d, StringComparer.Ordinal))}. ") +
                  $"{SpecificationNamespaceHosts.Count} specification-namespace host(s) are exempt: these " +
                  "are XML namespace identifiers written by the format itself, not links, and they " +
                  "accounted for every benign rejection measured before the exemption was added.",
            Severity: "info");

    private sealed record EmbeddedUrl(string Url, string Host, int Offset);

    private static List<EmbeddedUrl> CollectLinks(string content)
    {
        var links = new List<EmbeddedUrl>();

        foreach (Match m in UrlRegex.Matches(content))
        {
            var host = ExtractHost(m.Value);
            if (host.Length == 0) continue;

            links.Add(new EmbeddedUrl(m.Value, host, m.Index));
        }

        return links;
    }

    private ScanEvidence DescribeLinks(List<EmbeddedUrl> links)
    {
        if (links.Count == 0)
        {
            return new ScanEvidence(
                Kind: "link-inventory",
                Label: "http(s) links",
                Detail: "No http(s) URL found in the inspected bytes.",
                Severity: "info");
        }

        var hosts = links.Select(l => l.Host).Distinct(StringComparer.Ordinal).ToList();

        int namespaces = links.Count(l => SpecificationNamespaceHosts.Contains(l.Host));
        int allowListed = links.Count(l => !SpecificationNamespaceHosts.Contains(l.Host) && IsAllowed(l.Host));
        int untrusted = links.Count - namespaces - allowListed;

        // The three counts are separated because they mean different things: a
        // namespace count of six and an untrusted count of zero describes an
        // ordinary document, while the total alone would suggest six links.
        return new ScanEvidence(
            Kind: "link-inventory",
            Label: "http(s) links",
            Detail: $"{links.Count} URL-shaped string(s) across {hosts.Count} distinct host(s): " +
                    $"{namespaces} specification namespace(s), {allowListed} allow-listed, " +
                    $"{untrusted} untrusted.",
            Offset: links[0].Offset,
            Severity: "info");
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private static string ExtractHost(string url)
    {
        var m = HostRegex.Match(url);
        return m.Success ? m.Groups[1].Value.ToLowerInvariant() : string.Empty;
    }

    private bool IsAllowed(string host)
    {
        // A specification namespace is not a link, so it is not subject to the
        // link policy at all — checked before the allow-list rather than added to
        // it, so the two stay distinguishable in the evidence.
        if (SpecificationNamespaceHosts.Contains(host))
            return true;

        if (_allowedDomains.Count == 0) return false;

        foreach (var allowed in _allowedDomains)
            if (host == allowed || host.EndsWith("." + allowed, StringComparison.Ordinal))
                return true;   // allow the domain and its subdomains

        return false;
    }

    private static int CountOccurrences(string haystack, string needle)
    {
        int count = 0, i = 0;
        while ((i = haystack.IndexOf(needle, i, StringComparison.OrdinalIgnoreCase)) >= 0)
        {
            count++;
            i += needle.Length;
        }
        return count;
    }

    /// <summary>
    /// A short window of surrounding text, so the reader can see the match in
    /// context and judge it. Control characters are collapsed because a PDF is
    /// mostly binary and raw bytes would destroy the layout of the report.
    /// </summary>
    private static string Excerpt(string content, int index, int length, int padding = 12)
    {
        int start = Math.Max(0, index - padding);
        int end = Math.Min(content.Length, index + length + padding);

        var sb = new StringBuilder();
        for (int i = start; i < end; i++)
        {
            char c = content[i];
            sb.Append(char.IsControl(c) || c > 126 ? '.' : c);
        }

        return sb.ToString();
    }

    private static string Truncate(string value, int maxLength) =>
        value.Length <= maxLength ? value : value[..maxLength] + "...";
}