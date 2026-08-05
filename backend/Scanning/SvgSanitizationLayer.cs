using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace SecureUploader.Scanning;

/// <summary>
/// Layer 7: SVG Sanitization (SANITIZATION layer).
/// SVG is XML and can embed JavaScript (&lt;script&gt;, on* event handlers,
/// javascript: URIs) -> stored XSS. This layer parses the document and
/// rebuilds it keeping ONLY whitelisted elements and attributes.
/// Reference: OWASP File Upload Cheat Sheet + OWASP XSS Prevention Cheat Sheet.
///
/// ROOT-ELEMENT CHECK (a behaviour change, and the reason for it)
/// -------------------------------------------------------------
/// Sanitisation previously started AT the root and never checked the root itself:
/// its attributes were filtered and its children pruned, but its name was never
/// compared against the allow-list. Combined with detection in Layer 2 — which
/// classifies a file as SVG when "&lt;svg" appears anywhere in the first kilobyte,
/// including inside a comment — a document like
///
///     &lt;!-- &lt;svg&gt; --&gt;
///     &lt;html&gt;...&lt;/html&gt;
///
/// was detected as SVG, sanitised with &lt;html&gt; left in place as the root, and
/// stored to be served as an image.
///
/// A valid SVG has &lt;svg&gt; as its root by definition, so requiring it cannot
/// reject a legitimate file. This is the one place where behaviour was tightened
/// rather than only reported, because the alternative — reporting a hole while
/// leaving it open — is not a defensible position for a control whose entire
/// purpose is to make stored SVG safe to serve.
///
/// WHAT SURVIVES AND IS ONLY REPORTED
/// ----------------------------------
/// XML comments and processing instructions are preserved by the serializer.
/// Neither executes, but both carry arbitrary bytes through the pipeline intact,
/// which makes them an exfiltration channel and one half of a polyglot. They are
/// counted and reported rather than removed, so the decision to strip them can
/// follow from how often they actually appear in the corpus.
///
/// MEASURING NEUTRALISATION
/// ------------------------
/// Every SVG returns Sanitized, because rebuilding is prophylactic and runs
/// whether or not anything dangerous was present. A neutralisation rate derived
/// from that verdict is therefore 100% by construction and means nothing. What was
/// actually removed is counted by element and attribute NAME, so the metric rests
/// on removals rather than on the verdict — and so a rejection can say "one
/// &lt;script&gt; and two on* handlers were destroyed" instead of "the file was
/// sanitised".
/// </summary>
public sealed class SvgSanitizationLayer : IScanLayer
{
    public string Name => "SvgSanitization";

    /// <summary>
    /// Reason prefixes, so corpus results can be grouped by cause. BADROOT is a
    /// finding about the document; PARSE covers malformed XML, which for a
    /// deliberately hostile file and for a merely broken one looks the same and
    /// should not be counted as a detection.
    /// </summary>
    public const string ReasonBadRoot = "SVG-BADROOT";
    public const string ReasonNoRoot = "SVG-NOROOT";
    public const string ReasonParse = "SVG-PARSE";

    // Whitelist: only these SVG elements survive sanitization.
    private static readonly HashSet<string> AllowedElements =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "svg", "g", "defs", "title", "desc", "path", "rect", "circle",
            "ellipse", "line", "polyline", "polygon", "text", "tspan",
            "linearGradient", "radialGradient", "stop", "clipPath", "mask", "pattern"
        };

    // Whitelist: only these attributes survive. Note: NO event handlers,
    // NO href/xlink:href (external + javascript: URI vector).
    private static readonly HashSet<string> AllowedAttributes =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "id", "class", "width", "height", "viewBox", "x", "y", "x1", "y1", "x2", "y2",
            "cx", "cy", "r", "rx", "ry", "d", "points", "transform",
            "fill", "fill-opacity", "fill-rule", "stroke", "stroke-width", "stroke-opacity",
            "stroke-linecap", "stroke-linejoin", "stroke-dasharray",
            "opacity", "offset", "stop-color", "stop-opacity",
            "font-family", "font-size", "font-weight", "text-anchor", "gradientUnits", "xmlns"
        };

    /// <summary>
    /// Removals worth naming individually, with why they matter. Everything absent
    /// from the allow-lists is removed regardless; this table only decides how a
    /// removal is DESCRIBED, so that a stripped &lt;script&gt; is not reported with
    /// the same weight as a stripped &lt;image&gt;.
    /// </summary>
    private static readonly Dictionary<string, string> NotableElements =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["script"] = "Direct script execution — the primary stored-XSS vector in SVG.",
            ["foreignObject"] = "Embeds XHTML inside SVG. A documented bypass of several open-source " +
                                "SVG sanitisers (FortiGuard), so its removal is a specific test case.",
            ["use"] = "References other nodes, including across documents; an indirect injection path.",
            ["image"] = "Loads external or data: content into the rendered image.",
            ["animate"] = "SMIL animation can set attribute values at runtime, reaching blocked attributes.",
            ["animateTransform"] = "SMIL animation; same runtime attribute-setting path.",
            ["set"] = "SMIL element that assigns an attribute value at runtime.",
            ["handler"] = "Event handler element.",
            ["style"] = "CSS can load external resources and, historically, execute.",
            ["iframe"] = "Nested browsing context.",
            ["embed"] = "External plugin content.",
            ["object"] = "External plugin content.",
            ["a"] = "Hyperlink; carries an href and therefore a scheme.",
        };

    public ScanResult Scan(FileScanContext context)
    {
        if (context.DetectedFileType != "svg")
        {
            return ScanResult.Accept(Name, new[]
            {
                new ScanEvidence(
                    Kind: "svg-scope",
                    Label: "not-svg",
                    Detail: $"Detected type '{context.DetectedFileType ?? "(none)"}' is not SVG; " +
                            "raster images are sanitised by Layer 6.",
                    Severity: "info")
            });
        }

        try
        {
            context.FileStream.Position = 0;

            // Secure XML parsing: DTD disabled (billion-laughs / XXE protection),
            // no external entity resolution.
            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null
            };

            long originalSize = context.FileStream.Length;

            using var reader = XmlReader.Create(context.FileStream, settings);
            var doc = XDocument.Load(reader);

            if (doc.Root is null)
            {
                return ScanResult.Reject(Name,
                    $"{ReasonNoRoot}: SVG document has no root element.",
                    new[]
                    {
                        new ScanEvidence(
                            Kind: "svg-structure",
                            Label: "root",
                            Detail: "The document parsed as XML but contains no element. Nothing to sanitise " +
                                    "and nothing an image renderer could use.",
                            Severity: "low")
                    });
            }

            var rootName = doc.Root.Name.LocalName;

            // See the class remarks: the root was previously never validated, so a
            // document of any type could be stored and served as an image.
            if (!string.Equals(rootName, "svg", StringComparison.OrdinalIgnoreCase))
            {
                return ScanResult.Reject(Name,
                    $"{ReasonBadRoot}: Root element is <{rootName}>, not <svg>. " +
                    "A valid SVG has <svg> as its root, so this document is not one.",
                    new[]
                    {
                        new ScanEvidence(
                            Kind: "svg-badroot",
                            Label: $"<{rootName}>",
                            Detail: "Detection in Layer 2 matches the \"<svg\" marker anywhere in the leading " +
                                    "bytes, including inside a comment, so a non-SVG document can reach this " +
                                    "layer classified as SVG. Requiring the root element closes that path: " +
                                    "pruning children while leaving a foreign root in place would have " +
                                    "stored the document to be served as an image.",
                            Severity: "high",
                            Reference: "OWASP File Upload Cheat Sheet — validate structure, not just type")
                    });
            }

            var report = new SanitizationReport();
            CountNonElementNodes(doc, report);
            SanitizeElement(doc.Root, report);

            var cleaned = new MemoryStream();
            var bytes = Encoding.UTF8.GetBytes(doc.ToString(SaveOptions.DisableFormatting));
            cleaned.Write(bytes, 0, bytes.Length);
            cleaned.Position = 0;

            return ScanResult.Sanitize(Name, cleaned, report.BuildEvidence(originalSize, cleaned.Length));
        }
        catch (Exception ex)
        {
            // Fail securely: malformed or unparsable XML is rejected.
            // Recorded as a parse failure, not a detection: a hostile document and a
            // merely broken one fail here identically, and counting the two together
            // would inflate whichever figure they are added to.
            return ScanResult.Reject(Name,
                $"{ReasonParse}: SVG could not be sanitized: {ex.Message}",
                new[]
                {
                    new ScanEvidence(
                        Kind: "svg-parse-error",
                        Label: ex.GetType().Name,
                        Detail: $"{ex.Message} Note that a prohibited DTD raises here too, so an XXE or " +
                                "entity-expansion attempt appears as a parse failure — blocked, but not " +
                                "separately identified.",
                        Severity: "unknown")
                });
        }
    }

    // ------------------------------------------------------------------
    // Removal accounting
    // ------------------------------------------------------------------

    /// <summary>
    /// Tally of what sanitisation actually took out. Kept by NAME rather than as a
    /// bare count, because "one element removed" and "one &lt;script&gt; removed"
    /// are not the same claim.
    /// </summary>
    private sealed class SanitizationReport
    {
        public Dictionary<string, int> RemovedElements { get; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, int> RemovedAttributes { get; } = new(StringComparer.OrdinalIgnoreCase);
        public int Comments { get; set; }
        public int ProcessingInstructions { get; set; }
        public int ElementsKept { get; set; }

        public void RemoveElement(string name) => Bump(RemovedElements, name);
        public void RemoveAttribute(string name) => Bump(RemovedAttributes, name);

        private static void Bump(Dictionary<string, int> map, string key) =>
            map[key] = map.TryGetValue(key, out var n) ? n + 1 : 1;

        public int TotalElementsRemoved => RemovedElements.Values.Sum();
        public int TotalAttributesRemoved => RemovedAttributes.Values.Sum();
        public bool AnythingRemoved => TotalElementsRemoved > 0 || TotalAttributesRemoved > 0;

        public List<ScanEvidence> BuildEvidence(long originalSize, long cleanedSize)
        {
            var evidence = new List<ScanEvidence>();

            // Elements.
            if (TotalElementsRemoved == 0)
            {
                evidence.Add(new ScanEvidence(
                    Kind: "svg-elements",
                    Label: "removed",
                    Detail: $"None. All {ElementsKept} element(s) are on the allow-list.",
                    Severity: "info"));
            }
            else
            {
                var listed = RemovedElements
                    .OrderByDescending(kv => kv.Value)
                    .Select(kv => kv.Value > 1 ? $"<{kv.Key}> x{kv.Value}" : $"<{kv.Key}>");

                evidence.Add(new ScanEvidence(
                    Kind: "svg-elements",
                    Label: "removed",
                    Detail: $"{TotalElementsRemoved} element(s) destroyed: {string.Join(", ", listed)}. " +
                            $"{ElementsKept} allow-listed element(s) kept.",
                    Severity: "medium"));

                // Named separately so a stripped <script> is not buried in a list.
                foreach (var (name, note) in RemovedElements
                             .Where(kv => NotableElements.ContainsKey(kv.Key))
                             .Select(kv => (kv.Key, NotableElements[kv.Key])))
                {
                    evidence.Add(new ScanEvidence(
                        Kind: "svg-notable",
                        Label: $"<{name}>",
                        Detail: $"Removed x{RemovedElements[name]}. {note}",
                        Severity: "high",
                        Reference: "OWASP XSS Prevention Cheat Sheet"));
                }
            }

            // Attributes.
            var handlers = RemovedAttributes
                .Where(kv => kv.Key.StartsWith("on", StringComparison.OrdinalIgnoreCase))
                .ToList();

            if (TotalAttributesRemoved == 0)
            {
                evidence.Add(new ScanEvidence(
                    Kind: "svg-attributes",
                    Label: "removed",
                    Detail: "None. Every attribute present is on the allow-list.",
                    Severity: "info"));
            }
            else
            {
                var listed = RemovedAttributes
                    .OrderByDescending(kv => kv.Value)
                    .Take(12)
                    .Select(kv => kv.Value > 1 ? $"{kv.Key} x{kv.Value}" : kv.Key);

                evidence.Add(new ScanEvidence(
                    Kind: "svg-attributes",
                    Label: "removed",
                    Detail: $"{TotalAttributesRemoved} attribute(s) destroyed: {string.Join(", ", listed)}" +
                            (RemovedAttributes.Count > 12 ? ", ..." : "") + ".",
                    Severity: handlers.Count > 0 ? "high" : "medium"));
            }

            if (handlers.Count > 0)
            {
                evidence.Add(new ScanEvidence(
                    Kind: "svg-notable",
                    Label: "event handlers",
                    Detail: $"{handlers.Sum(kv => kv.Value)} on* handler(s) destroyed: " +
                            $"{string.Join(", ", handlers.Select(kv => kv.Key))}. An on* attribute runs script " +
                            "when the image is rendered, with no user interaction required.",
                    Severity: "high",
                    Reference: "OWASP XSS Prevention Cheat Sheet"));
            }

            // Preserved-but-noted nodes.
            if (Comments > 0 || ProcessingInstructions > 0)
            {
                evidence.Add(new ScanEvidence(
                    Kind: "svg-preserved",
                    Label: "comments / instructions",
                    Detail: $"{Comments} comment(s) and {ProcessingInstructions} processing instruction(s) " +
                            "PRESERVED by the serializer. Neither executes, but both carry arbitrary bytes " +
                            "through intact — an exfiltration channel and one half of a polyglot. Reported " +
                            "rather than stripped so the decision can rest on how often they occur.",
                    Severity: "low"));
            }

            // The verdict-versus-measurement distinction, made explicit.
            evidence.Add(new ScanEvidence(
                Kind: "svg-rewrite",
                Label: "before/after",
                Detail: $"{originalSize} B -> {cleanedSize} B. " +
                        (AnythingRemoved
                            ? $"NEUTRALISED: {TotalElementsRemoved} element(s) and " +
                              $"{TotalAttributesRemoved} attribute(s) destroyed."
                            : "Rebuilt with nothing removed — the size change is reserialisation, not " +
                              "neutralisation, and must not be counted as one."),
                Severity: AnythingRemoved ? "high" : "info"));

            return evidence;
        }
    }

    /// <summary>Counts comments and processing instructions anywhere in the document.</summary>
    private static void CountNonElementNodes(XDocument doc, SanitizationReport report)
    {
        foreach (var node in doc.DescendantNodes())
        {
            if (node is XComment) report.Comments++;
            else if (node is XProcessingInstruction) report.ProcessingInstructions++;
        }
    }

    /// <summary>Recursively removes non-whitelisted elements and attributes.</summary>
    private static void SanitizeElement(XElement element, SanitizationReport report)
    {
        report.ElementsKept++;

        // 1) Remove any attribute not on the whitelist.
        //    This kills every on* handler, href/xlink:href, style, etc. in one pass.
        var badAttributes = element.Attributes()
            .Where(a => !a.IsNamespaceDeclaration && !AllowedAttributes.Contains(a.Name.LocalName))
            .ToList();

        foreach (var attr in badAttributes)
        {
            // Prefixed name where there is one: xlink:href and a bare href are the
            // same local name but not the same finding.
            var reported = string.IsNullOrEmpty(attr.Name.NamespaceName)
                ? attr.Name.LocalName
                : $"{{{attr.Name.NamespaceName}}}{attr.Name.LocalName}";

            report.RemoveAttribute(reported);
            attr.Remove();
        }

        // 2) Recurse into children; remove any element not on the whitelist
        //    (<script>, <foreignObject>, <use>, <animate>, <image>, ...).
        var children = element.Elements().ToList();

        foreach (var child in children)
        {
            if (!AllowedElements.Contains(child.Name.LocalName))
            {
                report.RemoveElement(child.Name.LocalName);
                child.Remove();
            }
            else
            {
                SanitizeElement(child, report);
            }
        }
    }
}