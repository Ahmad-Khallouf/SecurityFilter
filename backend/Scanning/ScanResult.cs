namespace SecureUploader.Scanning;

/// <summary>
/// The decision produced by a single scan layer.
/// </summary>
public enum ScanDecision
{
    Accepted,   // File passed this layer
    Rejected,   // File failed this layer (fail-fast: pipeline stops)
    Sanitized   // File was modified/cleaned by this layer (pipeline continues with new stream)
}

/// <summary>
/// One concrete observation a layer made about the file.
///
/// PURPOSE: a rejection reason states the CONCLUSION; evidence states the
/// OBSERVATIONS the conclusion rests on. Without it a layer can only assert
/// "this file is bad"; with it the layer can show what it saw, where, and how
/// confident that makes it — which is what an evaluator (or a reviewer) needs
/// in order to check the claim instead of trusting it.
///
/// Deliberately generic so every layer uses the same shape: a byte mismatch,
/// a stream nesting depth, a stripped SVG attribute and a YARA string match
/// are all "something observed at some position with some interpretation".
/// </summary>
/// <param name="Kind">
/// Machine-readable evidence class, e.g. "yara-rule", "yara-string",
/// "byte-mismatch", "stream-depth", "stripped-element". Used for grouping in
/// the corpus results; never shown raw to an end user.
/// </param>
/// <param name="Label">What was observed — a rule name, field name, or string id.</param>
/// <param name="Detail">The observed value, in human-readable form.</param>
/// <param name="Offset">Byte offset in the file, when the observation has a position.</param>
/// <param name="Severity">
/// Interpretation strength, sourced from the detecting rule rather than invented
/// here. "high" = known-bad indicator; "medium" = dangerous capability present;
/// "low" = structural anomaly or evasion hint. A layer must NOT claim malice it
/// cannot demonstrate — see the rationale note on <see cref="ScanResult"/>.
/// </param>
/// <param name="Reference">External citation (CVE, CWE, ATT&amp;CK id, paper).</param>
public sealed record ScanEvidence(
    string Kind,
    string Label,
    string Detail,
    long? Offset = null,
    string? Severity = null,
    string? Reference = null);

/// <summary>
/// The result returned by every scan layer.
/// Reference: OWASP File Upload Cheat Sheet (validation outcomes),
/// OWASP ASVS V7 (logging rejection reasons server-side only).
///
/// ON WHAT A REJECTION MEANS
/// -------------------------
/// A static filter cannot prove that a given payload is malicious; proving that
/// requires dynamic execution or semantic analysis, both out of scope for an
/// upload gate. What this pipeline CAN establish is one of three things, and the
/// evidence carried here is what distinguishes them:
///
///   known-bad indicator   — matches a documented exploit trigger or signature
///   dangerous capability  — the file can act without user interaction
///   structural anomaly    — the file shows signs of hiding its own content
///
/// Rejections are therefore stated as policy outcomes ("this capability is not
/// permitted on this surface"), not as verdicts of malice. The distinction is
/// what keeps the reported false-positive rate meaningful.
/// </summary>
public sealed class ScanResult
{
    public ScanDecision Decision { get; }

    /// <summary>Internal reason for rejection. Logged server-side, NEVER returned to the client.</summary>
    public string? RejectionReason { get; }

    /// <summary>Name of the layer that produced this result (for logging &amp; monitoring).</summary>
    public string LayerName { get; }

    /// <summary>The cleaned file stream, only present when Decision == Sanitized.</summary>
    public Stream? SanitizedStream { get; }

    /// <summary>
    /// The observations behind <see cref="RejectionReason"/>. Empty for layers
    /// that have not been upgraded yet, and empty for a plain accept — so this
    /// is additive: an existing caller that ignores it behaves exactly as before.
    ///
    /// Subject to the same disclosure rule as RejectionReason: always recorded
    /// server-side, released to a client only in demo mode, at the controller.
    /// </summary>
    public IReadOnlyList<ScanEvidence> Evidence { get; }

    /// <summary>
    /// True when this verdict was replayed from the scan-result cache rather
    /// than produced by actually running the layer. Set only by CachedScanLayer.
    ///
    /// Deliberately NOT part of the factory methods: a layer cannot mark its own
    /// result as cached, so the flag can only ever be set by the cache itself.
    /// </summary>
    public bool FromCache { get; private set; }

    // Private constructor: forces usage of the factory methods below,
    // so an invalid combination (e.g. Rejected without a reason) cannot exist.
    private ScanResult(
        ScanDecision decision,
        string layerName,
        string? rejectionReason,
        Stream? sanitizedStream,
        IReadOnlyList<ScanEvidence>? evidence)
    {
        Decision = decision;
        LayerName = layerName;
        RejectionReason = rejectionReason;
        SanitizedStream = sanitizedStream;
        Evidence = evidence ?? Array.Empty<ScanEvidence>();
    }

    public static ScanResult Accept(string layerName, IReadOnlyList<ScanEvidence>? evidence = null)
        => new(ScanDecision.Accepted, layerName, null, null, evidence);

    public static ScanResult Reject(string layerName, string reason, IReadOnlyList<ScanEvidence>? evidence = null)
        => new(ScanDecision.Rejected, layerName, reason, null, evidence);

    public static ScanResult Sanitize(string layerName, Stream sanitizedStream, IReadOnlyList<ScanEvidence>? evidence = null)
        => new(ScanDecision.Sanitized, layerName, null, sanitizedStream, evidence);

    /// <summary>
    /// Returns a copy of this verdict marked as served from cache. A COPY, not a
    /// mutation: the cached instance is shared by every future hit on the same
    /// key, so flipping the flag in place would corrupt the stored entry.
    /// </summary>
    public ScanResult AsCacheHit()
    {
        var copy = new ScanResult(Decision, LayerName, RejectionReason, SanitizedStream, Evidence);
        copy.FromCache = true;
        return copy;
    }
}
