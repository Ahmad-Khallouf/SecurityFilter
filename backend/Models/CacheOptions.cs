namespace SecureUploader.Models;

/// <summary>
/// Configuration for the scan-result cache, bound from the "Cache" section
/// of appsettings.json.
///
/// The cache stores VERDICTS ONLY (a decision plus a short reason string) for
/// the expensive content-based detection layers, keyed by SHA-256 of the
/// content. It never stores file bytes.
/// </summary>
public sealed class CacheOptions
{
    public const string SectionName = "Cache";

    /// <summary>
    /// Master switch. Set to false to run the pipeline with caching disabled —
    /// required for clean, uncached timing measurements in the Phase 2
    /// comparative evaluation and the ablation study.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Maximum number of cached verdicts. Bounds memory so that a flood of
    /// unique uploads cannot become a memory-exhaustion DoS.
    /// </summary>
    public long MaxEntries { get; set; } = 10_000;

    /// <summary>Lifetime of a cached verdict, in minutes.</summary>
    public int TtlMinutes { get; set; } = 60;
}