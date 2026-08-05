using SecureUploader.Scanning;

namespace SecureUploader.Models;

/// <summary>
/// A per-layer record of what the pipeline did to one uploaded file.
/// One instance is produced for EVERY layer that runs, whatever the outcome —
/// so the trace is a complete audit of the path the file took, not just a
/// record of the layer that stopped it.
///
/// Two independent uses:
///   1. DEMONSTRATION — rendered in the UI when demo mode is enabled, so the
///      layered design is observable instead of merely asserted.
///   2. MEASUREMENT — <see cref="ElapsedMs"/> gives per-layer cost, which is
///      the raw data for the Phase 2 performance table and for showing what
///      the verdict cache actually saves.
///
/// NOTE: <see cref="Reason"/> is the internal rejection reason. It is ALWAYS
/// logged server-side; it is only ever sent to a client when demo mode is
/// explicitly enabled (see DemoOptions).
/// </summary>
public sealed class LayerTrace
{
    /// <summary>Layer name, e.g. "MagicBytes" or "Cached(SignatureScanning)".</summary>
    public string Layer { get; init; } = "";

    /// <summary>"Accepted", "Rejected", or "Sanitized".</summary>
    public string Decision { get; init; } = "";

    /// <summary>Why the layer rejected the file. Null unless Decision is "Rejected".</summary>
    public string? Reason { get; init; }

    /// <summary>Wall-clock time this layer took, in milliseconds.</summary>
    public double ElapsedMs { get; init; }

    /// <summary>
    /// True when the verdict came from the scan-result cache instead of a real
    /// scan. Populated by CachedScanLayer; false for every unwrapped layer.
    /// Makes the cache's effect visible rather than inferred from timing alone.
    /// </summary>
    public bool FromCache { get; init; }

    /// <summary>
    /// The individual observations behind the layer's decision: what was seen,
    /// where, and how the layer rates it.
    ///
    /// <see cref="Reason"/> carries the same information as one prose sentence,
    /// which is fine to read and useless to aggregate. These entries are typed and
    /// grouped by <c>Kind</c>, so corpus results can be tallied by cause instead of
    /// by string-matching a message that changes whenever the wording does.
    ///
    /// Populated for accepts as well as rejects — a layer that only speaks when it
    /// refuses leaves no way to show what it measured on the files it passed.
    /// Subject to the same disclosure rule as <see cref="Reason"/>: always recorded
    /// server-side, released to a client only in demo mode, at the controller.
    /// </summary>
    public IReadOnlyList<ScanEvidence> Evidence { get; init; } = Array.Empty<ScanEvidence>();
}