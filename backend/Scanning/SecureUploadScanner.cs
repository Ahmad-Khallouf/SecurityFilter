using System.Diagnostics;
using SecureUploader.Models;

namespace SecureUploader.Scanning;

/// <summary>
/// The main pipeline: runs all scan layers in order (fail-fast funnel).
/// References: OWASP File Upload Cheat Sheet (layered validation),
/// CWE-434 mitigation via defense-in-depth.
///
/// The runner is also the single point where the per-layer audit trail is
/// produced. Layers stay unaware of it, so tracing cannot be forgotten by a
/// layer, skipped by one, or reported inconsistently between them. Evidence is
/// copied here for the same reason: a layer states its observations and the runner
/// decides how they are recorded.
/// </summary>
public sealed class SecureUploadScanner
{
    private readonly IReadOnlyList<IScanLayer> _layers;
    private readonly ILogger<SecureUploadScanner> _logger;

    public SecureUploadScanner(IEnumerable<IScanLayer> layers, ILogger<SecureUploadScanner> logger)
    {
        _layers = layers.ToList();
        _logger = logger;
    }

    public ScanResult ScanFile(FileScanContext context)
    {
        foreach (var layer in _layers)
        {
            // Ensure each layer reads the stream from the beginning
            if (context.FileStream.CanSeek)
                context.FileStream.Position = 0;

            // Timed on EVERY path — including rejection. The cost of an early
            // reject is exactly what justifies the cheap-checks-first ordering,
            // so it has to be measured, not assumed.
            var stopwatch = Stopwatch.StartNew();
            var result = layer.Scan(context);
            stopwatch.Stop();

            context.Traces.Add(new LayerTrace
            {
                Layer = layer.Name,
                Decision = result.Decision.ToString(),
                Reason = result.RejectionReason,
                ElapsedMs = stopwatch.Elapsed.TotalMilliseconds,
                FromCache = result.FromCache,
                Evidence = result.Evidence
            });

            switch (result.Decision)
            {
                case ScanDecision.Rejected:
                    // Fail-fast: log server-side, stop immediately.
                    // OWASP ASVS V7: log the reason; never expose it to the client.
                    _logger.LogWarning(
                        "File '{FileName}' rejected by layer '{Layer}' after {Elapsed:F1} ms. Reason: {Reason}",
                        context.FileName, result.LayerName, stopwatch.Elapsed.TotalMilliseconds, result.RejectionReason);

                    // Evidence logged separately so the server-side record carries the
                    // observations, not only the conclusion. Without it a disputed
                    // verdict can only be re-examined by re-running the file, which is
                    // not possible once the upload has been discarded.
                    foreach (var item in result.Evidence)
                    {
                        _logger.LogInformation(
                            "  evidence [{Kind}] {Label}{Offset}: {Detail}",
                            item.Kind,
                            item.Label,
                            item.Offset is null ? "" : $" @0x{item.Offset:x}",
                            item.Detail);
                    }

                    return result;

                case ScanDecision.Sanitized:
                    // Replace the stream with the cleaned version and continue.
                    _logger.LogInformation(
                        "File '{FileName}' sanitized by layer '{Layer}'.",
                        context.FileName, result.LayerName);
                    context.FileStream = result.SanitizedStream!;
                    break;

                case ScanDecision.Accepted:
                    break; // continue to next layer
            }
        }

        _logger.LogInformation("File '{FileName}' passed all scan layers.", context.FileName);
        return ScanResult.Accept("Pipeline");
    }
}