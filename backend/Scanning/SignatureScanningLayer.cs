namespace SecureUploader.Scanning;

/// <summary>
/// Layer 5: Signature Scanning (YARA).
/// Scans the FULL RAW file content for known malicious patterns using the
/// official YARA engine, invoked as an external process.
/// Reference: OWASP File Upload Cheat Sheet — scan uploaded files for
/// malicious content; YARA is the industry-standard pattern-matching engine.
///
/// NOTE: YARA scans raw bytes. Content hidden inside compressed streams
/// (e.g. FlateDecode PDF streams) is NOT visible to it — see Layer 5b
/// (PDF stream decompression) which addresses this documented limitation.
///
/// The engine invocation and output analysis live in <see cref="YaraRunner"/>,
/// shared with Layer 5b. That sharing is deliberate: a difference between what
/// this layer finds and what 5b finds must be attributable to WHAT was scanned —
/// raw bytes versus decompressed streams — and never to a divergence in how the
/// scanner was called. It is what makes the ablation between the two layers a
/// measurement rather than a comparison of two slightly different tools.
///
/// This layer does NOT claim a matched payload is malicious; that would require
/// execution or semantic analysis. It reports which rule fired, what text
/// matched, at which offsets, how close the matched groups sit, and the rule's
/// own severity — so the verdict can be checked instead of trusted.
/// </summary>
public sealed class SignatureScanningLayer : IScanLayer
{
    public string Name => "SignatureScanning";

    private readonly string _yaraExecutablePath;
    private readonly string _rulesFilePath;
    private readonly int _timeoutMs;

    public SignatureScanningLayer(string yaraExecutablePath, string rulesFilePath, int timeoutMs = 10_000)
    {
        _yaraExecutablePath = yaraExecutablePath;
        _rulesFilePath = rulesFilePath;
        _timeoutMs = timeoutMs;
    }

    public ScanResult Scan(FileScanContext context)
    {
        // YARA operates on files on disk, but our file lives in a stream.
        // Write it to a temporary file, scan it, then always delete it.
        // Project-local scan-temp folder (Defender-excluded), NOT the shared system
        // TEMP: a decompressed payload written here must be openable by YARA.
        var tempPath = ScanTempDirectory.NewFile("secureuploader");

        try
        {
            using (var temp = File.Create(tempPath))
            {
                context.FileStream.Position = 0;
                context.FileStream.CopyTo(temp);
            }

            var matches = YaraRunner.Scan(_yaraExecutablePath, _rulesFilePath, tempPath, _timeoutMs);

            if (matches.Count == 0)
                return ScanResult.Accept(Name);

            // Offsets from this scan ARE file offsets, so no translation is needed:
            // what YARA reports is directly a position in the uploaded file.
            return ScanResult.Reject(
                Name,
                "YARA matched: " + YaraRunner.DescribeMatches(matches),
                YaraRunner.BuildEvidence(matches, kindPrefix: "yara"));
        }
        catch (Exception ex)
        {
            // Fail securely: if the scanner itself fails, we do NOT let the file through.
            // Recorded as evidence so a scanner error stays distinguishable from a
            // detection when corpus results are grouped — a masked engine error would
            // otherwise be counted as a true positive and inflate the detection rate.
            var failure = new[]
            {
                new ScanEvidence(
                    Kind: "scanner-error",
                    Label: ex.GetType().Name,
                    Detail: ex.Message,
                    Severity: "unknown")
            };

            return ScanResult.Reject(Name, $"YARA scan failed: {ex.Message}", failure);
        }
        finally
        {
            // Always clean up the temp file — never leave malicious content on disk.
            try { if (File.Exists(tempPath)) File.Delete(tempPath); } catch { /* best effort */ }
        }
    }
}