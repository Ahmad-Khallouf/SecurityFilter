using SecureUploader.Models;
using System.Globalization;
using System.IO.Compression;
using System.Text;

namespace SecureUploader.Scanning;

/// <summary>
/// Layer 5b: PDF FlateDecode Stream Scanning.
/// Addresses a documented limitation of raw YARA scanning (Layer 5): malicious
/// content hidden inside compressed PDF streams (/Filter /FlateDecode) is
/// invisible to a scan of the raw bytes. This layer locates every stream in a
/// PDF, decompresses whatever it can, and scans the DECOMPRESSED content.
///
/// Design: intentionally NOT a spec-compliant PDF parser. A security scanner
/// only needs to SURFACE hidden content, not render the document. We attempt to
/// inflate every stream blob (best-effort, multiple strategies); anything that
/// inflates is scanned. This minimizes external attack surface (no heavyweight
/// PDF library parsing untrusted input) and errs toward decompressing MORE.
///
/// SELF-BYPASS HARDENING — two weaknesses of the original implementation, both
/// identified during our own red-teaming of this filter, are closed here:
///
///   (1) NESTED-FILTER EVASION. A single inflation pass is defeated by
///       /Filter [/FlateDecode /FlateDecode]: after one pass the output is
///       still compressed, so YARA sees only high-entropy noise. Inflation is
///       now applied REPEATEDLY to its own output, up to MaxDecodeDepth.
///
///   (2) DECOMPRESSION-BOMB EXPOSURE. The original inflated untrusted streams
///       with Stream.CopyTo(), i.e. with no ceiling at all, so a small crafted
///       PDF could exhaust server memory. Inflation now runs through a BOUNDED
///       read loop with per-stream and whole-document caps.
///
/// The two fixes are deliberately shipped together: fixing (1) alone would
/// AMPLIFY (2), because every additional nesting level multiplies the
/// achievable expansion.
///
/// LIMITS POLICY (a size cap and an attack indicator are not the same thing):
///   - Byte caps (MaxBytesPerStream / MaxTotalBytes) TRUNCATE and keep
///     scanning — a large legitimate stream is plausible, so rejecting on size
///     alone would generate false positives.
///   - Expansion ratio (MaxExpansionRatio) REJECTS — ordinary content
///     compresses in the single digits, so extreme expansion is not a size
///     accident but the signature of a crafted bomb.
///
/// PROVENANCE, AND WHY THIS LAYER TRACKS IT
/// ----------------------------------------
/// YARA reports offsets into whatever it was handed. Here it is handed a
/// CONCATENATION of decompressed streams, so a bare offset like 0x1400 refers to
/// a buffer that exists only in memory and points nowhere a reader can inspect.
/// The span of every decompressed stream is therefore recorded, and a match
/// offset is translated back into the stream it came from and that stream's
/// position in the original upload.
///
/// This is what turns "matched at nesting depth 2" into a checkable claim: the
/// payload was inside the stream beginning at a named offset, it took N inflation
/// passes to reach, it expanded by a measured factor — and it was therefore
/// invisible to the raw scan in Layer 5. That last point is the ablation
/// argument for this layer's existence, and it needs the provenance to be stated
/// rather than asserted.
///
/// The engine invocation and match analysis live in <see cref="YaraRunner"/>,
/// shared with Layer 5. Sharing it is what guarantees a difference between the
/// two layers' results comes from WHAT was scanned, never from how.
/// </summary>
public sealed class PdfFlateDecodeLayer : IScanLayer
{
    public string Name => "PdfFlateDecode";

    private readonly string _yaraExecutablePath;
    private readonly string _rulesFilePath;
    private readonly int _timeoutMs;
    private readonly PdfDecodeOptions _limits;

    private static readonly byte[] PdfMagic = Encoding.ASCII.GetBytes("%PDF");
    private static readonly byte[] StreamKeyword = Encoding.ASCII.GetBytes("stream");
    private static readonly byte[] EndStreamKeyword = Encoding.ASCII.GetBytes("endstream");

    public PdfFlateDecodeLayer(
        string yaraExecutablePath,
        string rulesFilePath,
        PdfDecodeOptions limits,
        int timeoutMs = 10_000)
    {
        _yaraExecutablePath = yaraExecutablePath;
        _rulesFilePath = rulesFilePath;
        _limits = limits;
        _timeoutMs = timeoutMs;
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

            // Not a PDF? Nothing for this layer to do — pass through.
            if (!IsPdf(raw))
                return ScanResult.Accept(Name);

            var extraction = ExtractDecompressedStreams(raw);

            // Bomb indicator: reject before spending anything further on this file.
            if (extraction.BombDetected)
                return ScanResult.Reject(Name, extraction.BombReason, extraction.BombEvidence);

            // No decompressible content found — nothing hidden to scan here.
            // The survey is still reported: "this PDF had N streams and none of them
            // decompressed" is a different, and separately interesting, statement
            // from "this file is not a PDF".
            if (extraction.Content.Length == 0)
                return ScanResult.Accept(Name, extraction.SurveyEvidence());

            var matches = ScanBytesWithYara(extraction.Content);

            if (matches.Count == 0)
                return ScanResult.Accept(Name, extraction.SurveyEvidence());

            // Offsets returned here index the concatenated decompressed buffer, not
            // the upload, so they are translated back through the recorded spans.
            var reason = new StringBuilder("YARA matched inside decompressed PDF stream(s): ")
                .Append(YaraRunner.DescribeMatches(matches, extraction.Locate))
                .Append(" | max nesting depth reached: ")
                .Append(extraction.MaxDepthReached)
                .Append(" | NOT visible to the raw scan (Layer 5)");

            if (extraction.Truncated)
                reason.Append(" | note: output truncated at the configured byte cap");

            var evidence = new List<ScanEvidence>();
            evidence.AddRange(extraction.SurveyEvidence());
            evidence.AddRange(YaraRunner.BuildEvidence(matches, "pdfflate-yara", extraction.Locate));

            return ScanResult.Reject(Name, reason.ToString(), evidence);
        }
        catch (Exception ex)
        {
            // Fail securely: if we cannot analyze the PDF, we do NOT let it through.
            // Recorded as evidence so an analysis failure stays distinguishable from
            // a detection when the corpus results are grouped.
            var failure = new[]
            {
                new ScanEvidence(
                    Kind: "scanner-error",
                    Label: ex.GetType().Name,
                    Detail: ex.Message,
                    Severity: "unknown")
            };

            return ScanResult.Reject(Name, $"PDF FlateDecode scan failed: {ex.Message}", failure);
        }
    }

    /// <summary>Header check: "%PDF" within the first 1 KB (readers tolerate leading bytes).</summary>
    private static bool IsPdf(byte[] data)
    {
        int limit = Math.Min(data.Length, 1024);
        return IndexOf(data, PdfMagic, 0, limit) >= 0;
    }

    private static string Hex(long value) =>
        "0x" + value.ToString("x", CultureInfo.InvariantCulture);

    // ------------------------------------------------------------------
    // Provenance model
    // ------------------------------------------------------------------

    /// <summary>
    /// Where one decompressed stream came from and where it landed.
    ///
    /// Without this record a YARA offset into the concatenated buffer is
    /// unusable: it names a position in a temporary artefact rather than in the
    /// file under examination.
    /// </summary>
    private sealed record StreamSpan(
        int Index,
        long SourceOffset,
        int CompressedLength,
        long OutputStart,
        long OutputLength,
        int Depth,
        bool Truncated)
    {
        public bool Contains(long outputOffset) =>
            outputOffset >= OutputStart && outputOffset < OutputStart + OutputLength;

        public long ExpansionRatio =>
            CompressedLength > 0 ? OutputLength / CompressedLength : 0;

        /// <summary>Compact description used inline in the rejection reason.</summary>
        public string Describe(long outputOffset)
        {
            var within = outputOffset - OutputStart;
            return $"stream#{Index} src {Hex(SourceOffset)} +{Hex(within)} depth {Depth}";
        }
    }

    /// <summary>Outcome of walking one PDF and inflating all of its streams.</summary>
    private sealed class ExtractionOutcome
    {
        public byte[] Content { get; set; } = Array.Empty<byte>();
        public bool BombDetected { get; set; }
        public string BombReason { get; set; } = "";
        public List<ScanEvidence> BombEvidence { get; } = new();
        public int MaxDepthReached { get; set; }
        public bool Truncated { get; set; }
        public int StreamsFound { get; set; }
        public List<StreamSpan> Spans { get; } = new();

        /// <summary>
        /// Translates an offset in the concatenated buffer back to the stream it
        /// belongs to, and that stream's position in the original upload.
        /// </summary>
        public string Locate(long outputOffset)
        {
            foreach (var span in Spans)
                if (span.Contains(outputOffset))
                    return span.Describe(outputOffset);

            // Separator bytes between streams, or an offset past the last span.
            return $"decompressed+{Hex(outputOffset)} (unmapped)";
        }

        /// <summary>
        /// What this layer measured, independent of whether anything matched.
        ///
        /// Reported on accept as well as reject: the depth and expansion figures
        /// are the per-file data behind the layer's cost and behind the claim that
        /// nesting evasion is handled, and a layer that only speaks when it
        /// rejects leaves no way to show either.
        /// </summary>
        public List<ScanEvidence> SurveyEvidence()
        {
            var evidence = new List<ScanEvidence>
            {
                new(Kind: "pdfflate-survey",
                    Label: "streams",
                    Detail: $"{StreamsFound} stream(s) found, {Spans.Count} decompressed, " +
                            $"{Content.Length} bytes of decompressed content" +
                            (Truncated ? " (truncated at the configured cap)" : ""),
                    Severity: "info"),

                new(Kind: "pdfflate-survey",
                    Label: "max-nesting-depth",
                    Detail: MaxDepthReached == 0
                        ? "no stream required inflation"
                        : $"deepest stream needed {MaxDepthReached} inflation pass(es)" +
                          (MaxDepthReached > 1
                              ? " — nested filters present, which a single-pass scanner would miss"
                              : ""),
                    Severity: MaxDepthReached > 1 ? "low" : "info")
            };

            // Per-stream detail for the streams that actually carried content.
            foreach (var span in Spans)
            {
                evidence.Add(new ScanEvidence(
                    Kind: "pdfflate-stream",
                    Label: $"stream#{span.Index}",
                    Detail: $"{span.CompressedLength} B compressed at {Hex(span.SourceOffset)} " +
                            $"-> {span.OutputLength} B after {span.Depth} pass(es), " +
                            $"expansion {span.ExpansionRatio}x" +
                            (span.Truncated ? ", truncated" : ""),
                    Offset: span.SourceOffset,
                    Severity: "info"));
            }

            return evidence;
        }
    }

    /// <summary>Outcome of inflating ONE stream, through all of its nesting levels.</summary>
    private sealed class InflateOutcome
    {
        public byte[] Data { get; set; } = Array.Empty<byte>();
        public int Depth { get; set; }
        public bool Truncated { get; set; }
        public bool BombDetected { get; set; }
        public string BombReason { get; set; } = "";
        public long BombRatio { get; set; }
    }

    // ------------------------------------------------------------------
    // Extraction
    // ------------------------------------------------------------------

    /// <summary>
    /// Walks the raw bytes, extracts every stream body, and returns the
    /// concatenation of all successfully-decompressed stream contents, bounded
    /// by the configured whole-document budget.
    /// Best-effort by design: undecompressable blobs are skipped (other layers
    /// already scan the raw file).
    /// </summary>
    private ExtractionOutcome ExtractDecompressedStreams(byte[] pdf)
    {
        var outcome = new ExtractionOutcome();

        using var output = new MemoryStream();
        int searchFrom = 0;
        int streamIndex = 0;

        while (true)
        {
            int streamIdx = IndexOf(pdf, StreamKeyword, searchFrom, pdf.Length);
            if (streamIdx < 0) break;

            // Skip matches that are actually the tail of "endstream".
            bool isEndStream = streamIdx >= 3
                && pdf[streamIdx - 1] == (byte)'d'
                && pdf[streamIdx - 2] == (byte)'n'
                && pdf[streamIdx - 3] == (byte)'e';
            if (isEndStream)
            {
                searchFrom = streamIdx + StreamKeyword.Length;
                continue;
            }

            // Stream data starts right after the keyword, past the required EOL.
            int dataStart = streamIdx + StreamKeyword.Length;
            if (dataStart < pdf.Length && pdf[dataStart] == (byte)'\r') dataStart++;
            if (dataStart < pdf.Length && pdf[dataStart] == (byte)'\n') dataStart++;

            int endIdx = IndexOf(pdf, EndStreamKeyword, dataStart, pdf.Length);
            if (endIdx < 0) break; // malformed — stop.

            int dataEnd = endIdx;
            // Trim the single trailing EOL that usually precedes "endstream".
            if (dataEnd > dataStart && pdf[dataEnd - 1] == (byte)'\n') dataEnd--;
            if (dataEnd > dataStart && pdf[dataEnd - 1] == (byte)'\r') dataEnd--;

            int length = dataEnd - dataStart;
            if (length > 0)
            {
                streamIndex++;
                outcome.StreamsFound = streamIndex;

                var streamBytes = new byte[length];
                Array.Copy(pdf, dataStart, streamBytes, 0, length);

                var inflated = InflateRecursively(streamBytes);

                // A bomb indicator condemns the whole document immediately.
                if (inflated.BombDetected)
                {
                    outcome.BombDetected = true;
                    outcome.BombReason = inflated.BombReason;
                    outcome.Content = Array.Empty<byte>();

                    outcome.BombEvidence.Add(new ScanEvidence(
                        Kind: "pdfflate-bomb",
                        Label: $"stream#{streamIndex}",
                        Detail: $"{length} B compressed at {Hex(dataStart)} expanded {inflated.BombRatio}x " +
                                $"(limit {_limits.MaxExpansionRatio}x) at nesting depth {inflated.Depth}. " +
                                "Ordinary content compresses in the single digits, so this ratio is a " +
                                "crafted-expansion indicator rather than a size accident.",
                        Offset: dataStart,
                        Severity: "high",
                        Reference: "CWE-409 (improper handling of highly compressed data)"));

                    return outcome;
                }

                if (inflated.Truncated)
                    outcome.Truncated = true;

                if (inflated.Depth > outcome.MaxDepthReached)
                    outcome.MaxDepthReached = inflated.Depth;

                if (inflated.Data.Length > 0)
                {
                    long remaining = _limits.MaxTotalBytes - output.Length;
                    if (remaining <= 0)
                    {
                        // Whole-document budget exhausted: stop, scan what we have.
                        outcome.Truncated = true;
                        break;
                    }

                    int writeCount = (int)Math.Min(inflated.Data.Length, remaining);
                    if (writeCount < inflated.Data.Length)
                        outcome.Truncated = true;

                    // Span recorded BEFORE writing, so OutputStart is the position
                    // this stream's bytes will occupy in the concatenated buffer.
                    outcome.Spans.Add(new StreamSpan(
                        Index: streamIndex,
                        SourceOffset: dataStart,
                        CompressedLength: length,
                        OutputStart: output.Length,
                        OutputLength: writeCount,
                        Depth: inflated.Depth,
                        Truncated: inflated.Truncated || writeCount < inflated.Data.Length));

                    output.Write(inflated.Data, 0, writeCount);
                    output.WriteByte((byte)'\n'); // separator: patterns can't span two streams
                }
            }

            searchFrom = endIdx + EndStreamKeyword.Length;
        }

        outcome.Content = output.ToArray();
        return outcome;
    }

    /// <summary>
    /// Inflates a stream, then inflates the RESULT again, and so on up to
    /// MaxDecodeDepth. This defeats nested filters such as
    /// /Filter [/FlateDecode /FlateDecode]. The loop stops naturally as soon as
    /// a pass fails, which is the normal case for singly-compressed content:
    /// plain text does not inflate, so the last successful output is kept.
    /// </summary>
    private InflateOutcome InflateRecursively(byte[] compressed)
    {
        var outcome = new InflateOutcome();

        int originalLength = compressed.Length;
        byte[] current = compressed;
        int depth = 0;

        while (depth < _limits.MaxDecodeDepth)
        {
            // Depth 0 uses ALL strategies (maximise what we surface). Deeper passes
            // use the strict zlib strategy ONLY: raw-DEFLATE guessing is permissive
            // enough that it can "succeed" on ordinary text and replace good content
            // with garbage. zlib carries a header and an Adler-32 checksum, so a
            // genuine nested layer is recognised and plain content simply fails.
            bool strictOnly = depth > 0;

            if (!TryInflateOnce(current, strictOnly, out byte[] inflated, out bool truncated))
                break; // no further layer of compression — done

            depth++;
            current = inflated;

            if (truncated)
                outcome.Truncated = true;

            // CUMULATIVE expansion, measured against the ORIGINAL compressed
            // stream: this is the real bomb metric, because each nesting level
            // multiplies the achievable gain.
            if (originalLength > 0)
            {
                long ratio = current.LongLength / originalLength;
                if (ratio > _limits.MaxExpansionRatio)
                {
                    outcome.BombDetected = true;
                    outcome.BombRatio = ratio;
                    outcome.Depth = depth;
                    outcome.BombReason =
                        $"PDF stream expanded {ratio}x (limit {_limits.MaxExpansionRatio}x) " +
                        $"at nesting depth {depth} — decompression-bomb indicator.";
                    return outcome;
                }
            }

            // Cap already reached: deeper passes would operate on partial data.
            if (truncated)
                break;
        }

        outcome.Data = depth > 0 ? current : Array.Empty<byte>();
        outcome.Depth = depth;
        return outcome;
    }

    /// <summary>
    /// Attempts ONE decompression pass. At depth 0 several strategies are tried
    /// to maximize surfaced content (naive single-strategy scanners are easy to
    /// evade); at deeper nesting levels only the checksummed zlib strategy is
    /// used, so that already-decoded content cannot be mis-decoded into garbage.
    /// </summary>
    private bool TryInflateOnce(byte[] data, bool strictOnly, out byte[] result, out bool truncated)
    {
        // 1. zlib — standard PDF FlateDecode (2-byte header + Adler-32 checksum).
        if (TryDecompress(data, useZlib: true, skip: 0, out result, out truncated)) return true;

        // Nested passes stop here: the permissive strategies below are for
        // recovering malformed real-world PDFs, not for probing decoded output.
        if (!strictOnly)
        {
            // 2. raw DEFLATE with the 2-byte zlib header skipped.
            if (data.Length > 2 &&
                TryDecompress(data, useZlib: false, skip: 2, out result, out truncated)) return true;

            // 3. raw DEFLATE with no header (non-conformant producers).
            if (TryDecompress(data, useZlib: false, skip: 0, out result, out truncated)) return true;
        }

        result = Array.Empty<byte>();
        truncated = false;
        return false;
    }

    private bool TryDecompress(byte[] data, bool useZlib, int skip, out byte[] result, out bool truncated)
    {
        result = Array.Empty<byte>();
        truncated = false;

        try
        {
            using var input = new MemoryStream(data, skip, data.Length - skip);
            using Stream decompressor = useZlib
                ? new ZLibStream(input, CompressionMode.Decompress)
                : new DeflateStream(input, CompressionMode.Decompress);

            using var outMs = new MemoryStream();

            // BOUNDED read loop. The previous implementation called CopyTo(),
            // which inflates with no ceiling — that was the bomb exposure.
            var buffer = new byte[81920];
            long total = 0;
            int read;

            while ((read = decompressor.Read(buffer, 0, buffer.Length)) > 0)
            {
                long allowed = _limits.MaxBytesPerStream - total;

                if (read >= allowed)
                {
                    if (allowed > 0)
                        outMs.Write(buffer, 0, (int)allowed);

                    truncated = true;
                    break;
                }

                outMs.Write(buffer, 0, read);
                total += read;
            }

            if (outMs.Length == 0) return false;

            result = outMs.ToArray();
            return true;
        }
        catch
        {
            // Not a valid stream under this strategy — skip.
            result = Array.Empty<byte>();
            truncated = false;
            return false;
        }
    }

    /// <summary>
    /// Writes the decompressed content out and scans it.
    ///
    /// This is the layer that exposed the Defender interaction: it writes the
    /// DECOMPRESSED stream, so a payload is briefly in the clear on disk and must
    /// remain openable by YARA — hence the project-local, Defender-excluded
    /// scan-temp folder rather than the shared system TEMP.
    /// </summary>
    private List<YaraRuleMatch> ScanBytesWithYara(byte[] content)
    {
        var tempPath = ScanTempDirectory.NewFile("secureuploader_pdfflate");
        try
        {
            File.WriteAllBytes(tempPath, content);
            return YaraRunner.Scan(_yaraExecutablePath, _rulesFilePath, tempPath, _timeoutMs);
        }
        finally
        {
            try { if (File.Exists(tempPath)) File.Delete(tempPath); } catch { /* best effort */ }
        }
    }

    /// <summary>Byte-array search for <paramref name="needle"/> starting at <paramref name="start"/>, up to <paramref name="limit"/>.</summary>
    private static int IndexOf(byte[] haystack, byte[] needle, int start, int limit)
    {
        int max = Math.Min(limit, haystack.Length) - needle.Length;
        for (int i = start; i <= max; i++)
        {
            bool found = true;
            for (int j = 0; j < needle.Length; j++)
                if (haystack[i + j] != needle[j]) { found = false; break; }
            if (found) return i;
        }
        return -1;
    }
}