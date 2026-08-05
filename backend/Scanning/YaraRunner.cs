using System.Diagnostics;
using System.Globalization;
using System.Text;

namespace SecureUploader.Scanning;

/// <summary>
/// One matched string inside a rule: which pattern, where, and what bytes.
/// </summary>
public sealed record YaraStringHit(string StringId, long Offset, string MatchedText)
{
    /// <summary>
    /// Identifier with the trailing index removed: $js1 and $js2 both belong to
    /// group "js". A rule conventionally numbers patterns it treats as
    /// interchangeable and names unrelated ones differently, so the prefix
    /// recovers the rule author's intent without hard-coding rule knowledge here.
    /// </summary>
    public string Group
    {
        get
        {
            var name = StringId.TrimStart('$');
            int end = name.Length;
            while (end > 0 && char.IsDigit(name[end - 1])) end--;
            return end > 0 ? name[..end] : name;
        }
    }

    /// <summary>
    /// Shortened, single-line form of the matched bytes for the human-readable
    /// summary line. The FULL text is preserved in the evidence list; only the
    /// inline summary is abbreviated.
    ///
    /// Necessary because a matched string can be long and full of punctuation —
    /// the EICAR test string is 68 characters of it — which runs into the
    /// surrounding text and makes the line unreadable exactly where it matters
    /// most. Newlines and tabs are collapsed for the same reason: a match that
    /// spans lines would otherwise break the layout of the summary.
    /// </summary>
    public string Preview(int maxLength = 40)
    {
        var flat = MatchedText
            .Replace("\r", " ")
            .Replace("\n", " ")
            .Replace("\t", " ");

        while (flat.Contains("  ")) flat = flat.Replace("  ", " ");
        flat = flat.Trim();

        return flat.Length <= maxLength ? flat : flat[..maxLength] + "...";
    }
}

/// <summary>Closest approach between two groups of matched strings.</summary>
public sealed record YaraGroupProximity(string GroupA, string GroupB, long Distance, long AtOffset)
{
    public bool CoLocated => Distance <= YaraRunner.CoLocationWindowBytes;
}

/// <summary>One rule that fired, with its meta block and every place it matched.</summary>
public sealed class YaraRuleMatch
{
    public string RuleName { get; init; } = "";
    public Dictionary<string, string> Meta { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    public List<YaraStringHit> Hits { get; } = new();

    public string? Severity => Meta.TryGetValue("severity", out var v) ? v : null;
    public string? Category => Meta.TryGetValue("category", out var v) ? v : null;
    public string? Reference => Meta.TryGetValue("reference", out var v) ? v : null;
    public string? Description => Meta.TryGetValue("description", out var v) ? v : null;

    /// <summary>
    /// Closest approach for every pair of distinct groups, nearest first.
    /// Empty when the rule fired on a single group, where the distance between
    /// interchangeable patterns carries no information.
    /// </summary>
    public List<YaraGroupProximity> GroupProximities()
    {
        var byGroup = Hits
            .GroupBy(h => h.Group, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.Select(h => h.Offset).ToList(), StringComparer.Ordinal);

        var groups = byGroup.Keys.OrderBy(k => k, StringComparer.Ordinal).ToList();
        var result = new List<YaraGroupProximity>();

        for (int i = 0; i < groups.Count; i++)
        {
            for (int j = i + 1; j < groups.Count; j++)
            {
                long best = long.MaxValue;
                long at = 0;

                foreach (var a in byGroup[groups[i]])
                {
                    foreach (var b in byGroup[groups[j]])
                    {
                        var d = Math.Abs(a - b);
                        if (d < best) { best = d; at = Math.Min(a, b); }
                    }
                }

                if (best != long.MaxValue)
                    result.Add(new YaraGroupProximity(groups[i], groups[j], best, at));
            }
        }

        return result.OrderBy(p => p.Distance).ToList();
    }
}

/// <summary>
/// Shared YARA invocation and output analysis.
///
/// WHY THIS IS SHARED
/// ------------------
/// Layer 5 scans the raw file; Layer 5b scans the decompressed PDF streams. Both
/// call the same engine for the same purpose, and until this file existed both
/// carried their own copy of the invocation — with the result that a fix applied
/// to one silently left the other behind. Two such divergences had already
/// appeared: the missing detail flags, and the pipe-draining deadlock. Keeping
/// one implementation is what makes the two layers comparable in the evaluation,
/// since a difference in their results can then only come from WHAT was scanned,
/// never from HOW.
///
/// WHY IT REPORTS MORE THAN A RULE NAME
/// -----------------------------------
/// A rule name alone is an assertion: a pattern matched, but not what matched,
/// where, or how strong the inference is — so nobody reading the result can
/// check it. YARA already produces the detail; it has to be asked for:
///   -s   print the matched strings with their byte offsets
///   -m   print the rule's own meta block (severity, category, reference)
/// Parsing both keeps the interpretation in the rule files, where a new rule
/// carries its own classification, rather than in a C# table that has to be
/// edited in lockstep.
///
/// PROXIMITY
/// ---------
/// A multi-string rule normally fires on CO-OCCURRENCE: pattern A appears and
/// pattern B appears, anywhere in the scanned bytes. That is weaker than it
/// looks — a legitimate PDF can hold an /OpenAction that merely turns a page
/// while, far away, carrying benign form-validation JavaScript.
///
/// The offsets settle it. Matches a few dozen bytes apart sit in the same
/// object, i.e. are genuinely wired together; matches kilobytes apart may be
/// unrelated. Distances are measured between GROUPS rather than individual
/// strings, because the tightest individual pair is often the least informative:
/// in a PDF it is /JavaScript beside /JS, twelve bytes apart because that IS the
/// shape of a JavaScript action dictionary — which shows the script is
/// well-formed but says nothing about whether it auto-runs. Every group pair is
/// therefore reported, so both facts survive.
///
/// Nothing here claims a payload is malicious. Establishing that needs execution
/// or semantic analysis, neither of which belongs in an upload gate. What is
/// reported is what was found, where, and how the rule itself rates it.
/// </summary>
public static class YaraRunner
{
    /// <summary>
    /// Distance, in bytes, under which two matched string groups are reported as
    /// co-located rather than merely co-present.
    ///
    /// 512 is deliberately loose: a PDF action dictionary and the script it
    /// references normally sit well within it, while unrelated objects in a real
    /// document are typically much further apart. It bounds a REPORTING threshold
    /// only — nothing is accepted or rejected on the strength of it, so an
    /// imprecise value costs clarity, never safety.
    /// </summary>
    public const long CoLocationWindowBytes = 512;

    /// <summary>Caps on reason-string length; full detail always survives in the evidence list.</summary>
    private const int MaxReportedPairs = 3;
    private const int MaxReportedStrings = 8;

    /// <summary>
    /// Runs YARA over one file on disk and returns every rule that fired, with
    /// its meta block and the offset of every matched string.
    /// An empty list means a clean scan.
    /// </summary>
    public static List<YaraRuleMatch> Scan(
        string yaraExecutablePath,
        string rulesFilePath,
        string targetFilePath,
        int timeoutMs)
    {
        var psi = new ProcessStartInfo
        {
            FileName = yaraExecutablePath,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        // -s prints matched strings with byte offsets; -m prints the rule meta block.
        psi.ArgumentList.Add("-s");
        psi.ArgumentList.Add("-m");

        // Arguments added separately so paths with spaces are handled safely
        // (prevents command-injection-style issues with crafted filenames).
        psi.ArgumentList.Add(rulesFilePath);
        psi.ArgumentList.Add(targetFilePath);

        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException("Failed to start the YARA process.");

        // Both pipes must be drained CONCURRENTLY. Reading one to the end and then
        // the other deadlocks as soon as the un-read pipe's buffer fills: the child
        // blocks on write while the parent blocks on read, and the timeout below is
        // never reached because it sits after the blocking call. Harmless while the
        // output was a single line; with -s it is many lines per match, so the reads
        // are started before the wait.
        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();

        // Timeout protection: a hung scanner must never hang the request (DoS guard).
        if (!process.WaitForExit(timeoutMs))
        {
            try { process.Kill(true); } catch { /* best effort */ }
            throw new TimeoutException($"YARA scan exceeded the {timeoutMs} ms timeout.");
        }

        // The pipes close on exit, so these complete promptly; bounded defensively.
        if (!Task.WaitAll(new Task[] { stdoutTask, stderrTask }, 5_000))
            throw new TimeoutException("Timed out reading YARA output after the process exited.");

        string stdout = stdoutTask.Result;
        string stderr = stderrTask.Result;

        // Exit code 0 = scan completed (with or without matches).
        // Anything else = engine error (bad rules file, unreadable file, ...).
        // NOTE: rule-quality warnings ("string may slow down scanning") also arrive
        // on stderr with exit code 0, so stderr alone must not be treated as failure.
        if (process.ExitCode != 0)
            throw new InvalidOperationException(
                $"YARA exited with code {process.ExitCode}. Error: {stderr.Trim()}");

        return ParseOutput(stdout);
    }

    // ------------------------------------------------------------------
    // Reporting
    // ------------------------------------------------------------------

    private static string Hex(long offset) =>
        "0x" + offset.ToString("x", CultureInfo.InvariantCulture);

    /// <summary>
    /// Self-contained explanation of a set of matches: which rules fired, how each
    /// rule rates itself, where every pattern matched, and how close the groups sit.
    /// </summary>
    /// <param name="locate">
    /// Optional translator from a scanned-bytes offset to a description of where
    /// those bytes originally came from. Layer 5 scans the file itself, so offsets
    /// are already file offsets and no translation is needed. Layer 5b scans a
    /// concatenation of decompressed streams, where a bare offset is meaningless
    /// on its own — the callback is what turns it back into a position in the
    /// original upload.
    /// </param>
    public static string DescribeMatches(
        IEnumerable<YaraRuleMatch> matches,
        Func<long, string>? locate = null)
    {
        var perRule = new List<string>();

        foreach (var rule in matches)
        {
            var sb = new StringBuilder(rule.RuleName);

            var tags = new List<string>();
            if (rule.Severity is not null) tags.Add($"severity={rule.Severity}");
            if (rule.Category is not null) tags.Add($"category={rule.Category}");
            if (tags.Count > 0) sb.Append(" [").Append(string.Join(", ", tags)).Append(']');

            if (rule.Hits.Count > 0)
            {
                var shown = rule.Hits.Take(MaxReportedStrings).Select(h =>
                {
                    var where = locate is null ? Hex(h.Offset) : locate(h.Offset);
                    // Quoted and spaced: without delimiters a matched string ending
                    // in punctuation runs straight into its own location and the
                    // boundary between the two becomes impossible to see.
                    return $"\"{h.Preview()}\" at {where}";
                });

                sb.Append(" | strings: ").Append(string.Join(", ", shown));

                if (rule.Hits.Count > MaxReportedStrings)
                    sb.Append(", +").Append(rule.Hits.Count - MaxReportedStrings).Append(" more");
            }

            var proximities = rule.GroupProximities();
            if (proximities.Count > 0)
            {
                var shown = proximities
                    .Take(MaxReportedPairs)
                    .Select(p => $"{p.GroupA}~{p.GroupB} {p.Distance}B {(p.CoLocated ? "co-located" : "distant")}");

                sb.Append(" | proximity: ").Append(string.Join(", ", shown));
            }

            if (rule.Reference is not null)
                sb.Append(" | ref: ").Append(rule.Reference);

            perRule.Add(sb.ToString());
        }

        return string.Join("  ||  ", perRule);
    }

    /// <summary>
    /// Flat, groupable evidence: one entry per rule carrying its classification,
    /// one per matched string carrying its position, and one per group pair
    /// carrying the measured distance.
    /// </summary>
    /// <param name="kindPrefix">
    /// Distinguishes which layer produced the evidence — "yara" for the raw scan,
    /// "pdfflate-yara" for the decompressed-stream scan. Keeping them separable is
    /// what allows the ablation to state how many detections came ONLY from
    /// decompression, which is the entire justification for that layer existing.
    /// </param>
    public static List<ScanEvidence> BuildEvidence(
        IEnumerable<YaraRuleMatch> matches,
        string kindPrefix = "yara",
        Func<long, string>? locate = null)
    {
        var evidence = new List<ScanEvidence>();

        foreach (var rule in matches)
        {
            evidence.Add(new ScanEvidence(
                Kind: $"{kindPrefix}-rule",
                Label: rule.RuleName,
                Detail: rule.Description ?? "(no description in rule meta)",
                Offset: null,
                Severity: rule.Severity,
                Reference: rule.Reference));

            foreach (var hit in rule.Hits)
            {
                var detail = locate is null
                    ? hit.MatchedText
                    : $"{hit.MatchedText} (source: {locate(hit.Offset)})";

                evidence.Add(new ScanEvidence(
                    Kind: $"{kindPrefix}-string",
                    Label: $"{rule.RuleName}/{hit.StringId}",
                    Detail: detail,
                    Offset: hit.Offset,
                    Severity: rule.Severity));
            }

            foreach (var p in rule.GroupProximities())
            {
                var meaning = p.CoLocated
                    ? "within one object window — the matches are wired together, not merely co-present"
                    : "far apart — co-occurrence only; the link between them is not demonstrated";

                evidence.Add(new ScanEvidence(
                    Kind: $"{kindPrefix}-proximity",
                    Label: $"{rule.RuleName}/{p.GroupA}~{p.GroupB}",
                    Detail: $"{p.Distance} bytes apart: {meaning}",
                    Offset: p.AtOffset,
                    Severity: rule.Severity));
            }
        }

        return evidence;
    }

    // ------------------------------------------------------------------
    // Output parsing
    // ------------------------------------------------------------------

    /// <summary>
    /// Parses the -s -m output.
    ///
    /// Output shape:
    ///   RuleName [key="value",key2="value2"] C:\path\to\file
    ///   0x2a46:$js1: /JavaScript
    ///   0x3269:$act1: /OpenAction
    ///
    /// A header line names the rule; the offset lines that follow belong to it
    /// until the next header.
    /// </summary>
    private static List<YaraRuleMatch> ParseOutput(string stdout)
    {
        var results = new List<YaraRuleMatch>();
        YaraRuleMatch? current = null;

        foreach (var rawLine in stdout.Split('\n'))
        {
            var line = rawLine.TrimEnd('\r', '\n');
            if (string.IsNullOrWhiteSpace(line)) continue;

            // Offset lines are the only ones beginning with a hex offset.
            if (TryParseStringHit(line, out var hit))
            {
                current?.Hits.Add(hit!);
                continue;
            }

            // Otherwise: a rule header. Everything before the first space is the
            // rule name; a bracketed section, when -m is in effect, is the meta.
            var name = line.Split(' ', 2)[0].Trim();
            if (name.Length == 0) continue;

            current = new YaraRuleMatch { RuleName = name };
            foreach (var kv in ParseMetaBlock(line))
                current.Meta[kv.Key] = kv.Value;

            results.Add(current);
        }

        return results;
    }

    /// <summary>
    /// Parses "0x2a46:$js1: /JavaScript".
    /// Split on the FIRST two colons only — the matched text may itself contain
    /// colons, which a naive split would truncate.
    /// </summary>
    private static bool TryParseStringHit(string line, out YaraStringHit? hit)
    {
        hit = null;

        if (!line.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) return false;

        int firstColon = line.IndexOf(':');
        if (firstColon < 0) return false;

        int secondColon = line.IndexOf(':', firstColon + 1);
        if (secondColon < 0) return false;

        var offsetText = line[..firstColon].Trim();
        if (!offsetText.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) return false;

        if (!long.TryParse(offsetText.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var offset))
            return false;

        var stringId = line[(firstColon + 1)..secondColon].Trim();
        if (stringId.Length == 0 || stringId[0] != '$') return false;

        hit = new YaraStringHit(stringId, offset, line[(secondColon + 1)..].Trim());
        return true;
    }

    /// <summary>
    /// Extracts key="value" pairs from the bracketed meta section of a header line.
    /// Quote-aware: a value may legitimately contain commas, which splitting on
    /// ',' alone would break apart.
    /// </summary>
    private static IEnumerable<KeyValuePair<string, string>> ParseMetaBlock(string headerLine)
    {
        int open = headerLine.IndexOf('[');
        int close = headerLine.LastIndexOf(']');
        if (open < 0 || close < 0 || close <= open) yield break;

        var body = headerLine[(open + 1)..close];

        int i = 0;
        while (i < body.Length)
        {
            int eq = body.IndexOf('=', i);
            if (eq < 0) break;

            var key = body[i..eq].Trim().Trim(',').Trim();
            i = eq + 1;

            string value;
            if (i < body.Length && body[i] == '"')
            {
                int end = body.IndexOf('"', i + 1);
                if (end < 0) break;

                value = body[(i + 1)..end];
                i = end + 1;
            }
            else
            {
                int end = body.IndexOf(',', i);
                if (end < 0) end = body.Length;

                value = body[i..end].Trim();
                i = end;
            }

            if (i < body.Length && body[i] == ',') i++;

            if (key.Length > 0)
                yield return new KeyValuePair<string, string>(key, value);
        }
    }
}