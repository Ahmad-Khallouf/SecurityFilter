namespace SecureUploader.Scanning;

/// <summary>
/// Layer 4: Double-Extension Detection.
///
/// Catches filenames that hide a dangerous extension before a benign one,
/// e.g. "shell.php.jpg" or "invoice.pdf.exe". Some misconfigured servers
/// (notably Apache with a permissive AddHandler) execute a file based on a
/// NON-final extension.
/// Reference: OWASP File Upload Cheat Sheet — "double extensions".
///
/// POLICY (see StrictMode below)
/// -----------------------------
/// STRICT (default): any filename carrying more than one extension segment is
/// rejected, whether or not the hidden segment appears in the dangerous list.
///
/// Rationale: a blacklist of dangerous extensions is necessarily incomplete,
/// and is trivially evaded by mutating the segment so it no longer matches the
/// list while remaining executable to a permissive server or parser:
///     shell.php%00.jpg   (embedded NUL)
///     "shell.php .jpg"   (trailing space)
///     shell.phar.jpg     (a variant absent from most blacklists)
/// The pattern-level rejection closes all of these at once. It is an allowlist
/// posture applied to filename SHAPE, consistent with Layer 1's allowlist
/// applied to the extension itself.
///
/// Cost: legitimate names containing dots ("holiday.2024.jpg", "report.v2.pdf")
/// are rejected. On an upload surface where the operator controls the client,
/// this is an acceptable and documented trade-off — but it IS a cost, and it
/// must be measured rather than assumed away. Hence StrictMode.
///
/// LENIENT: only a segment matching DangerousExtensions triggers rejection.
/// Provided so the false-positive cost of STRICT can be quantified: run the
/// corpus under both settings and report detection / false-positive deltas.
///
/// This is a supplementary detection layer; the primary guard is the extension
/// whitelist (Layer 1). Together = defense-in-depth.
/// </summary>
public sealed class DoubleExtensionLayer : IScanLayer
{
    public string Name => "DoubleExtension";

    /// <summary>
    /// Ablation switch. TRUE = reject any multi-extension filename (default).
    /// FALSE = reject only known-dangerous middle segments.
    /// Flip and rebuild to produce the comparative measurement; do not ship FALSE.
    /// </summary>
    public static bool StrictMode { get; set; } = true;

    /// <summary>
    /// Reason prefixes. Kept as constants so corpus results can be grouped by
    /// rejection CAUSE without string-matching prose. Report these separately:
    /// EVASION and DANGEROUS are true positives against a documented technique;
    /// PATTERN is the strict-policy cost and is where false positives land.
    /// </summary>
    public const string ReasonDangerous = "DE-DANGEROUS";
    public const string ReasonPattern = "DE-PATTERN";
    public const string ReasonEvasion = "DE-EVASION";

    /// <summary>
    /// Server-executable, script, and shell-integration extensions that must
    /// never appear as a hidden segment. PHAR and HTA are included deliberately:
    /// both are documented covert formats in real image-based polyglots
    /// (Koch et al., "On the Abuse and Detection of Polyglot Files", WWW 2025).
    /// </summary>
    private static readonly HashSet<string> DangerousExtensions =
        new(StringComparer.OrdinalIgnoreCase)
        {
            // PHP family — note phar/pht/phps, commonly missing from blacklists
            "php", "php2", "php3", "php4", "php5", "php7", "php8",
            "phtml", "pht", "phar", "phps", "inc",

            // ASP / .NET
            "asp", "aspx", "asa", "asax", "ascx", "ashx", "asmx",
            "cer", "cshtml", "vbhtml", "config",

            // Java
            "jsp", "jspx", "jsw", "jsv", "jspf", "jar", "war", "ear",

            // Windows executables and installers
            "exe", "dll", "com", "msi", "msp", "scr", "pif", "cpl", "msc",

            // Windows scripting / shell integration
            "bat", "cmd", "ps1", "psm1", "ps1xml", "vbs", "vbe",
            "js", "jse", "wsf", "wsh", "hta", "chm", "lnk", "reg", "url",

            // Unix shell and interpreters
            "sh", "bash", "zsh", "ksh", "csh", "py", "pyc", "pl", "rb", "cgi", "lua",

            // Server configuration — execution by policy rather than by content
            "htaccess", "htpasswd", "user", "ini",

            // Markup capable of script execution when served inline
            "svg", "html", "htm", "xhtml", "shtml", "xml", "xsl", "swf",
        };

    /// <summary>
    /// Characters that have no legitimate place in an uploaded filename and are
    /// used to desynchronise a filter's parse from the consumer's parse.
    /// NUL truncates in C-based path handling; control characters and trailing
    /// whitespace are stripped inconsistently across filesystems.
    /// </summary>
    private static bool ContainsEvasionCharacters(string fileName, out string detail)
    {
        foreach (var c in fileName)
        {
            if (c == '\0')
            {
                detail = "embedded NUL byte";
                return true;
            }

            if (char.IsControl(c))
            {
                detail = $"control character U+{(int)c:X4}";
                return true;
            }
        }

        // A segment that is only whitespace, or padded with it, is an attempt to
        // make the segment miss a blacklist while a lenient parser still honours it.
        foreach (var segment in fileName.Split('.'))
        {
            if (segment.Length > 0 && segment.Trim().Length != segment.Length)
            {
                detail = $"padded extension segment '{segment}'";
                return true;
            }
        }

        detail = string.Empty;
        return false;
    }

    public ScanResult Scan(FileScanContext context)
    {
        var fileName = context.FileName;

        if (string.IsNullOrWhiteSpace(fileName))
            return ScanResult.Reject(Name, $"{ReasonEvasion}: Empty or missing filename.");

        // Evasion characters are checked BEFORE splitting: a NUL or padded segment
        // would otherwise slip past the blacklist comparison while remaining
        // meaningful to a downstream parser.
        if (ContainsEvasionCharacters(fileName, out var evasionDetail))
        {
            return ScanResult.Reject(Name,
                $"{ReasonEvasion}: Filename contains a filter-evasion artefact ({evasionDetail}).");
        }

        var parts = fileName.Split('.');

        // Leading dot: ".htaccess" splits to ["", "htaccess"]. Treated as a single
        // extension by a naive count, so the empty base name is checked explicitly.
        if (parts.Length >= 2 && parts[0].Length == 0)
        {
            var hidden = parts[1];
            if (DangerousExtensions.Contains(hidden))
            {
                return ScanResult.Reject(Name,
                    $"{ReasonDangerous}: Filename '{fileName}' is a dot-prefixed '{hidden}' file.");
            }
        }

        // One extension only (name + extension = 2 segments) — nothing hidden.
        if (parts.Length <= 2)
            return ScanResult.Accept(Name);

        // Inspect every segment EXCEPT the base name and the final extension.
        // The final extension is Layer 1's responsibility.
        for (int i = 1; i < parts.Length - 1; i++)
        {
            var middle = parts[i];

            if (DangerousExtensions.Contains(middle))
            {
                return ScanResult.Reject(Name,
                    $"{ReasonDangerous}: Dangerous hidden extension '.{middle}' detected in filename '{fileName}'.");
            }
        }

        // No listed dangerous segment. Under STRICT the multi-extension SHAPE is
        // itself rejected — this is what closes the blacklist's inevitable gaps.
        // Under LENIENT the file passes, and the difference between the two runs
        // is the measurement.
        if (StrictMode)
        {
            return ScanResult.Reject(Name,
                $"{ReasonPattern}: Filename '{fileName}' carries more than one extension segment.");
        }

        return ScanResult.Accept(Name);
    }
}