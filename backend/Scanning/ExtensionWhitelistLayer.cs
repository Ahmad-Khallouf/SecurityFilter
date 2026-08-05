namespace SecureUploader.Scanning;

/// <summary>
/// Layer 1: Extension Whitelisting.
/// Only explicitly allowed extensions per category are accepted (whitelist, never blacklist).
/// Reference: OWASP File Upload Cheat Sheet — "List allowed extensions";
/// CWE-434 (Unrestricted Upload of File with Dangerous Type).
/// </summary>
public sealed class ExtensionWhitelistLayer : IScanLayer
{
    public string Name => "ExtensionWhitelist";

    // Allowed extensions per upload category. Whitelist approach:
    // anything not in this list is rejected (fail-safe default).
    // List is based on real-world platform behavior (major platforms accept
    // JPG/PNG/WEBP for avatars; KYC systems accept PDF + photos for ID documents).
    // SVG is accepted ONLY because Layer 7 (SVG Sanitization) neutralizes
    // embedded scripts (XSS risk) — major platforms reject it outright.
    private static readonly Dictionary<string, HashSet<string>> AllowedExtensions =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["profile"] = new(StringComparer.OrdinalIgnoreCase) { ".jpg", ".jpeg", ".png", ".webp", ".svg" },
            ["id"] = new(StringComparer.OrdinalIgnoreCase) { ".pdf", ".jpg", ".jpeg", ".png" }
        };

    public ScanResult Scan(FileScanContext context)
    {
        // Fail securely: unknown category => reject.
        if (!AllowedExtensions.TryGetValue(context.Category, out var allowed))
            return ScanResult.Reject(Name, $"Unknown upload category '{context.Category}'.");

        if (string.IsNullOrWhiteSpace(context.FileName))
            return ScanResult.Reject(Name, "Empty or missing filename.");

        var extension = Path.GetExtension(context.FileName);

        if (string.IsNullOrEmpty(extension))
            return ScanResult.Reject(Name, "File has no extension.");

        if (!allowed.Contains(extension))
            return ScanResult.Reject(Name, $"Extension '{extension}' is not whitelisted for category '{context.Category}'.");

        return ScanResult.Accept(Name);
    }
}