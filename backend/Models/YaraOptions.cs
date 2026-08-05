namespace SecureUploader.Models;

/// <summary>
/// Strongly-typed configuration for the YARA scanning layers,
/// bound from the "Yara" section of appsettings.json.
/// </summary>
public sealed class YaraOptions
{
    public const string SectionName = "Yara";

    /// <summary>Full path to the YARA executable (yara64.exe).</summary>
    public string ExecutablePath { get; set; } = @"C:\yara\yara64.exe";

    /// <summary>Rules file path, relative to the application content root.</summary>
    public string RulesFilePath { get; set; } = "YaraRules/rules.yar";

    /// <summary>Scan timeout in milliseconds (DoS guard).</summary>
    public int TimeoutMs { get; set; } = 10_000;
}