namespace SecureUploader.Models;

/// <summary>
/// Controls whether the API exposes its internal reasoning, bound from the
/// "Demo" section of appsettings.json.
///
/// WHY THIS IS A SERVER-SIDE SWITCH AND NOT A UI TOGGLE:
/// hiding detail in the front-end would be cosmetic — the response would still
/// carry it, and anyone opening the browser's developer tools would read it.
/// With the switch here, a production response does not CONTAIN the detail at
/// all, and the comparison endpoint does not exist.
///
/// Default is FALSE. Disclosing which layer rejected a file, and why, hands an
/// attacker a per-layer oracle for tuning an evasion. Enabling it is a
/// deliberate act for demonstration and documentation.
/// </summary>
public sealed class DemoOptions
{
    public const string SectionName = "Demo";

    /// <summary>
    /// When false (production default): rejections return a single generic
    /// message, no layer trace is returned, and /api/compare returns 404.
    /// When true: the full layer trace with timings is returned, and the
    /// comparison endpoint is available.
    /// </summary>
    public bool Enabled { get; set; } = false;
    /// <summary>
    /// Folder for comparison outputs, relative to the content root. Deliberately
    /// separate from the upload storage root: the weak comparators will happily
    /// store hostile files, and this folder is never served over HTTP.
    /// </summary>
    public string ComparisonStorageRoot { get; set; } = "comparison-output";
}