namespace SecureUploader.Models;

/// <summary>
/// Upload limits and allow-lists, bound from the "Upload" section of
/// appsettings.json. Kept in config so the Phase 4/5 testing can tweak limits
/// without recompiling.
/// </summary>
public class UploadOptions
{
    public const string SectionName = "Upload";

    /// <summary>Maximum accepted file size, in bytes.</summary>
    public long MaxFileSizeBytes { get; set; } = 5 * 1024 * 1024; // 5 MB

    /// <summary>Folder (relative to the app content root, or absolute) where accepted files are stored.</summary>
    public string StorageRoot { get; set; } = "uploads";

    /// <summary>Allowed file extensions (weak baseline check — only the last extension is inspected).</summary>
    public List<string> AllowedExtensions { get; set; } =
        new() { ".jpg", ".jpeg", ".png", ".webp", ".svg", ".pdf" };

    /// <summary>Allowed client-declared content types (weak baseline check — client-controlled, spoofable).</summary>
    public List<string> AllowedContentTypes { get; set; } =
        new() { "image/jpeg", "image/png", "image/webp", "image/svg+xml", "application/pdf" };
}
