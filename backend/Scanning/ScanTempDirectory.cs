namespace SecureUploader.Scanning;

/// <summary>
/// Owns the single project-local directory that YARA temp files are written to.
///
/// WHY THIS EXISTS: YARA scans files on disk, so the compressed-stream layer has
/// to write its DECOMPRESSED output to a temp file before scanning it. On a host
/// running Windows Defender that decompressed file — now containing the payload
/// in the clear — is locked or quarantined the instant it is written, and YARA
/// then fails to open it. That turns a real detection into a misleading
/// "could not open file" rejection.
///
/// Routing every scan temp file into ONE known project folder lets that single
/// folder carry a Defender exclusion, instead of excluding the shared system
/// TEMP (which every process on the machine writes to). The exclusion is
/// narrow, named, and documented — the same isolated-work-folder principle used
/// for the sample corpus.
///
/// The folder holds only transient scan buffers; entries are deleted
/// immediately after each scan by the layer that created them.
/// </summary>
public static class ScanTempDirectory
{
    private static string? _path;

    /// <summary>
    /// Absolute path to the scan-temp folder. Created on first use.
    /// Configured once at startup via <see cref="Configure"/>.
    /// </summary>
    public static string Path
    {
        get
        {
            if (_path is null)
                throw new InvalidOperationException(
                    "ScanTempDirectory.Configure must be called at startup before any scan runs.");

            Directory.CreateDirectory(_path);
            return _path;
        }
    }

    /// <summary>Sets the folder location. Called once from Program.cs.</summary>
    public static void Configure(string absolutePath)
    {
        _path = absolutePath;
        Directory.CreateDirectory(absolutePath);
    }

    /// <summary>Builds a unique temp file path inside the scan-temp folder.</summary>
    public static string NewFile(string prefix) =>
        System.IO.Path.Combine(Path, $"{prefix}_{Guid.NewGuid():N}.tmp");
}
