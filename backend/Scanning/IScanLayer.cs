namespace SecureUploader.Scanning;

/// <summary>
/// Contract that every scan layer must implement.
/// Enables the pipeline (SecureUploadScanner) to treat all layers uniformly.
/// Design principle: defense-in-depth — each layer is an independent control.
/// </summary>
public interface IScanLayer
{
    /// <summary>Human-readable layer name, used for logging.</summary>
    string Name { get; }

    /// <summary>Inspects the file and returns Accept / Reject / Sanitize.</summary>
    ScanResult Scan(FileScanContext context);
} 
