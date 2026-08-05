using ImageMagick;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using SecureUploader.Middleware;
using SecureUploader.Models;
using SecureUploader.Scanning;
using SecureUploader.Services;

var builder = WebApplication.CreateBuilder(args);

// ---------------------------------------------------------------------------
// CORS — the React dev server (Vite) runs on a different origin. The Vite proxy
// (see frontend/vite.config.js) means CORS is usually not even hit in dev, but
// this policy keeps things working if the front-end calls the API directly.
// ---------------------------------------------------------------------------
const string CorsPolicy = "frontend";
builder.Services.AddCors(options =>
{
    options.AddPolicy(CorsPolicy, policy =>
        policy.WithOrigins(
                "http://localhost:5173",   // Vite default
                "http://localhost:3000")   // CRA / alt port
              .AllowAnyHeader()
              .AllowAnyMethod());
});

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Bind upload settings (limits, allow-lists, storage location) from appsettings.json.
builder.Services.Configure<UploadOptions>(
    builder.Configuration.GetSection(UploadOptions.SectionName));

// ---------------------------------------------------------------------------
// SCANNING PIPELINE (Phase 3)
// The static-analysis layers, registered in FAIL-FAST FUNNEL ORDER.
// Cheap checks run first; expensive content inspection runs last.
//
// ORDER IS SECURITY-RELEVANT:
//   1. ExtensionWhitelist      - cheapest reject, no I/O          [NOT cached: filename-based]
//   2. MagicBytes              - detects the REAL file type       [NOT cached: sets DetectedFileType]
//   3. HeaderContentMatching   - DEPENDS on (2)                   [NOT cached: filename/header-based]
//   4. DoubleExtension         - filename-based                   [NOT cached: filename-based]
//   5. SignatureScanning       - YARA over raw bytes (expensive)  [CACHED]
//   5b. PdfFlateDecode         - inflate PDF streams, then YARA   [CACHED]
//   5c. EmbeddedLinkScan       - URL extraction from SVG/PDF      [CACHED]
//   6. ImageReEncoding         - SANITIZES: decode -> re-encode   [NEVER cached]
//   7. SvgSanitization         - SANITIZES: strips scripts/handlers [NEVER cached]
//
// CACHING RULE: only content-based DETECTION layers are wrapped in
// CachedScanLayer. Filename-dependent layers deliberately stay outside the
// cache and run on every upload, so identical bytes submitted under a
// different (malicious) filename cannot inherit a cached verdict.
// ---------------------------------------------------------------------------

// YARA paths and timeout now come from the "Yara" section of appsettings.json
// (defined in one place; no longer hardcoded or duplicated across layers).
builder.Services.Configure<YaraOptions>(
    builder.Configuration.GetSection(YaraOptions.SectionName));

// Image re-encoding (Layer 6) and scan-result cache settings.
// Bounds for the PDF FlateDecode layer: decompression-bomb caps and the
// nested-filter decode depth (see PdfFlateDecodeLayer for the rationale).
builder.Services.Configure<PdfDecodeOptions>(
    builder.Configuration.GetSection(PdfDecodeOptions.SectionName));

builder.Services.Configure<ReEncodingOptions>(
    builder.Configuration.GetSection(ReEncodingOptions.SectionName));
builder.Services.Configure<CacheOptions>(
    builder.Configuration.GetSection(CacheOptions.SectionName));

// Demo mode: server-side switch controlling whether internal reasoning leaves
// the process at all, and whether the comparison endpoint exists. Default off.
builder.Services.Configure<DemoOptions>(
    builder.Configuration.GetSection(DemoOptions.SectionName));

// Bounded in-memory cache for scan verdicts. SizeLimit + per-entry Size = 1
// means "at most MaxEntries verdicts", so a flood of unique uploads cannot
// exhaust memory.
var cacheSettings = builder.Configuration
    .GetSection(CacheOptions.SectionName).Get<CacheOptions>() ?? new CacheOptions();

builder.Services.AddSingleton<IMemoryCache>(_ =>
    new MemoryCache(new MemoryCacheOptions { SizeLimit = cacheSettings.MaxEntries }));

// ImageMagick resource ceilings — the library-level backstop behind the
// header-only dimension checks inside ImageReEncodingLayer.
var reEncodingSettings = builder.Configuration
    .GetSection(ReEncodingOptions.SectionName).Get<ReEncodingOptions>() ?? new ReEncodingOptions();

ResourceLimits.Memory = (ulong)reEncodingSettings.MagickMemoryLimitMb * 1024 * 1024;
ResourceLimits.Width = (ulong)reEncodingSettings.MaxWidth;
ResourceLimits.Height = (ulong)reEncodingSettings.MaxHeight;

var contentRoot = builder.Environment.ContentRootPath;

// Route all YARA temp files into ONE project-local folder so a single, narrow
// Defender exclusion can cover them. Without this, a decompressed payload (e.g.
// the EICAR test string surfaced from a FlateDecode stream) is quarantined the
// moment it is written to the shared system TEMP, and YARA fails to open it —
// which would masquerade as a rejection. Exclude ONLY this folder; keep
// real-time protection on everywhere else.
var scanTempDir = Path.Combine(contentRoot, "_scan_temp");
SecureUploader.Scanning.ScanTempDirectory.Configure(scanTempDir);

builder.Services.AddScoped<SecureUploadScanner>(sp =>
{
    var yara = sp.GetRequiredService<IOptions<YaraOptions>>().Value;
    var reEncoding = sp.GetRequiredService<IOptions<ReEncodingOptions>>().Value;
    var pdfDecode = sp.GetRequiredService<IOptions<PdfDecodeOptions>>().Value;
    var cacheOptions = sp.GetRequiredService<IOptions<CacheOptions>>().Value;
    var memoryCache = sp.GetRequiredService<IMemoryCache>();

    var yaraExecutablePath = yara.ExecutablePath;
    var yaraRulesPath = Path.Combine(contentRoot, yara.RulesFilePath);
    var ttl = TimeSpan.FromMinutes(cacheOptions.TtlMinutes);

    // Wraps a detection layer in the verdict cache — or returns it untouched
    // when caching is disabled (needed for uncached Phase 2 timing runs).
    IScanLayer Cached(IScanLayer layer) => cacheOptions.Enabled
        ? new CachedScanLayer(layer, memoryCache, ttl, yaraRulesPath)
        : layer;

    return new SecureUploadScanner(
        layers: new IScanLayer[]
        {
            new ExtensionWhitelistLayer(),
            new MagicBytesLayer(),
            new HeaderContentMatchingLayer(),
            new DoubleExtensionLayer(),
            Cached(new SignatureScanningLayer(yaraExecutablePath, yaraRulesPath, yara.TimeoutMs)),
            Cached(new PdfFlateDecodeLayer(yaraExecutablePath, yaraRulesPath, pdfDecode, yara.TimeoutMs)),
            Cached(new EmbeddedLinkLayer(blockExternalLinks: false)),
            new ImageReEncodingLayer(reEncoding),
            new SvgSanitizationLayer()
        },
        logger: sp.GetRequiredService<ILogger<SecureUploadScanner>>());
});

// ---------------------------------------------------------------------------
// SCANNER SELECTION — the integration seam.
// The upload pipeline depends on a single IFileScanner. Swap between the weak
// Phase 1 baseline and the full static-analysis filter by changing THIS SINGLE
// LINE. Nothing else in the pipeline changes.
//
//   Baseline comparator (Phase 1):
//   builder.Services.AddScoped<IFileScanner, BasicValidationScanner>();
// ---------------------------------------------------------------------------
builder.Services.AddScoped<IFileScanner, StaticAnalysisScanner>();

// ---------------------------------------------------------------------------
// COMPARISON HARNESS (Phase 2 evaluation).
// Every comparator is registered by its CONCRETE type, never as IFileScanner:
// registering them all under the interface would make the line above ambiguous
// and silently change which scanner the real upload path uses.
//
// Reference comparators re-implement DVWA's four documented security levels.
// Ordered weakest-first so the comparison table reads as a progression, with our
// own weak baseline immediately before the layered filter.
// ---------------------------------------------------------------------------
builder.Services.AddScoped<DvwaLowScanner>();
builder.Services.AddScoped<DvwaMediumScanner>();
builder.Services.AddScoped<DvwaHighScanner>();
builder.Services.AddScoped<DvwaImpossibleScanner>();
builder.Services.AddScoped<BasicValidationScanner>();
builder.Services.AddScoped<StaticAnalysisScanner>();

builder.Services.AddScoped<ComparisonOrchestrator>(sp =>
{
    var demo = sp.GetRequiredService<IOptions<DemoOptions>>().Value;

    var comparisonRoot = Path.IsPathRooted(demo.ComparisonStorageRoot)
        ? demo.ComparisonStorageRoot
        : Path.Combine(contentRoot, demo.ComparisonStorageRoot);

    var scanners = new IFileScanner[]
    {
        sp.GetRequiredService<DvwaLowScanner>(),
        sp.GetRequiredService<DvwaMediumScanner>(),
        sp.GetRequiredService<DvwaHighScanner>(),
        sp.GetRequiredService<DvwaImpossibleScanner>(),
        sp.GetRequiredService<BasicValidationScanner>(),
        sp.GetRequiredService<StaticAnalysisScanner>()
    };

    return new ComparisonOrchestrator(
        scanners,
        comparisonRoot,
        sp.GetRequiredService<ILogger<ComparisonOrchestrator>>());
});

builder.Services.AddScoped<CorpusRunner>();

// Allow reasonably large multipart uploads.
const long MaxUploadBytes = 50L * 1024 * 1024; // 50 MB hard ceiling at the server
builder.Services.Configure<FormOptions>(o => o.MultipartBodyLengthLimit = MaxUploadBytes);
builder.WebHost.ConfigureKestrel((KestrelServerOptions o) =>
{
    o.Limits.MaxRequestBodySize = MaxUploadBytes;
    o.AddServerHeader = false;   // do not advertise "Server: Kestrel"
});

var app = builder.Build();

// Security headers on EVERY response (first in the pipeline so it wraps all responses).
app.UseMiddleware<SecurityHeadersMiddleware>();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseCors(CorsPolicy);
app.MapControllers();

app.Run();