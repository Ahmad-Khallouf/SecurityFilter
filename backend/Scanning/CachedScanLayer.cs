using System.Security.Cryptography;
using Microsoft.Extensions.Caching.Memory;

namespace SecureUploader.Scanning;

/// <summary>
/// Decorator that adds a scan-result cache in front of an EXPENSIVE
/// content-based detection layer (YARA process spawns, stream decompression).
///
/// DESIGN RULES (security-relevant):
///   1. Only DETECTION layers may be wrapped — never sanitization layers.
///      Enforced structurally: a Sanitized result is passed through UNCACHED,
///      because a consumed stream cannot be replayed from a cache.
///   2. Filename-dependent layers (1, 3, 4) are NEVER wrapped; they stay
///      outside the cache and run on every upload, so the classic bypass
///      "same bytes, different (malicious) name" is impossible by construction.
///   3. The cache key binds three things together:
///        inner layer name + SHA-256(content) + rules-file fingerprint.
///      Editing rules.yar changes the fingerprint, which retires every stale
///      verdict instantly — no manual cache flush needed.
///   4. SHA-256 (not MD5/SHA-1): a collision-capable hash would itself become
///      the bypass (get a benign colliding file cached first, then upload the
///      payload with the same hash).
///   5. Entries carry a size + TTL so the cache is bounded (a flood of unique
///      files must not become a memory-exhaustion DoS).
/// </summary>
public sealed class CachedScanLayer : IScanLayer
{
    private readonly IScanLayer _inner;
    private readonly IMemoryCache _cache;
    private readonly TimeSpan _ttl;
    private readonly string? _rulesFilePath;

    public string Name => $"Cached({_inner.Name})";

    public CachedScanLayer(IScanLayer inner, IMemoryCache cache, TimeSpan ttl, string? rulesFilePath = null)
    {
        _inner = inner;
        _cache = cache;
        _ttl = ttl;
        _rulesFilePath = rulesFilePath;
    }

    public ScanResult Scan(FileScanContext context)
    {
        // 1) Content fingerprint: computed once per upload, shared via the context
        //    so the second/third cached layer finds it ready.
        context.ContentHash ??= ComputeSha256(context.FileStream);

        // 2) Dependency fingerprint: rules file size + last-write time. Read on
        //    every scan (two cheap syscalls) so rule edits take effect instantly.
        var rulesFingerprint = GetRulesFingerprint();

        var key = $"{_inner.Name}|{context.ContentHash}|{rulesFingerprint}";

        // 3) Cache hit: return the stored verdict, skip the expensive layer.
        if (_cache.TryGetValue<ScanResult>(key, out var cached) && cached is not null)
            return cached.AsCacheHit();

        // 4) Miss: run the real layer.
        var result = _inner.Scan(context);

        // 5) Only Accept/Reject verdicts are cacheable. A Sanitized result holds
        //    a live stream and must never be replayed from a cache.
        if (result.Decision != ScanDecision.Sanitized)
        {
            _cache.Set(key, result, new MemoryCacheEntryOptions
            {
                Size = 1,
                AbsoluteExpirationRelativeToNow = _ttl
            });
        }

        return result;
    }

    private static string ComputeSha256(Stream stream)
    {
        stream.Position = 0;
        var hash = SHA256.HashData(stream);
        stream.Position = 0; // leave the stream ready for the inner layer
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private string GetRulesFingerprint()
    {
        if (_rulesFilePath is null)
            return "none";

        try
        {
            var fi = new FileInfo(_rulesFilePath);
            return fi.Exists ? $"{fi.Length}-{fi.LastWriteTimeUtc.Ticks}" : "missing";
        }
        catch
        {
            // If the fingerprint cannot be read, fail toward correctness: a
            // unique value disables caching for this one scan rather than
            // risking a stale verdict under an unknown rules state.
            return Guid.NewGuid().ToString("N");
        }
    }
}