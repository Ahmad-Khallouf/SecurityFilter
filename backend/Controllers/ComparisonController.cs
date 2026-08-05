using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using SecureUploader.Models;
using SecureUploader.Services;

namespace SecureUploader.Controllers;

/// <summary>
/// The comparison endpoint: runs one uploaded file through every configured
/// scanner and returns their verdicts side by side.
///
/// GATED ON DEMO MODE. When demo mode is off the endpoint returns 404 — not 403.
/// A 403 would confirm the endpoint exists; 404 tells an unauthorised caller
/// nothing, and the production surface genuinely does not include it.
///
/// This endpoint is for evaluation and demonstration. The real upload path is
/// unchanged and still runs the layered filter alone.
/// </summary>
[ApiController]
[Route("api")]
public class ComparisonController : ControllerBase
{
    private static readonly string[] ValidCategories = { "profile", "id" };

    private readonly ComparisonOrchestrator _orchestrator;
    private readonly DemoOptions _demo;
    private readonly ILogger<ComparisonController> _logger;

    public ComparisonController(
        ComparisonOrchestrator orchestrator,
        IOptions<DemoOptions> demo,
        ILogger<ComparisonController> logger)
    {
        _orchestrator = orchestrator;
        _demo = demo.Value;
        _logger = logger;
    }

    /// <summary>
    /// Lets the front-end discover whether demo features should be shown at all,
    /// instead of hard-coding an assumption that would drift from the server.
    /// </summary>
    [HttpGet("demo-status")]
    public IActionResult DemoStatus() => Ok(new { demoMode = _demo.Enabled });

    [HttpPost("compare")]
    public async Task<IActionResult> Compare(
        [FromForm] IFormFile? file,
        [FromForm] string? category,
        CancellationToken ct)
    {
        if (!_demo.Enabled)
            return NotFound();

        category = (category ?? "").Trim().ToLowerInvariant();
        if (!ValidCategories.Contains(category))
            return BadRequest(UploadResponse.Error(
                $"Unknown category '{category}'. Expected one of: {string.Join(", ", ValidCategories)}."));

        if (file is null || file.Length == 0)
            return BadRequest(UploadResponse.Error("No file was provided."));

        _logger.LogWarning(
            "COMPARISON RUN starting for '{File}'. Weak comparators will store this file unmodified.",
            file.FileName);

        var result = await _orchestrator.RunAsync(file, category, ct);
        return Ok(result);
    }
}
