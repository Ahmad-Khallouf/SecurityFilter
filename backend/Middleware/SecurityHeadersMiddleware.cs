namespace SecureUploader.Middleware;

/// <summary>
/// Adds a baseline set of HTTP security response headers to every response.
/// Protects the browser/consumer side of the upload lifecycle - complementing
/// the scanning pipeline, which protects the acceptance side.
/// Reference: OWASP Secure Headers Project.
/// </summary>
public sealed class SecurityHeadersMiddleware
{
    private readonly RequestDelegate _next;

    public SecurityHeadersMiddleware(RequestDelegate next) => _next = next;

    public async Task InvokeAsync(HttpContext context)
    {
        var headers = context.Response.Headers;

        // Stop the browser from MIME-sniffing a response away from its declared type.
        headers["X-Content-Type-Options"] = "nosniff";

        // Disallow embedding the app in a frame (clickjacking protection).
        headers["X-Frame-Options"] = "DENY";

        // Do not leak the referring URL to other origins.
        headers["Referrer-Policy"] = "no-referrer";

        // Disable browser features the app does not need.
        headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";

        // Restrict who may load resources served by this API.
        headers["Cross-Origin-Resource-Policy"] = "same-origin";

        // Defence-in-depth for any HTML/file this backend serves directly.
        // NOTE: 'unsafe-inline' is kept so the dev-only Swagger UI still works;
        // tighten it in production (where Swagger is disabled).
        headers["Content-Security-Policy"] =
            "default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; " +
            "script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:";

        await _next(context);
    }
}