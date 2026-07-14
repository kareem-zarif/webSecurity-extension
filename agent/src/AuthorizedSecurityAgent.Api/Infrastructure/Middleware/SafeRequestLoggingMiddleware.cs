using System.Diagnostics;
using AuthorizedSecurityAgent.Infrastructure.Logging;

namespace AuthorizedSecurityAgent.Infrastructure.Middleware;

internal sealed class SafeRequestLoggingMiddleware(
    RequestDelegate next,
    ILogger<SafeRequestLoggingMiddleware> logger)
{
    public async Task InvokeAsync(HttpContext context)
    {
        var stopwatch = Stopwatch.StartNew();

        try
        {
            await next(context);
        }
        finally
        {
            stopwatch.Stop();

            // Endpoint display names are static metadata. Raw URLs, queries, headers,
            // request bodies, cookies, and exception messages are deliberately excluded.
            var endpointName = context.GetEndpoint()?.DisplayName ?? "Unmatched endpoint";
            logger.LogInformation(
                "HTTP {Method} {EndpointName} returned {StatusCode} in {ElapsedMilliseconds} ms",
                context.Request.Method,
                endpointName,
                context.Response.StatusCode,
                stopwatch.Elapsed.TotalMilliseconds);
        }
    }
}

