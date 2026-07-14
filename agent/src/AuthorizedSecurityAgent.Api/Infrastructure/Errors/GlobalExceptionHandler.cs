using AuthorizedSecurityAgent.Application.Contracts;
using Microsoft.AspNetCore.Diagnostics;

namespace AuthorizedSecurityAgent.Infrastructure.Errors;

internal sealed class GlobalExceptionHandler(ILogger<GlobalExceptionHandler> logger) : IExceptionHandler
{
    public async ValueTask<bool> TryHandleAsync(
        HttpContext httpContext,
        Exception exception,
        CancellationToken cancellationToken)
    {
        var traceId = httpContext.TraceIdentifier;

        // Never log the exception message or object: either can contain request secrets.
        logger.LogError(
            "Unhandled {ExceptionType} for trace {TraceId}",
            exception.GetType().Name,
            traceId);

        httpContext.Response.StatusCode = StatusCodes.Status500InternalServerError;
        await httpContext.Response.WriteAsJsonAsync(
            new ErrorResponse(
                ErrorCode: ErrorCodes.UnexpectedError,
                Message: ErrorMessages.UnexpectedError,
                TraceId: traceId),
            cancellationToken);

        return true;
    }
}

