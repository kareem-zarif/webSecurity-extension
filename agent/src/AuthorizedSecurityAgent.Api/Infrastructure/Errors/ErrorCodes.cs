namespace AuthorizedSecurityAgent.Infrastructure.Errors;

internal static class ErrorCodes
{
    public const string UnexpectedError = "unexpected-error";

    public static string ForStatus(int statusCode) => statusCode switch
    {
        StatusCodes.Status400BadRequest => "bad-request",
        StatusCodes.Status401Unauthorized => "unauthorized",
        StatusCodes.Status403Forbidden => "forbidden",
        StatusCodes.Status404NotFound => "route-not-found",
        StatusCodes.Status405MethodNotAllowed => "method-not-allowed",
        StatusCodes.Status429TooManyRequests => "rate-limit-exceeded",
        _ => $"http-{statusCode}"
    };
}

