namespace AuthorizedSecurityAgent.Infrastructure.Errors;

internal static class ErrorMessages
{
    public const string UnexpectedError = "The local agent could not complete the request.";

    public static string ForStatus(int statusCode) => statusCode switch
    {
        StatusCodes.Status400BadRequest => "The request is invalid.",
        StatusCodes.Status401Unauthorized => "The request is not authorized.",
        StatusCodes.Status403Forbidden => "The request is not permitted.",
        StatusCodes.Status404NotFound => "The requested local-agent route does not exist.",
        StatusCodes.Status405MethodNotAllowed => "The HTTP method is not supported for this route.",
        StatusCodes.Status429TooManyRequests => "The local-agent request limit was exceeded.",
        _ => "The local agent returned an error."
    };
}

