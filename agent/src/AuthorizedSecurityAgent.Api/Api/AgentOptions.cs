using System.ComponentModel.DataAnnotations;

namespace AuthorizedSecurityAgent.Api;

internal sealed class AgentOptions
{
    public const string SectionName = "Agent";

    [Range(1024, 65535)]
    public int Port { get; init; } = 17854;

    public string[] AllowedDevelopmentOrigins { get; init; } = [];

    public static bool IsLoopbackOrigin(string value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var origin))
        {
            return false;
        }

        var isSupportedScheme = origin.Scheme == Uri.UriSchemeHttp || origin.Scheme == Uri.UriSchemeHttps;
        var isOriginOnly = origin.AbsolutePath == "/" &&
                           string.IsNullOrEmpty(origin.Query) &&
                           string.IsNullOrEmpty(origin.Fragment) &&
                           string.IsNullOrEmpty(origin.UserInfo);

        return isSupportedScheme && origin.IsLoopback && isOriginOnly;
    }
}
