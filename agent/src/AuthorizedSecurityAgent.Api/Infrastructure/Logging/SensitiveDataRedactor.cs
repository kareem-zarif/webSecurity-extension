using System.Globalization;
using System.Text.RegularExpressions;

namespace AuthorizedSecurityAgent.Infrastructure.Logging;

internal sealed partial class SensitiveDataRedactor : ISensitiveDataRedactor
{
    public const string RedactedValue = "[REDACTED]";

    private static readonly HashSet<string> SensitivePropertyNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "authorization",
        "proxyauthorization",
        "cookie",
        "setcookie",
        "password",
        "passwd",
        "pwd",
        "token",
        "accesstoken",
        "refreshtoken",
        "idtoken",
        "apikey",
        "clientsecret",
        "session",
        "sessionid"
    };

    public object? RedactValue(string propertyName, object? value)
    {
        if (SensitivePropertyNames.Contains(NormalizePropertyName(propertyName)))
        {
            return RedactedValue;
        }

        return value switch
        {
            null => null,
            string text => RedactText(text),
            char character => character,
            bool boolean => boolean,
            byte or sbyte or short or ushort or int or uint or long or ulong or float or double or decimal => value,
            DateTime or DateTimeOffset or TimeSpan or Guid => value,
            _ => RedactText(Convert.ToString(value, CultureInfo.InvariantCulture) ?? string.Empty)
        };
    }

    public string RedactText(string value)
    {
        var redacted = BearerTokenPattern().Replace(value, $"Bearer {RedactedValue}");
        redacted = JwtPattern().Replace(redacted, RedactedValue);
        return SensitiveAssignmentPattern().Replace(redacted, match =>
            $"{match.Groups["key"].Value}={RedactedValue}");
    }

    private static string NormalizePropertyName(string value) =>
        NonAlphaNumericPattern().Replace(value, string.Empty);

    [GeneratedRegex(@"(?i)\bBearer\s+[A-Za-z0-9\-._~+/]+=*")]
    private static partial Regex BearerTokenPattern();

    [GeneratedRegex(@"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")]
    private static partial Regex JwtPattern();

    [GeneratedRegex(@"(?i)[""']?(?<key>authorization|proxy-authorization|cookie|set-cookie|password|passwd|pwd|access[_-]?token|refresh[_-]?token|id[_-]?token|api[_-]?key|client[_-]?secret|session(?:id)?)[""']?\s*[:=]\s*(?:[""'][^""']*[""']|[^\s,;]+)")]
    private static partial Regex SensitiveAssignmentPattern();

    [GeneratedRegex("[^A-Za-z0-9]")]
    private static partial Regex NonAlphaNumericPattern();
}

