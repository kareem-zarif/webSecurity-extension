namespace AuthorizedSecurityAgent.Infrastructure.Logging;

internal interface ISensitiveDataRedactor
{
    object? RedactValue(string propertyName, object? value);

    string RedactText(string value);
}

