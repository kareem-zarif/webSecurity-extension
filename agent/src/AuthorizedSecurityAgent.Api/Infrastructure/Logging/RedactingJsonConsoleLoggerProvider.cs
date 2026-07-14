using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.Json;

namespace AuthorizedSecurityAgent.Infrastructure.Logging;

[ProviderAlias("RedactingJsonConsole")]
internal sealed class RedactingJsonConsoleLoggerProvider(ISensitiveDataRedactor redactor)
    : ILoggerProvider, ISupportExternalScope
{
    private readonly ConcurrentDictionary<string, RedactingJsonConsoleLogger> _loggers = new(StringComparer.Ordinal);
    private IExternalScopeProvider _scopeProvider = new LoggerExternalScopeProvider();

    public ILogger CreateLogger(string categoryName) =>
        _loggers.GetOrAdd(categoryName, name => new RedactingJsonConsoleLogger(name, redactor, () => _scopeProvider));

    public void SetScopeProvider(IExternalScopeProvider scopeProvider) => _scopeProvider = scopeProvider;

    public void Dispose() => _loggers.Clear();
}

internal sealed class RedactingJsonConsoleLogger(
    string category,
    ISensitiveDataRedactor redactor,
    Func<IExternalScopeProvider> getScopeProvider) : ILogger
{
    private static readonly object ConsoleLock = new();
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);

    public IDisposable BeginScope<TState>(TState state) where TState : notnull =>
        getScopeProvider().Push(state);

    public bool IsEnabled(LogLevel logLevel) => logLevel != LogLevel.None;

    public void Log<TState>(
        LogLevel logLevel,
        EventId eventId,
        TState state,
        Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        if (!IsEnabled(logLevel))
        {
            return;
        }

        var properties = GetRedactedProperties(state);
        var activity = Activity.Current;
        var payload = new Dictionary<string, object?>
        {
            ["timestamp"] = DateTimeOffset.UtcNow,
            ["level"] = logLevel.ToString(),
            ["category"] = category,
            ["eventId"] = eventId.Id,
            ["message"] = redactor.RedactText(formatter(state, exception)),
            ["traceId"] = activity?.TraceId.ToString(),
            ["spanId"] = activity?.SpanId.ToString(),
            ["exceptionType"] = exception?.GetType().Name,
            ["properties"] = properties.Count == 0 ? null : properties
        };

        var output = JsonSerializer.Serialize(payload, SerializerOptions);
        lock (ConsoleLock)
        {
            Console.Out.WriteLine(output);
        }
    }

    private Dictionary<string, object?> GetRedactedProperties<TState>(TState state)
    {
        var properties = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        if (state is not IEnumerable<KeyValuePair<string, object?>> structuredState)
        {
            return properties;
        }

        foreach (var item in structuredState)
        {
            if (item.Key == "{OriginalFormat}")
            {
                continue;
            }

            properties[item.Key] = redactor.RedactValue(item.Key, item.Value);
        }

        return properties;
    }
}
