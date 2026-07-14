namespace AuthorizedSecurityAgent.Application.Contracts;

public sealed record AgentHealthResponse(
    string Status,
    string Service,
    string Version,
    DateTimeOffset UtcTimestamp);

