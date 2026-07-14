namespace AuthorizedSecurityAgent.Application.Contracts;

public sealed record ErrorResponse(
    string ErrorCode,
    string Message,
    string TraceId,
    IReadOnlyDictionary<string, IReadOnlyList<string>>? Errors = null,
    string ContractVersion = Contracts.ContractVersion.Current);

