namespace AuthorizedSecurityAgent.Application.Contracts;

public sealed record ScanRequest(
    string TargetUrl,
    string AuthorizedOrigin,
    bool AuthorizationConfirmed,
    string ContractVersion = Contracts.ContractVersion.Current);
