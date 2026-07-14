namespace AuthorizedSecurityAgent.Application.Contracts;

public sealed record ScanRequest(
    string TargetUrl,
    string AuthorizedOrigin,
    bool AuthorizationConfirmed,
    ScanMode Mode = ScanMode.Baseline,
    bool ActiveVerificationConfirmed = false,
    string ContractVersion = Contracts.ContractVersion.Current);

public enum ScanMode
{
    Baseline,
    ActiveVerification
}
