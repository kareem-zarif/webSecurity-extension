namespace AuthorizedSecurityAgent.Application.Contracts;

public sealed record ScanRequest(
    string TargetUrl,
    string AuthorizedOrigin,
    bool AuthorizationConfirmed,
    ScanMode Mode = ScanMode.Baseline,
    bool ActiveVerificationConfirmed = false,
    bool LabExploitationConfirmed = false,
    LabScanProfile? LabProfile = null,
    string ContractVersion = Contracts.ContractVersion.Current);

public enum ScanMode
{
    Baseline,
    ActiveVerification,
    LabExploitation
}

public sealed record LabScanProfile(
    string XssPath,
    string XssParameter,
    string SqlPath,
    string SqlParameter,
    string SqlBaselineValue,
    string CommandPath,
    string CommandParameter,
    string SsrfPath,
    string SsrfParameter,
    string SsrfCanaryUrl,
    string SsrfExpectedMarker,
    string TraversalPath,
    string TraversalParameter,
    string TraversalPayload,
    string TraversalExpectedMarker,
    string UploadPath,
    string UploadFieldName,
    string UploadRetrievalPathTemplate,
    string IdorPathTemplate,
    string IdorOwnResourceId,
    string IdorOtherResourceId,
    string AccountAToken,
    string AccountBToken,
    int RequestsPerSecond = 2);
