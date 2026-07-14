namespace AuthorizedSecurityAgent.Application.Contracts;

public sealed record Finding(
    Guid Id,
    Guid ScanId,
    string RuleId,
    string Title,
    string Category,
    Severity Severity,
    Confidence Confidence,
    Uri AffectedUrl,
    string? AffectedParameter,
    string Evidence,
    string RiskDescription,
    string Remediation,
    IReadOnlyList<Uri> References,
    FindingStatus Status,
    DateTimeOffset FirstDetectedAt,
    DateTimeOffset LastDetectedAt,
    string ContractVersion = Contracts.ContractVersion.Current);

public enum Severity
{
    Informational,
    Low,
    Medium,
    High,
    Critical
}

public enum Confidence
{
    Low,
    Medium,
    High
}

public enum FindingStatus
{
    Open,
    AcceptedRisk,
    FalsePositive,
    Resolved
}

