namespace AuthorizedSecurityAgent.Application.Contracts;

public sealed record ScanReport(
    Guid ScanId,
    Uri TargetUrl,
    DateTimeOffset StartedAt,
    DateTimeOffset CompletedAt,
    ScanSummary Summary,
    IReadOnlyList<string> ChecksPerformed,
    IReadOnlyList<Finding> Findings,
    string ScopeNote,
    string ContractVersion = Contracts.ContractVersion.Current);

public sealed record ScanSummary(
    int TotalChecks,
    int TotalFindings,
    int Critical,
    int High,
    int Medium,
    int Low,
    int Informational);
