namespace AuthorizedSecurityAgent.Application.Contracts;

public sealed record ScanEvent(
    Guid EventId,
    Guid ScanId,
    ScanEventType EventType,
    DateTimeOffset OccurredAt,
    string? Message = null,
    int? ProgressPercent = null,
    string ContractVersion = Contracts.ContractVersion.Current);

public enum ScanEventType
{
    Queued,
    Started,
    Progress,
    Paused,
    Completed,
    Failed,
    Stopped
}

