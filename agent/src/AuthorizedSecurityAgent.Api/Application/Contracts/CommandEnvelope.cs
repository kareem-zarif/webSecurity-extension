namespace AuthorizedSecurityAgent.Application.Contracts;

public sealed record CommandEnvelope<TPayload>(
    Guid CommandId,
    CommandType CommandType,
    TPayload Payload,
    string ContractVersion = Contracts.ContractVersion.Current);

public enum CommandType
{
    StartScan,
    StopScan,
    PauseScan,
    ResumeScan
}

