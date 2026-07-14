# Shared wire contracts

`protocol.schema.json` is the runtime-neutral reference for communication between the extension and the local agent.

The current contract version is `1.0`. The schema defines:

- command envelopes;
- scan-event envelopes;
- finding payloads;
- authorized scan requests, summaries, and reports;
- error responses.

TypeScript mirrors live in `extension/src/contracts`, and C# mirrors live in `agent/src/AuthorizedSecurityAgent.Api/Application/Contracts`. Keep JSON property names camel-cased and update all three representations in the same story whenever a wire contract changes.

Sensitive evidence must be redacted before it is assigned to one of these contracts. A contract definition is not authorization to persist or log its values.
