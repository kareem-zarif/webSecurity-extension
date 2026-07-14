# Authorized Web Security Assessment Extension

This repository contains a local-first browser extension and security agent for authorized defensive web assessment. The MVP is implemented one SFD story at a time. The current implementation covers **SEC-001 — Initialize the solution**.

## Safety boundary

The product is only for targets the tester owns or is explicitly authorized to assess. It must never perform unrestricted scanning, destructive exploitation, credential attacks, denial of service, stealth, persistence, arbitrary command execution, or extraction of real application data.

The local agent listens only on the loopback interfaces. Log messages are emitted through a redacting structured logger, and request bodies, headers, cookies, query strings, and raw exception messages are never logged.

## Repository layout

- `extension/` — Manifest V3 React/TypeScript browser extension.
- `agent/` — .NET 10 ASP.NET Core local agent.
- `contracts/` — language-neutral JSON Schema definitions shared by both applications.

## Prerequisites

- Node.js 22 or newer and npm.
- .NET SDK 10.
- Chromium, Chrome, or Edge for loading the unpacked extension.

## Run the local agent

```powershell
dotnet run --project agent/src/AuthorizedSecurityAgent.Api
```

The agent binds to `http://localhost:17854` on loopback only. Its health endpoint is:

```text
GET http://127.0.0.1:17854/health
```

The port is configured through `Agent:Port` in the agent settings. Environment variables use the standard double-underscore format, for example `Agent__Port=17855`.

## Run the extension UI locally

```powershell
cd extension
npm install
npm run dev
```

Open the Vite URL to preview the popup. It automatically checks the local agent and exposes loading, available, and unavailable states.

To load the actual extension:

```powershell
cd extension
npm run build
```

Then open the browser's extensions page, enable developer mode, choose **Load unpacked**, and select `extension/dist`. Start the local agent before using **Check again** in the popup.

## Configuration

Extension environment files define `VITE_AGENT_BASE_URL` and `VITE_AGENT_HEALTH_TIMEOUT_MS`. The extension rejects any agent URL that is not HTTP(S) loopback. Do not place secrets in `VITE_` variables because Vite embeds them in the browser bundle.

Agent settings define the fixed loopback port and development-only CORS origins. Production does not enable cross-origin web origins; Manifest V3 host permissions allow the unpacked/installed extension to call the loopback agent directly.

## Logging and errors

The agent writes one JSON object per log event. Sensitive property names and recognizable bearer/JWT values are replaced with `[REDACTED]`. The application intentionally logs endpoint display names instead of raw URLs, so query-string credentials cannot enter logs. Central error handling returns the shared `ErrorResponse` shape with a trace identifier and a generic message; raw exception messages and stack traces are not returned or logged.

## Shared contracts

`contracts/protocol.schema.json` is the language-neutral wire-contract reference. Equivalent TypeScript and C# records are kept in each application so neither runtime requires generated code during SEC-001. Contract version `1.0` is sent in envelopes and error responses. Later contract changes must remain backward-compatible or introduce a new explicit version.

## Validation

SEC-001 can be validated without automated test files, as required by the SFD:

```powershell
npm --prefix extension run typecheck
npm --prefix extension run build
dotnet build agent/AuthorizedSecurityAgent.sln
```

