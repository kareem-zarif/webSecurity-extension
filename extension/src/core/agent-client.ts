import {
  CONTRACT_VERSION,
  type AgentHealthResponse,
  type ErrorResponse,
  type Finding,
  type ScanReport,
  type ScanSummary,
} from '../contracts';
import type { ExtensionConfig } from './config';

export class AgentConnectionError extends Error {
  public constructor(
    message: string,
    public readonly traceId?: string,
  ) {
    super(message);
    this.name = 'AgentConnectionError';
  }
}

export class AgentClient {
  public constructor(private readonly config: ExtensionConfig) {}

  public async getHealth(signal?: AbortSignal): Promise<AgentHealthResponse> {
    const timeoutSignal = AbortSignal.timeout(this.config.healthTimeoutMs);
    const requestSignal = signal === undefined
      ? timeoutSignal
      : AbortSignal.any([signal, timeoutSignal]);

    let response: Response;
    try {
      response = await fetch(new URL('/health', this.config.agentBaseUrl), {
        method: 'GET',
        headers: { Accept: 'application/json' },
        cache: 'no-store',
        credentials: 'omit',
        referrerPolicy: 'no-referrer',
        signal: requestSignal,
      });
    } catch (error: unknown) {
      if (requestSignal.aborted) {
        throw new AgentConnectionError('The local agent did not respond in time.');
      }

      throw new AgentConnectionError(
        error instanceof TypeError
          ? 'The local agent is unavailable. Start it and try again.'
          : 'The health check could not be completed.',
      );
    }

    if (!response.ok) {
      const problem = await tryReadErrorResponse(response);
      throw new AgentConnectionError(
        problem?.message ?? `The local agent returned HTTP ${response.status}.`,
        problem?.traceId,
      );
    }

    const payload: unknown = await response.json();
    if (!isAgentHealthResponse(payload)) {
      throw new AgentConnectionError('The local agent returned an unexpected health response.');
    }

    return payload;
  }

  public async runScan(targetOrigin: string, signal?: AbortSignal): Promise<ScanReport> {
    const timeoutSignal = AbortSignal.timeout(30_000);
    const requestSignal = signal === undefined
      ? timeoutSignal
      : AbortSignal.any([signal, timeoutSignal]);

    let response: Response;
    try {
      response = await fetch(new URL('/api/scans', this.config.agentBaseUrl), {
        method: 'POST',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          contractVersion: CONTRACT_VERSION,
          targetUrl: targetOrigin,
          authorizedOrigin: targetOrigin,
          authorizationConfirmed: true,
        }),
        cache: 'no-store',
        credentials: 'omit',
        referrerPolicy: 'no-referrer',
        signal: requestSignal,
      });
    } catch (error: unknown) {
      if (requestSignal.aborted) {
        throw new AgentConnectionError('The assessment was cancelled or did not finish in time.');
      }

      throw new AgentConnectionError(
        error instanceof TypeError
          ? 'The local agent became unavailable during the assessment.'
          : 'The assessment request could not be completed.',
      );
    }

    if (!response.ok) {
      const problem = await tryReadErrorResponse(response);
      throw new AgentConnectionError(
        problem?.message ?? `The local agent returned HTTP ${response.status}.`,
        problem?.traceId,
      );
    }

    const payload: unknown = await response.json();
    if (!isScanReport(payload)) {
      throw new AgentConnectionError('The local agent returned an unexpected assessment report.');
    }

    return payload;
  }
}

async function tryReadErrorResponse(response: Response): Promise<ErrorResponse | undefined> {
  try {
    const payload: unknown = await response.json();
    if (isObject(payload) &&
      payload.contractVersion === '1.0' &&
      typeof payload.errorCode === 'string' &&
      typeof payload.message === 'string' &&
      typeof payload.traceId === 'string') {
      return payload as unknown as ErrorResponse;
    }
  } catch {
    // The HTTP status still provides a safe fallback when the payload is not JSON.
  }

  return undefined;
}

function isAgentHealthResponse(value: unknown): value is AgentHealthResponse {
  return isObject(value) &&
    value.status === 'healthy' &&
    value.service === 'authorized-security-agent' &&
    typeof value.version === 'string' &&
    typeof value.utcTimestamp === 'string' &&
    !Number.isNaN(Date.parse(value.utcTimestamp));
}

function isScanReport(value: unknown): value is ScanReport {
  return isObject(value) &&
    value.contractVersion === CONTRACT_VERSION &&
    typeof value.scanId === 'string' &&
    typeof value.targetUrl === 'string' &&
    typeof value.startedAt === 'string' &&
    typeof value.completedAt === 'string' &&
    typeof value.scopeNote === 'string' &&
    Array.isArray(value.checksPerformed) &&
    value.checksPerformed.every((check: unknown) => typeof check === 'string') &&
    Array.isArray(value.findings) &&
    value.findings.every(isFinding) &&
    isScanSummary(value.summary);
}

function isScanSummary(value: unknown): value is ScanSummary {
  return isObject(value) &&
    ['totalChecks', 'totalFindings', 'critical', 'high', 'medium', 'low', 'informational']
      .every(key => typeof value[key] === 'number');
}

function isFinding(value: unknown): value is Finding {
  return isObject(value) &&
    value.contractVersion === CONTRACT_VERSION &&
    typeof value.id === 'string' &&
    typeof value.scanId === 'string' &&
    typeof value.ruleId === 'string' &&
    typeof value.title === 'string' &&
    typeof value.category === 'string' &&
    isSeverity(value.severity) &&
    isConfidence(value.confidence) &&
    typeof value.affectedUrl === 'string' &&
    typeof value.evidence === 'string' &&
    typeof value.riskDescription === 'string' &&
    typeof value.remediation === 'string' &&
    Array.isArray(value.references) &&
    value.references.every((reference: unknown) => typeof reference === 'string') &&
    value.status === 'open' &&
    typeof value.firstDetectedAt === 'string' &&
    typeof value.lastDetectedAt === 'string';
}

function isSeverity(value: unknown): boolean {
  return value === 'informational' || value === 'low' || value === 'medium' ||
    value === 'high' || value === 'critical';
}

function isConfidence(value: unknown): boolean {
  return value === 'low' || value === 'medium' || value === 'high';
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}
