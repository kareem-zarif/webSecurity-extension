import type { AgentHealthResponse, ErrorResponse } from '../contracts';
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

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

