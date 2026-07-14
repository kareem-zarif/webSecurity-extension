const DEFAULT_HEALTH_TIMEOUT_MS = 3_000;
const MINIMUM_HEALTH_TIMEOUT_MS = 500;
const MAXIMUM_HEALTH_TIMEOUT_MS = 15_000;

export interface ExtensionConfig {
  readonly agentBaseUrl: URL;
  readonly healthTimeoutMs: number;
}

export function loadExtensionConfig(): ExtensionConfig {
  const agentBaseUrl = parseLoopbackUrl(import.meta.env.VITE_AGENT_BASE_URL);
  const healthTimeoutMs = parseHealthTimeout(import.meta.env.VITE_AGENT_HEALTH_TIMEOUT_MS);

  return { agentBaseUrl, healthTimeoutMs };
}

function parseLoopbackUrl(value: string | undefined): URL {
  if (value === undefined || value.trim().length === 0) {
    throw new Error('The local agent URL is not configured.');
  }

  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error('The local agent URL is invalid.');
  }

  const isLoopbackHost =
    url.hostname === 'localhost' ||
    url.hostname === '127.0.0.1' ||
    url.hostname === '[::1]';
  const isSupportedProtocol = url.protocol === 'http:' || url.protocol === 'https:';

  if (!isLoopbackHost || !isSupportedProtocol) {
    throw new Error('The local agent URL must use HTTP(S) on a loopback address.');
  }

  if (url.username.length > 0 || url.password.length > 0 || url.search.length > 0 || url.hash.length > 0) {
    throw new Error('The local agent URL cannot contain credentials, a query, or a fragment.');
  }

  url.pathname = url.pathname.replace(/\/$/, '');
  return url;
}

function parseHealthTimeout(value: string | undefined): number {
  if (value === undefined || value.trim().length === 0) {
    return DEFAULT_HEALTH_TIMEOUT_MS;
  }

  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < MINIMUM_HEALTH_TIMEOUT_MS || parsed > MAXIMUM_HEALTH_TIMEOUT_MS) {
    throw new Error(
      `The health-check timeout must be an integer from ${MINIMUM_HEALTH_TIMEOUT_MS} to ${MAXIMUM_HEALTH_TIMEOUT_MS} milliseconds.`,
    );
  }

  return parsed;
}

