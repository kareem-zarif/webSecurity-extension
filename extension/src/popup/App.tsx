import { useCallback, useEffect, useRef, useState } from 'react';
import type { AgentHealthResponse } from '../contracts';
import { AgentClient, AgentConnectionError } from '../core/agent-client';
import { loadExtensionConfig } from '../core/config';

type ConnectionState =
  | { readonly kind: 'loading' }
  | { readonly kind: 'available'; readonly health: AgentHealthResponse }
  | { readonly kind: 'unavailable'; readonly message: string; readonly traceId?: string };

export function App() {
  const [connection, setConnection] = useState<ConnectionState>({ kind: 'loading' });
  const requestController = useRef<AbortController | null>(null);

  const checkHealth = useCallback(async () => {
    requestController.current?.abort();
    const controller = new AbortController();
    requestController.current = controller;
    setConnection({ kind: 'loading' });

    try {
      const client = new AgentClient(loadExtensionConfig());
      const health = await client.getHealth(controller.signal);
      if (!controller.signal.aborted) {
        setConnection({ kind: 'available', health });
      }
    } catch (error: unknown) {
      if (controller.signal.aborted) {
        return;
      }

      const message = error instanceof Error
        ? error.message
        : 'The local agent health check failed.';
      const traceId = error instanceof AgentConnectionError ? error.traceId : undefined;
      setConnection(traceId === undefined
        ? { kind: 'unavailable', message }
        : { kind: 'unavailable', message, traceId });
    }
  }, []);

  useEffect(() => {
    void checkHealth();
    return () => requestController.current?.abort();
  }, [checkHealth]);

  return (
    <main className="popup-shell">
      <header className="brand">
        <span className="brand-mark" aria-hidden="true">AS</span>
        <div>
          <p className="eyebrow">Local security workspace</p>
          <h1>Authorized Assessment</h1>
        </div>
      </header>

      <section className={`status-card status-card--${connection.kind}`} aria-live="polite">
        <div className="status-heading">
          <span className="status-dot" aria-hidden="true" />
          <div>
            <p className="status-label">Local agent</p>
            <h2>{statusTitle(connection)}</h2>
          </div>
        </div>

        {connection.kind === 'loading' && (
          <p className="status-detail">Checking the loopback service…</p>
        )}

        {connection.kind === 'available' && (
          <dl className="health-details">
            <div>
              <dt>Version</dt>
              <dd>{connection.health.version}</dd>
            </div>
            <div>
              <dt>Checked</dt>
              <dd>{formatTimestamp(connection.health.utcTimestamp)}</dd>
            </div>
          </dl>
        )}

        {connection.kind === 'unavailable' && (
          <div className="error-detail">
            <p>{connection.message}</p>
            {connection.traceId !== undefined && (
              <p className="trace-id">Trace: {connection.traceId}</p>
            )}
          </div>
        )}

        <button type="button" onClick={() => void checkHealth()} disabled={connection.kind === 'loading'}>
          {connection.kind === 'loading' ? 'Checking…' : 'Check again'}
        </button>
      </section>

      <aside className="safety-note">
        <span aria-hidden="true">✓</span>
        <p>Assessment features remain locked to explicitly authorized targets.</p>
      </aside>
    </main>
  );
}

function statusTitle(state: ConnectionState): string {
  switch (state.kind) {
    case 'loading':
      return 'Connecting';
    case 'available':
      return 'Available';
    case 'unavailable':
      return 'Unavailable';
  }
}

function formatTimestamp(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(new Date(value));
}

