import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { AgentHealthResponse, Finding, ScanReport, Severity } from '../contracts';
import { AgentClient, AgentConnectionError } from '../core/agent-client';
import { loadExtensionConfig } from '../core/config';

type ConnectionState =
  | { readonly kind: 'loading' }
  | { readonly kind: 'available'; readonly health: AgentHealthResponse }
  | { readonly kind: 'unavailable'; readonly message: string; readonly traceId?: string };

type ScanState =
  | { readonly kind: 'idle' }
  | { readonly kind: 'running' }
  | { readonly kind: 'complete'; readonly report: ScanReport }
  | { readonly kind: 'error'; readonly message: string; readonly traceId?: string };

const severityOrder: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'informational'];

export function App() {
  const [connection, setConnection] = useState<ConnectionState>({ kind: 'loading' });
  const [targetOrigin, setTargetOrigin] = useState('');
  const [authorizationConfirmed, setAuthorizationConfirmed] = useState(false);
  const [scan, setScan] = useState<ScanState>({ kind: 'idle' });
  const healthController = useRef<AbortController | null>(null);
  const scanController = useRef<AbortController | null>(null);

  const checkHealth = useCallback(async () => {
    healthController.current?.abort();
    const controller = new AbortController();
    healthController.current = controller;
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

  const useCurrentPage = useCallback(async () => {
    const currentOrigin = await getCurrentTabOrigin();
    if (currentOrigin !== undefined) {
      setTargetOrigin(currentOrigin);
      setAuthorizationConfirmed(false);
      setScan({ kind: 'idle' });
    }
  }, []);

  useEffect(() => {
    void checkHealth();
    void useCurrentPage();
    return () => {
      healthController.current?.abort();
      scanController.current?.abort();
    };
  }, [checkHealth, useCurrentPage]);

  const normalizedTarget = useMemo(() => normalizeOrigin(targetOrigin), [targetOrigin]);
  const targetHost = normalizedTarget === undefined ? 'this exact website' : new URL(normalizedTarget).host;
  const canScan = connection.kind === 'available' &&
    normalizedTarget !== undefined &&
    authorizationConfirmed &&
    scan.kind !== 'running';

  const runScan = async () => {
    if (!authorizationConfirmed) {
      setScan({ kind: 'error', message: 'Confirm written authorization before starting an assessment.' });
      return;
    }

    if (normalizedTarget === undefined) {
      setScan({ kind: 'error', message: 'Enter a valid HTTP or HTTPS website origin.' });
      return;
    }

    if (connection.kind !== 'available') {
      setScan({ kind: 'error', message: 'Start the local agent and verify its connection first.' });
      return;
    }

    scanController.current?.abort();
    const controller = new AbortController();
    scanController.current = controller;
    setScan({ kind: 'running' });

    try {
      const report = await new AgentClient(loadExtensionConfig()).runScan(normalizedTarget, controller.signal);
      if (!controller.signal.aborted) {
        setScan({ kind: 'complete', report });
      }
    } catch (error: unknown) {
      if (controller.signal.aborted) {
        return;
      }

      const message = error instanceof Error ? error.message : 'The assessment failed.';
      const traceId = error instanceof AgentConnectionError ? error.traceId : undefined;
      setScan(traceId === undefined
        ? { kind: 'error', message }
        : { kind: 'error', message, traceId });
    }
  };

  return (
    <main className="popup-shell">
      <header className="brand">
        <span className="brand-mark" aria-hidden="true">AS</span>
        <div>
          <p className="eyebrow">Authorized security workspace</p>
          <h1>Website Assessment</h1>
        </div>
      </header>

      <AgentStatus connection={connection} onRetry={checkHealth} />

      <section className="assessment-card" aria-labelledby="assessment-title">
        <div className="section-heading">
          <div>
            <p className="step-label">Assessment target</p>
            <h2 id="assessment-title">Test an authorized website</h2>
          </div>
          <span className="coverage-badge">12 checks</span>
        </div>

        <label className="field-label" htmlFor="target-origin">Exact website origin</label>
        <div className="target-row">
          <input
            id="target-origin"
            type="url"
            value={targetOrigin}
            placeholder="https://client.example"
            spellCheck="false"
            onChange={event => {
              setTargetOrigin(event.target.value);
              setAuthorizationConfirmed(false);
              setScan({ kind: 'idle' });
            }}
          />
          <button className="secondary-button current-page-button" type="button" onClick={() => void useCurrentPage()}>
            Current
          </button>
        </div>
        {targetOrigin.length > 0 && normalizedTarget === undefined && (
          <p className="field-error">Use an HTTP(S) origin without a path, query, credentials, or fragment.</p>
        )}

        <label className="authorization-check">
          <input
            type="checkbox"
            checked={authorizationConfirmed}
            onChange={event => setAuthorizationConfirmed(event.target.checked)}
          />
          <span>
            I own <strong>{targetHost}</strong> or have explicit written permission to assess it.
          </span>
        </label>

        <details className="coverage-details">
          <summary>What this assessment checks</summary>
          <p>
            HTTPS and HSTS, CSP, clickjacking, MIME sniffing, referrer and permissions policies,
            cookie flags, CORS, technology disclosure, mixed content, insecure forms, and script integrity.
          </p>
          <p>
            It sends one unauthenticated GET request and follows only same-origin redirects. It does not use
            browser cookies, exploit payloads, credential attacks, brute force, persistence, or denial of service.
          </p>
        </details>

        <button className="primary-button" type="button" onClick={() => void runScan()} disabled={!canScan}>
          {scan.kind === 'running' ? 'Assessing safely…' : 'Run authorized assessment'}
        </button>

        {scan.kind === 'error' && (
          <div className="inline-error" role="alert">
            <strong>Assessment could not start</strong>
            <span>{scan.message}</span>
            {scan.traceId !== undefined && <code>Trace: {scan.traceId}</code>}
          </div>
        )}
      </section>

      {scan.kind === 'complete' && <AssessmentReport report={scan.report} />}

      <aside className="safety-note">
        <span aria-hidden="true">✓</span>
        <p>Review findings manually before sending them to a client; automated checks can require contextual validation.</p>
      </aside>
    </main>
  );
}

interface AgentStatusProps {
  readonly connection: ConnectionState;
  readonly onRetry: () => Promise<void>;
}

function AgentStatus({ connection, onRetry }: AgentStatusProps) {
  return (
    <section className={`agent-strip agent-strip--${connection.kind}`} aria-live="polite">
      <span className="status-dot" aria-hidden="true" />
      <div className="agent-copy">
        <span>Local agent</span>
        <strong>{statusTitle(connection)}</strong>
      </div>
      {connection.kind === 'available' && <small>v{connection.health.version}</small>}
      {connection.kind !== 'available' && (
        <button className="text-button" type="button" onClick={() => void onRetry()} disabled={connection.kind === 'loading'}>
          {connection.kind === 'loading' ? 'Checking…' : 'Check again'}
        </button>
      )}
    </section>
  );
}

function AssessmentReport({ report }: { readonly report: ScanReport }) {
  return (
    <section className="report-card" aria-labelledby="report-title">
      <div className="section-heading report-heading">
        <div>
          <p className="step-label">Assessment report</p>
          <h2 id="report-title">{report.summary.totalFindings} finding{report.summary.totalFindings === 1 ? '' : 's'}</h2>
        </div>
        <span className="report-time">{formatTimestamp(report.completedAt)}</span>
      </div>

      <div className="severity-summary" aria-label="Finding counts by severity">
        {severityOrder.map(severity => (
          <div className={`severity-count severity-count--${severity}`} key={severity}>
            <strong>{countForSeverity(report, severity)}</strong>
            <span>{severity === 'informational' ? 'Info' : capitalize(severity)}</span>
          </div>
        ))}
      </div>

      <div className="report-actions">
        <button className="secondary-button" type="button" onClick={() => downloadJsonReport(report)}>Export JSON</button>
        <button className="secondary-button" type="button" onClick={() => downloadHtmlReport(report)}>Client report</button>
      </div>

      {report.findings.length === 0 ? (
        <div className="empty-report">
          <strong>No issues detected by these checks</strong>
          <p>This does not prove the application is vulnerability-free; authenticated workflows and business logic still need manual testing.</p>
        </div>
      ) : (
        <div className="finding-list">
          {report.findings.map(finding => <FindingDetails finding={finding} key={finding.id} />)}
        </div>
      )}

      <details className="scope-details">
        <summary>Scope and checks performed</summary>
        <p>{report.scopeNote}</p>
        <ul>
          {report.checksPerformed.map(check => <li key={check}>{check}</li>)}
        </ul>
      </details>
    </section>
  );
}

function FindingDetails({ finding }: { readonly finding: Finding }) {
  return (
    <details className={`finding finding--${finding.severity}`}>
      <summary>
        <span className={`severity-pill severity-pill--${finding.severity}`}>{finding.severity}</span>
        <span>{finding.title}</span>
      </summary>
      <div className="finding-body">
        <dl>
          <div><dt>Category</dt><dd>{finding.category}</dd></div>
          <div><dt>Confidence</dt><dd>{capitalize(finding.confidence)}</dd></div>
        </dl>
        <h3>Evidence</h3>
        <p>{finding.evidence}</p>
        <h3>Why it matters</h3>
        <p>{finding.riskDescription}</p>
        <h3>Recommended fix</h3>
        <p>{finding.remediation}</p>
        {finding.references[0] !== undefined && (
          <a href={finding.references[0]} target="_blank" rel="noreferrer">Technical reference ↗</a>
        )}
      </div>
    </details>
  );
}

async function getCurrentTabOrigin(): Promise<string | undefined> {
  if (typeof chrome === 'undefined' || chrome.tabs?.query === undefined) {
    return undefined;
  }

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return originFromPage(tab?.url ?? '');
}

function originFromPage(value: string): string | undefined {
  try {
    const parsed = new URL(value);
    if ((parsed.protocol !== 'http:' && parsed.protocol !== 'https:') ||
      parsed.username.length > 0 ||
      parsed.password.length > 0) {
      return undefined;
    }

    return `${parsed.origin}/`;
  } catch {
    return undefined;
  }
}

function normalizeOrigin(value: string): string | undefined {
  try {
    const parsed = new URL(value.trim());
    if ((parsed.protocol !== 'http:' && parsed.protocol !== 'https:') ||
      parsed.username.length > 0 ||
      parsed.password.length > 0 ||
      parsed.pathname !== '/' ||
      parsed.search.length > 0 ||
      parsed.hash.length > 0) {
      return undefined;
    }

    return `${parsed.origin}/`;
  } catch {
    return undefined;
  }
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

function countForSeverity(report: ScanReport, severity: Severity): number {
  return severity === 'informational' ? report.summary.informational : report.summary[severity];
}

function capitalize(value: string): string {
  return `${value.charAt(0).toUpperCase()}${value.slice(1)}`;
}

function formatTimestamp(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(new Date(value));
}

function downloadJsonReport(report: ScanReport): void {
  downloadFile(
    `authorized-assessment-${safeHost(report.targetUrl)}.json`,
    JSON.stringify(report, null, 2),
    'application/json',
  );
}

function downloadHtmlReport(report: ScanReport): void {
  const findings = report.findings.map(finding => `
    <section class="finding ${escapeHtml(finding.severity)}">
      <p class="severity">${escapeHtml(finding.severity.toUpperCase())} · ${escapeHtml(finding.category)}</p>
      <h2>${escapeHtml(finding.title)}</h2>
      <h3>Evidence</h3><p>${escapeHtml(finding.evidence)}</p>
      <h3>Risk</h3><p>${escapeHtml(finding.riskDescription)}</p>
      <h3>Recommended fix</h3><p>${escapeHtml(finding.remediation)}</p>
    </section>`).join('');

  const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authorized assessment report</title><style>
body{max-width:920px;margin:40px auto;padding:0 24px;color:#17211e;font:15px/1.55 system-ui,sans-serif}
h1{margin-bottom:4px}.meta{color:#5d6966}.summary{display:flex;gap:12px;flex-wrap:wrap;margin:28px 0}
.summary span{padding:10px 14px;border:1px solid #dce4e0;border-radius:10px}.finding{margin:18px 0;padding:22px;border:1px solid #dce4e0;border-left:6px solid #71807b;border-radius:12px}
.finding.critical,.finding.high{border-left-color:#b73737}.finding.medium{border-left-color:#ba7520}.finding.low{border-left-color:#426f9d}.severity{font-weight:700;text-transform:uppercase;letter-spacing:.06em;font-size:12px}h2{margin-top:0}h3{margin-bottom:4px;font-size:14px}.scope{margin-top:32px;padding:18px;background:#f1f5f3;border-radius:12px}
</style></head><body>
<h1>Authorized Website Security Assessment</h1>
<p class="meta">Target: ${escapeHtml(report.targetUrl)} · Completed: ${escapeHtml(new Date(report.completedAt).toLocaleString())} · Scan: ${escapeHtml(report.scanId)}</p>
<div class="summary"><span><strong>${report.summary.totalFindings}</strong> findings</span><span><strong>${report.summary.high}</strong> high</span><span><strong>${report.summary.medium}</strong> medium</span><span><strong>${report.summary.low}</strong> low</span><span><strong>${report.summary.informational}</strong> info</span></div>
${findings || '<section class="finding"><h2>No issues detected by the automated checks</h2><p>This result does not prove the application is vulnerability-free.</p></section>'}
<section class="scope"><h2>Scope</h2><p>${escapeHtml(report.scopeNote)}</p><p>Automated results require manual validation before client delivery.</p></section>
</body></html>`;

  downloadFile(`authorized-assessment-${safeHost(report.targetUrl)}.html`, html, 'text/html');
}

function downloadFile(fileName: string, content: string, contentType: string): void {
  const url = URL.createObjectURL(new Blob([content], { type: `${contentType};charset=utf-8` }));
  const link = document.createElement('a');
  link.href = url;
  link.download = fileName;
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1_000);
}

function safeHost(value: string): string {
  try {
    return new URL(value).host.replace(/[^a-z0-9.-]/gi, '_');
  } catch {
    return 'website';
  }
}

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}
