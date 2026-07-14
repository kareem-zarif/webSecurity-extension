export const CONTRACT_VERSION = '1.0' as const;

export type ContractVersion = typeof CONTRACT_VERSION;

export type CommandType =
  | 'start-scan'
  | 'stop-scan'
  | 'pause-scan'
  | 'resume-scan';

export interface CommandEnvelope<TPayload extends Record<string, unknown>> {
  readonly contractVersion: ContractVersion;
  readonly commandId: string;
  readonly commandType: CommandType;
  readonly payload: TPayload;
}

export type ScanEventType =
  | 'queued'
  | 'started'
  | 'progress'
  | 'paused'
  | 'completed'
  | 'failed'
  | 'stopped';

export interface ScanEvent {
  readonly contractVersion: ContractVersion;
  readonly eventId: string;
  readonly scanId: string;
  readonly eventType: ScanEventType;
  readonly occurredAt: string;
  readonly message?: string | null;
  readonly progressPercent?: number | null;
}

export type Severity = 'informational' | 'low' | 'medium' | 'high' | 'critical';
export type Confidence = 'low' | 'medium' | 'high';
export type FindingStatus = 'open' | 'accepted-risk' | 'false-positive' | 'resolved';

export interface Finding {
  readonly contractVersion: ContractVersion;
  readonly id: string;
  readonly scanId: string;
  readonly ruleId: string;
  readonly title: string;
  readonly category: string;
  readonly severity: Severity;
  readonly confidence: Confidence;
  readonly affectedUrl: string;
  readonly affectedParameter?: string | null;
  readonly testMethod: string;
  readonly evidence: string;
  readonly riskDescription: string;
  readonly remediation: string;
  readonly references: readonly string[];
  readonly status: FindingStatus;
  readonly firstDetectedAt: string;
  readonly lastDetectedAt: string;
}

export interface ErrorResponse {
  readonly contractVersion: ContractVersion;
  readonly errorCode: string;
  readonly message: string;
  readonly traceId: string;
  readonly errors?: Readonly<Record<string, readonly string[]>>;
}

export interface AgentHealthResponse {
  readonly status: 'healthy';
  readonly service: 'authorized-security-agent';
  readonly version: string;
  readonly utcTimestamp: string;
}

export interface ScanRequest {
  readonly contractVersion: ContractVersion;
  readonly targetUrl: string;
  readonly authorizedOrigin: string;
  readonly authorizationConfirmed: boolean;
  readonly mode: ScanMode;
  readonly activeVerificationConfirmed: boolean;
}

export type ScanMode = 'baseline' | 'active-verification';

export interface ScanSummary {
  readonly totalChecks: number;
  readonly requestsSent: number;
  readonly totalFindings: number;
  readonly critical: number;
  readonly high: number;
  readonly medium: number;
  readonly low: number;
  readonly informational: number;
}

export interface ScanReport {
  readonly contractVersion: ContractVersion;
  readonly scanId: string;
  readonly targetUrl: string;
  readonly mode: ScanMode;
  readonly startedAt: string;
  readonly completedAt: string;
  readonly summary: ScanSummary;
  readonly checksPerformed: readonly string[];
  readonly findings: readonly Finding[];
  readonly scopeNote: string;
}
