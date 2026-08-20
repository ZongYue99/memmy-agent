import type { SandboxType } from "./sandbox-attempt.js";

export type ApprovalAuditDecision = "approved" | "denied" | "cancelled" | "expired" | "invalid";

export type AuditAttemptState = "completed" | "denied" | "cancelled" | "runtime-failed";

export type SandboxAuditDetail =
  | Readonly<{
      kind: "approval-requested";
      requestId: string;
      parentAttemptId: string;
      argsHash: string;
      initialPolicyHash: string;
      subjectId: string;
      expiresAt: number;
    }>
  | Readonly<{
      kind: "approval-decided";
      requestId: string;
      parentAttemptId: string;
      decision: ApprovalAuditDecision;
    }>
  | Readonly<{
      kind: "approval-grant-issued";
      grantId: string;
      parentAttemptId: string;
      approvalGrantHash: string;
      expiresAt: number;
    }>
  | Readonly<{
      kind: "retry-planned";
      attemptId: string;
      parentAttemptId: string;
      approvalGrantHash: string;
      compiledPolicyHash: string;
      sandboxType: SandboxType;
    }>
  | Readonly<{
      kind: "approval-grant-consumed";
      grantId: string;
      attemptId: string;
      parentAttemptId: string;
      approvalGrantHash: string;
    }>
  | Readonly<{
      kind: "attempt-finished";
      attemptId: string;
      parentAttemptId?: string;
      compiledPolicyHash: string;
      sandboxType: SandboxType;
      state: AuditAttemptState;
      stateObservedAt: number;
      reasonCode?: string;
      evidenceRef?: string;
      exitCode?: number | null;
      outputTruncated?: boolean;
    }>;

export type SandboxAuditEventDraft = Readonly<{
  runtimeCallId: string;
  detail: SandboxAuditDetail;
}>;

export type SandboxAuditEvent = SandboxAuditEventDraft &
  Readonly<{
    version: 1;
    auditId: string;
    recordedAt: number;
  }>;
