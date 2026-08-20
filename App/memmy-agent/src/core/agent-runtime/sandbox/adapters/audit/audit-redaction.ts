import type { SandboxAuditDetail, SandboxAuditEventDraft } from "../../domain/audit-event.js";
import { immutableSnapshot } from "../../domain/immutable.js";

const MAX_TEXT_CHARS = 256;
const REASON_CODE = /^[a-z0-9][a-z0-9._-]{0,127}$/i;
const SHA256 = /^[a-f0-9]{64}$/;
const APPROVAL_DECISIONS = ["approved", "denied", "cancelled", "expired", "invalid"] as const;
const ATTEMPT_STATES = ["completed", "denied", "cancelled", "runtime-failed"] as const;
const RESOURCE_LEASE_STATES = ["starting", "active", "revoking", "terminated", "failed"] as const;
const RESOURCE_TYPES = [
  "browser",
  "stdio-mcp",
  "http-mcp",
  "plugin-worker",
  "memory-writer",
  "exec-session",
  "goal",
  "cron",
] as const;
const SANDBOX_TYPES = [
  "macos-seatbelt",
  "linux-bwrap",
  "linux-landlock",
  "windows-restricted-token",
  "external",
  "disabled",
] as const;

function containsControlCharacter(value: string): boolean {
  return [...value].some((character) => {
    const codePoint = character.codePointAt(0)!;
    return codePoint <= 0x1f || codePoint === 0x7f;
  });
}

function requireText(value: string, label: string): void {
  if (
    !value ||
    value.length > MAX_TEXT_CHARS ||
    value !== value.trim() ||
    containsControlCharacter(value)
  ) {
    throw new Error(`${label} must be a bounded audit identifier`);
  }
}

function requireHash(value: string, label: string): void {
  if (!SHA256.test(value)) throw new Error(`${label} must be a SHA-256 hash`);
}

function requireTimestamp(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} must be a non-negative Unix millisecond timestamp`);
  }
}

function requireAllowedValue(value: string, allowed: readonly string[], label: string): void {
  if (!allowed.includes(value)) throw new Error(`${label} is not an allowed audit value`);
}

function validateDetail(detail: SandboxAuditDetail): void {
  switch (detail.kind) {
    case "preflight-approval-requested":
      requireText(detail.requestId, "requestId");
      requireHash(detail.argsHash, "argsHash");
      requireHash(detail.initialPolicyHash, "initialPolicyHash");
      requireText(detail.subjectId, "subjectId");
      requireTimestamp(detail.expiresAt, "expiresAt");
      return;
    case "preflight-approval-decided":
      requireText(detail.requestId, "requestId");
      requireAllowedValue(detail.decision, APPROVAL_DECISIONS, "decision");
      return;
    case "approval-requested":
      requireText(detail.requestId, "requestId");
      requireText(detail.parentAttemptId, "parentAttemptId");
      requireHash(detail.argsHash, "argsHash");
      requireHash(detail.initialPolicyHash, "initialPolicyHash");
      requireText(detail.subjectId, "subjectId");
      requireTimestamp(detail.expiresAt, "expiresAt");
      return;
    case "approval-decided":
      requireText(detail.requestId, "requestId");
      requireText(detail.parentAttemptId, "parentAttemptId");
      requireAllowedValue(detail.decision, APPROVAL_DECISIONS, "decision");
      return;
    case "approval-grant-issued":
      requireText(detail.grantId, "grantId");
      requireText(detail.parentAttemptId, "parentAttemptId");
      requireHash(detail.approvalGrantHash, "approvalGrantHash");
      requireTimestamp(detail.expiresAt, "expiresAt");
      return;
    case "retry-planned":
      requireText(detail.attemptId, "attemptId");
      requireText(detail.parentAttemptId, "parentAttemptId");
      requireHash(detail.approvalGrantHash, "approvalGrantHash");
      requireHash(detail.compiledPolicyHash, "compiledPolicyHash");
      requireAllowedValue(detail.sandboxType, SANDBOX_TYPES, "sandboxType");
      return;
    case "approval-grant-consumed":
      requireText(detail.grantId, "grantId");
      requireText(detail.attemptId, "attemptId");
      requireText(detail.parentAttemptId, "parentAttemptId");
      requireHash(detail.approvalGrantHash, "approvalGrantHash");
      return;
    case "attempt-finished":
      requireText(detail.attemptId, "attemptId");
      if (detail.parentAttemptId) requireText(detail.parentAttemptId, "parentAttemptId");
      requireHash(detail.compiledPolicyHash, "compiledPolicyHash");
      requireAllowedValue(detail.sandboxType, SANDBOX_TYPES, "sandboxType");
      requireAllowedValue(detail.state, ATTEMPT_STATES, "state");
      requireTimestamp(detail.stateObservedAt, "stateObservedAt");
      if (detail.reasonCode && !REASON_CODE.test(detail.reasonCode)) {
        throw new Error("reasonCode must be a normalized code");
      }
      if (detail.evidenceRef) requireHash(detail.evidenceRef, "evidenceRef");
      if (
        detail.exitCode !== undefined &&
        detail.exitCode !== null &&
        !Number.isSafeInteger(detail.exitCode)
      ) {
        throw new Error("exitCode must be an integer or null");
      }
      if (detail.outputTruncated !== undefined && typeof detail.outputTruncated !== "boolean") {
        throw new Error("outputTruncated must be a boolean");
      }
      return;
    case "resource-lease-state":
      requireText(detail.leaseId, "leaseId");
      requireText(detail.resourceId, "resourceId");
      requireAllowedValue(detail.resourceType, RESOURCE_TYPES, "resourceType");
      requireAllowedValue(detail.state, RESOURCE_LEASE_STATES, "state");
      requireHash(detail.compiledPolicyHash, "compiledPolicyHash");
      requireHash(detail.backendCapabilityHash, "backendCapabilityHash");
      requireTimestamp(detail.expiresAt, "expiresAt");
      if (detail.reasonCode && !REASON_CODE.test(detail.reasonCode)) {
        throw new Error("reasonCode must be a normalized code");
      }
      return;
    default:
      throw new Error("unsupported sandbox audit event kind");
  }
}

export function redactAuditDraft(draft: SandboxAuditEventDraft): SandboxAuditEventDraft {
  requireText(draft.runtimeCallId, "runtimeCallId");
  validateDetail(draft.detail);
  return immutableSnapshot(draft);
}
