import { randomBytes } from "node:crypto";
import type { ResolvedAccessSet } from "../domain/capability.js";
import type { ApprovalAuditDecision } from "../domain/audit-event.js";
import { immutableSnapshot } from "../domain/immutable.js";
import type { ApprovalChannelPort } from "../ports/approval-channel-port.js";
import type { ApprovalGrantStorePort } from "../ports/approval-grant-store-port.js";
import type { AuditPort } from "../ports/audit-port.js";
import type { ClockPort } from "../ports/clock-port.js";
import type { IdGeneratorPort } from "../ports/id-generator-port.js";
import type { ApprovalGrant, ApprovalGrantBinding } from "./approval-grant.js";
import { attachApprovalGrantHash } from "./approval-grant.js";

const DEFAULT_APPROVAL_TTL_MS = 60_000;

export type ApprovalOutcome =
  | Readonly<{ kind: "approved"; grant: ApprovalGrant }>
  | Readonly<{ kind: "denied" | "cancelled" | "expired" | "invalid-response" }>;

type ApprovalBrokerOptions = Readonly<{
  channel: ApprovalChannelPort;
  store: ApprovalGrantStorePort;
  ids: IdGeneratorPort;
  clock: ClockPort;
  audit: AuditPort;
  nonce?: () => string;
  ttlMs?: number;
}>;

function requireStableIdentifier(label: string, value: string): void {
  if (!value || value !== value.trim()) throw new Error(`${label} must be a stable identifier`);
}

function requireTimestamp(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} must be a non-negative Unix millisecond timestamp`);
  }
}

/** Creates call-bound approval challenges and manages their single-use grants. */
export class ApprovalBroker {
  private readonly nonce: () => string;
  private readonly ttlMs: number;

  constructor(private readonly options: ApprovalBrokerOptions) {
    this.nonce = options.nonce ?? (() => randomBytes(32).toString("base64url"));
    this.ttlMs = options.ttlMs ?? DEFAULT_APPROVAL_TTL_MS;
    if (!Number.isSafeInteger(this.ttlMs) || this.ttlMs <= 0) {
      throw new Error("ttlMs must be a positive integer");
    }
  }

  async requestApproval(
    input: Readonly<{
      runtimeCallId: string;
      argsHash: string;
      initialPolicyHash: string;
      parentAttemptId: string;
      additionalPermission: ResolvedAccessSet;
      subjectId: string;
      abortSignal?: AbortSignal;
    }>,
  ): Promise<ApprovalOutcome> {
    if (input.abortSignal?.aborted) return { kind: "cancelled" };
    for (const [label, value] of [
      ["runtimeCallId", input.runtimeCallId],
      ["argsHash", input.argsHash],
      ["initialPolicyHash", input.initialPolicyHash],
      ["parentAttemptId", input.parentAttemptId],
      ["subjectId", input.subjectId],
    ] as const) {
      requireStableIdentifier(label, value);
    }
    if (!input.additionalPermission.length) {
      throw new Error("additionalPermission must not be empty");
    }
    const requestId = this.options.ids.nextId("approval-request");
    const nonce = this.nonce();
    requireStableIdentifier("requestId", requestId);
    requireStableIdentifier("nonce", nonce);
    const requestedAt = this.options.clock.now();
    requireTimestamp(requestedAt, "requestedAt");
    const expiresAt = requestedAt + this.ttlMs;
    if (!Number.isSafeInteger(expiresAt)) throw new Error("approval expiry is out of range");
    const request = immutableSnapshot({
      requestId,
      runtimeCallId: input.runtimeCallId,
      argsHash: input.argsHash,
      initialPolicyHash: input.initialPolicyHash,
      parentAttemptId: input.parentAttemptId,
      additionalPermission: input.additionalPermission,
      subjectId: input.subjectId,
      nonce,
      requestedAt,
      expiresAt,
    });
    if (
      !(await this.recordAudit({
        runtimeCallId: input.runtimeCallId,
        detail: {
          kind: "approval-requested",
          requestId,
          parentAttemptId: input.parentAttemptId,
          argsHash: input.argsHash,
          initialPolicyHash: input.initialPolicyHash,
          subjectId: input.subjectId,
          expiresAt,
        },
      }))
    ) {
      return { kind: "invalid-response" };
    }
    const recordDecision = (decision: ApprovalAuditDecision) =>
      this.recordAudit({
        runtimeCallId: input.runtimeCallId,
        detail: {
          kind: "approval-decided",
          requestId,
          parentAttemptId: input.parentAttemptId,
          decision,
        },
      });
    let decision;
    try {
      decision = await this.options.channel.requestApproval(request, input.abortSignal);
    } catch {
      const kind = input.abortSignal?.aborted ? "cancelled" : "invalid-response";
      await recordDecision(kind === "cancelled" ? "cancelled" : "invalid");
      return { kind };
    }
    if (decision.requestId !== requestId) {
      await recordDecision("invalid");
      return { kind: "invalid-response" };
    }
    if (decision.kind !== "approved") {
      if (!(await recordDecision(decision.kind))) return { kind: "invalid-response" };
      return { kind: decision.kind };
    }
    if (input.abortSignal?.aborted) {
      await recordDecision("cancelled");
      return { kind: "cancelled" };
    }
    const issuedAt = this.options.clock.now();
    requireTimestamp(issuedAt, "issuedAt");
    if (issuedAt < requestedAt) {
      await recordDecision("invalid");
      return { kind: "invalid-response" };
    }
    if (issuedAt > expiresAt) {
      await recordDecision("expired");
      return { kind: "expired" };
    }
    if (decision.subjectId !== input.subjectId || decision.nonce !== nonce) {
      await recordDecision("invalid");
      return { kind: "invalid-response" };
    }
    if (!(await recordDecision("approved"))) return { kind: "invalid-response" };
    const grantId = this.options.ids.nextId("approval-grant");
    requireStableIdentifier("grantId", grantId);
    const grant = attachApprovalGrantHash({
      grantId,
      runtimeCallId: input.runtimeCallId,
      argsHash: input.argsHash,
      initialPolicyHash: input.initialPolicyHash,
      parentAttemptId: input.parentAttemptId,
      additionalPermission: input.additionalPermission,
      subjectId: input.subjectId,
      issuedAt,
      expiresAt,
    });
    if (!(await this.options.store.save(grant))) return { kind: "invalid-response" };
    if (
      !(await this.recordAudit({
        runtimeCallId: input.runtimeCallId,
        detail: {
          kind: "approval-grant-issued",
          grantId,
          parentAttemptId: input.parentAttemptId,
          approvalGrantHash: grant.approvalGrantHash,
          expiresAt,
        },
      }))
    ) {
      await this.options.store.revoke(grantId);
      return { kind: "invalid-response" };
    }
    return immutableSnapshot({ kind: "approved", grant });
  }

  consume(grantId: string, binding: ApprovalGrantBinding): Promise<ApprovalGrant | null> {
    return this.options.store.consume(grantId, binding, this.options.clock.now());
  }

  revoke(grantId: string): Promise<void> {
    return this.options.store.revoke(grantId);
  }

  private async recordAudit(draft: Parameters<AuditPort["record"]>[0]): Promise<boolean> {
    try {
      await this.options.audit.record(draft);
      return true;
    } catch {
      return false;
    }
  }
}
